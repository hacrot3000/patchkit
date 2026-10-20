"""Provisioning-profile checks for IPA signing.

These checks catch mismatched app IDs, expired profiles and entitlements that
a profile does not grant. They are NOT a substitute for Apple's signature
verification, an Apple Development/Distribution identity, or device install.
"""
from datetime import datetime, timezone
from pathlib import Path
import plistlib
import subprocess

from ipa_errors import IPAError


# These capabilities must be provisioned. Some non-provisioned entitlements
# are legal; only keys in this set are rejected when absent from a profile.
PROVISIONED_KEYS = frozenset({
    "application-identifier",
    "com.apple.application-identifier",
    "com.apple.developer.team-identifier",
    "keychain-access-groups",
    "com.apple.security.application-groups",
    "com.apple.developer.associated-domains",
    "aps-environment",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.icloud-services",
    "com.apple.developer.ubiquity-container-identifiers",
    "com.apple.developer.networking.networkextension",
    "com.apple.developer.healthkit",
    "com.apple.developer.in-app-payments",
    "com.apple.developer.pass-type-identifiers",
})


def _granted(grant, requested):
    """Conservatively compare signed entitlement against a profile grant.

    A terminal '*' in a provisioning identifier grants matching prefixes,
    e.g. TEAM.*. No shell globbing or wildcard in the middle is accepted.
    """
    if isinstance(grant, bool) or isinstance(requested, bool):
        return isinstance(grant, bool) and isinstance(requested, bool) and grant == requested
    if isinstance(grant, str) and isinstance(requested, str):
        if grant.endswith("*") and grant.count("*") == 1:
            return requested.startswith(grant[:-1])
        return requested == grant
    if isinstance(grant, list) and isinstance(requested, list):
        return all(any(_granted(item, candidate) for item in grant)
                   for candidate in requested)
    if isinstance(grant, dict) and isinstance(requested, dict):
        return all(key in grant and _granted(grant[key], val)
                   for key, val in requested.items())
    return type(grant) is type(requested) and grant == requested


def validate_profile(profile, bundle_id, entitlements, *, now=None):
    """Raise IPAError on a known mismatch; return non-sensitive metadata."""
    if not isinstance(profile, dict) or not isinstance(entitlements, dict):
        raise IPAError("Provisioning profile and signed entitlements must be dictionaries")
    if not isinstance(bundle_id, str) or not bundle_id or "/" in bundle_id:
        raise IPAError("Invalid bundle identifier for provisioning check")
    expires = profile.get("ExpirationDate")
    if not isinstance(expires, datetime):
        raise IPAError("Provisioning profile has no valid ExpirationDate")
    expires_utc = (expires.replace(tzinfo=timezone.utc) if expires.tzinfo is None
                   else expires.astimezone(timezone.utc))
    clock = now if now is not None else datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    if expires_utc <= clock.astimezone(timezone.utc):
        raise IPAError("Provisioning profile is expired")
    grants = profile.get("Entitlements")
    if not isinstance(grants, dict):
        raise IPAError("Provisioning profile is missing Entitlements")
    teams = profile.get("TeamIdentifier")
    if not isinstance(teams, list) or not teams or not all(
            isinstance(value, str) and value for value in teams):
        raise IPAError("Provisioning profile has no valid TeamIdentifier")
    signed_app_id = entitlements.get(
        "application-identifier", entitlements.get("com.apple.application-identifier")
    )
    profile_app_id = grants.get(
        "application-identifier", grants.get("com.apple.application-identifier")
    )
    if not isinstance(signed_app_id, str) or not isinstance(profile_app_id, str):
        raise IPAError("Provisioning verification requires application-identifier entitlement")
    valid_ids = [team + "." + bundle_id for team in teams]
    if signed_app_id not in valid_ids:
        raise IPAError("Signed application-identifier does not match bundle identifier/team")
    if not _granted(profile_app_id, signed_app_id):
        raise IPAError("Provisioning profile does not authorize signed application-identifier")
    signed_team = entitlements.get("com.apple.developer.team-identifier")
    if signed_team is not None and signed_team not in teams:
        raise IPAError("Signed team-identifier is not in provisioning profile")
    for key, requested in entitlements.items():
        if key in grants:
            if not _granted(grants[key], requested):
                raise IPAError("Provisioning profile does not grant entitlement: %s" % key)
        elif key in PROVISIONED_KEYS:
            # Apple still supports restricted entitlements outside this list.
            # Reject only known provisioning-bound capabilities.
            if key == "com.apple.application-identifier" and "application-identifier" in grants:
                continue
            raise IPAError("Provisioning profile lacks entitlement: %s" % key)
    devices = profile.get("ProvisionedDevices")
    return {
        "bundle_id": bundle_id,
        "profile_name": profile.get("Name", ""),
        "team": signed_app_id.split(".", 1)[0],
        "expires": expires_utc.isoformat(),
        "development_device_count": len(devices) if isinstance(devices, list) else None,
    }


def decode_mobileprovision(path):
    """Decode CMS payload using Apple's macOS security tool.

    Decoding is not an independent verification of Apple's CMS signing chain.
    """
    path = Path(path)
    cmd = ["security", "cms", "-D", "-i", str(path)]
    try:
        result = subprocess.run(cmd, capture_output=True, check=True)
        data = plistlib.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, ValueError, TypeError) as exc:
        raise IPAError("Cannot decode provisioning profile: %s" % path) from exc
    if not isinstance(data, dict):
        raise IPAError("Provisioning CMS payload must contain a plist dictionary")
    return data


def check_bundle_profiles(app, *, require_all=False):
    """Validate all available .app/.appex profiles AFTER signing.

    Requiring profiles is opt-in except when an explicit replacement profile
    was provided. Frameworks and dylibs do not have provisioning profiles.
    """
    from ipa_patch import signable_paths

    inspected = []
    for bundle in signable_paths(app):
        if bundle.suffix not in (".app", ".appex"):
            continue
        relative = bundle.relative_to(app).as_posix()
        profile_path = bundle / "embedded.mobileprovision"
        if not profile_path.is_file():
            if require_all:
                raise IPAError("Missing embedded.mobileprovision in %s" % relative)
            continue
        try:
            metadata = plistlib.loads((bundle / "Info.plist").read_bytes())
            bundle_id = metadata["CFBundleIdentifier"]
        except (OSError, KeyError, ValueError, TypeError) as exc:
            raise IPAError("Cannot inspect bundle identifier in %s" % relative) from exc
        if not isinstance(bundle_id, str):
            raise IPAError("Invalid CFBundleIdentifier in %s" % relative)
        try:
            signed = subprocess.run(
                ["codesign", "-d", "--entitlements", ":-", str(bundle)],
                capture_output=True, check=True
            )
            entitlements = plistlib.loads(signed.stdout)
        except (OSError, subprocess.CalledProcessError, ValueError, TypeError) as exc:
            raise IPAError("Cannot read signed bundle entitlements: %s" % relative) from exc
        profile = decode_mobileprovision(profile_path)
        inspected.append(validate_profile(profile, bundle_id, entitlements))
    return inspected
