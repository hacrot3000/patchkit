"""Offline provisioning profile and signed entitlements checks."""
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch
import subprocess

from ipa_errors import IPAError
from ipa_profiles import _granted, decode_mobileprovision, validate_profile


TEAM = "AA11BB22CC"
BUNDLE = "com.example.patchkit"
NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


def fixture(*, app_id=TEAM + ".*"):
    return {
        "Name": "QA iOS profile",
        "TeamIdentifier": [TEAM],
        "ExpirationDate": NOW + timedelta(days=60),
        "Entitlements": {
            "application-identifier": app_id,
            "com.apple.developer.team-identifier": TEAM,
            "get-task-allow": False,
            "keychain-access-groups": [TEAM + ".*"],
            "com.apple.security.application-groups": ["group.com.example.*"],
            "aps-environment": "development",
        },
        "ProvisionedDevices": ["dummy1", "dummy2"]
    }


def signed():
    return {
        "application-identifier": TEAM + "." + BUNDLE,
        "com.apple.developer.team-identifier": TEAM,
        "get-task-allow": False,
        "keychain-access-groups": [TEAM + "." + BUNDLE],
        "com.apple.security.application-groups": ["group.com.example.patchkit"],
    }


class ProvisioningProfileTests(unittest.TestCase):
    def test_accepts_matching_profile_and_wildcard_grants(self):
        metadata = validate_profile(fixture(), BUNDLE, signed(), now=NOW)
        self.assertEqual(metadata["bundle_id"], BUNDLE)
        self.assertEqual(metadata["team"], TEAM)
        self.assertEqual(metadata["development_device_count"], 2)

    def test_expires_closed(self):
        data = fixture()
        data["ExpirationDate"] = NOW
        with self.assertRaisesRegex(IPAError, "expired"):
            validate_profile(data, BUNDLE, signed(), now=NOW)

    def test_bundle_mismatch(self):
        with self.assertRaisesRegex(IPAError, "bundle identifier"):
            validate_profile(fixture(), "com.example.other", signed(), now=NOW)

    def test_wrong_team_fails(self):
        data = signed()
        data["application-identifier"] = "BADTEAM." + BUNDLE
        with self.assertRaisesRegex(IPAError, "bundle identifier/team"):
            validate_profile(fixture(), BUNDLE, data, now=NOW)

    def test_accepts_legacy_application_identifier_key_alias(self):
        profile = fixture()
        profile["Entitlements"]["com.apple.application-identifier"] = (
            profile["Entitlements"].pop("application-identifier")
        )
        self.assertEqual(
            validate_profile(profile, BUNDLE, signed(), now=NOW)["bundle_id"],
            BUNDLE
        )
        signature = signed()
        signature["com.apple.application-identifier"] = (
            signature.pop("application-identifier")
        )
        self.assertEqual(
            validate_profile(fixture(), BUNDLE, signature, now=NOW)["bundle_id"],
            BUNDLE
        )

    def test_mismatched_provisioning_pattern(self):
        with self.assertRaisesRegex(IPAError, "does not authorize"):
            validate_profile(fixture(app_id=TEAM + ".com.other.*"),
                             BUNDLE, signed(), now=NOW)

    def test_cannot_grant_push_or_groups_not_in_profile(self):
        for name, value in [
            ("aps-environment", "production"),
            ("com.apple.security.application-groups", ["group.com.other"]),
            ("get-task-allow", True)
        ]:
            with self.subTest(name=name):
                data = signed()
                data[name] = value
                with self.assertRaisesRegex(IPAError, "does not grant"):
                    validate_profile(fixture(), BUNDLE, data, now=NOW)

    def test_missing_provisioned_entitlement_fails(self):
        data = signed()
        data["com.apple.developer.associated-domains"] = ["applinks:example.org"]
        with self.assertRaisesRegex(IPAError, "lacks entitlement"):
            validate_profile(fixture(), BUNDLE, data, now=NOW)

    def test_multiple_requested_groups_must_all_be_granted(self):
        data = signed()
        data["keychain-access-groups"] = [TEAM + ".first", "OTHER.second"]
        with self.assertRaisesRegex(IPAError, "does not grant"):
            validate_profile(fixture(), BUNDLE, data, now=NOW)

    def test_wildcard_is_only_terminal(self):
        self.assertTrue(_granted(TEAM + ".*", TEAM + "." + BUNDLE))
        self.assertFalse(_granted("AA*BB", "AAZZBB"))
        self.assertFalse(_granted("group.*.x", "group.any.x"))

    def test_rejects_invalid_or_unsigned_profile(self):
        with patch("ipa_profiles.subprocess.run",
                   side_effect=subprocess.CalledProcessError(1, "security")):
            with self.assertRaisesRegex(IPAError, "Cannot decode"):
                decode_mobileprovision("/tmp/not-a-profile")

    def test_rejects_missing_expiration_team_and_app_id(self):
        for broken in (
            {"ExpirationDate": None},
            {"TeamIdentifier": []},
            {"Entitlements": {}}
        ):
            with self.subTest(broken=broken):
                data = fixture()
                data.update(broken)
                with self.assertRaises(IPAError):
                    validate_profile(data, BUNDLE, signed(), now=NOW)


if __name__ == "__main__":
    unittest.main()
