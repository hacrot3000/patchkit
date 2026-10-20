#!/usr/bin/env python3
"""Install and smoke-launch an authorized signed IPA on a paired iPhone.

Nothing is installed unless --execute is explicitly supplied. Plan mode works
on Linux; execute mode requires macOS, Xcode devicectl and a trusted device.
"""
import argparse
import json
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipa_patch import IPAError, app_bundle, extract_ipa


def plan_commands(device, app_path, bundle_id):
    if not device or device.startswith("-") or not bundle_id:
        raise IPAError("Device identifier and bundle identifier are required")
    return [
        ["codesign", "--verify", "--deep", "--strict", str(app_path)],
        ["xcrun", "devicectl", "device", "install", "app", "--device",
         device, str(app_path)],
        ["xcrun", "devicectl", "device", "process", "launch", "--device",
         device, bundle_id],
    ]


def inspect_app(root):
    app, _ = app_bundle(root)
    metadata = plistlib.loads((app / "Info.plist").read_bytes())
    bundle_id = metadata.get("CFBundleIdentifier")
    if not isinstance(bundle_id, str) or not bundle_id or any(
            ch.isspace() for ch in bundle_id):
        raise IPAError("IPA has no usable CFBundleIdentifier")
    return app, bundle_id


def smoke(ipa, device, *, execute=False, max_unpacked_mib=2048):
    if execute and sys.platform != "darwin":
        raise IPAError("Physical iPhone smoke tests require macOS")
    if execute and not shutil.which("xcrun"):
        raise IPAError("xcrun is unavailable; install Xcode and pair the iPhone")
    result = {"device": device, "ipa": str(Path(ipa).resolve()),
              "mode": "execute" if execute else "plan", "steps": []}
    with tempfile.TemporaryDirectory(prefix="patchkit-ios-device-") as work:
        root = Path(work)
        extract_ipa(ipa, root, max_unpacked_mib * 1024 * 1024)
        app, bundle_id = inspect_app(root)
        result["bundle_id"] = bundle_id
        commands = plan_commands(device, app, bundle_id)
        if not execute:
            result["commands"] = [
                ["${EXTRACTED_APP}" if value == str(app) else value
                 for value in command] for command in commands
            ]
            result["result"] = "PLAN_ONLY"
            result["note"] = ("EXTRACTED_APP is a placeholder; plan mode cleans up "
                              "the temporary extracted application.")
            return result
        result["commands"] = commands
        for command in commands:
            step = {"action": "verify_signature" if command[0] == "codesign"
                    else ("install" if command[3] == "install" else "launch")}
            try:
                output = subprocess.run(command, capture_output=True, text=True,
                                        timeout=120, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                step["status"] = "error"
                step["error"] = str(exc)
                result["steps"].append(step)
                result["result"] = "FAILED"
                return result
            step["exit_code"] = output.returncode
            step["stdout"] = output.stdout[-8000:]
            step["stderr"] = output.stderr[-8000:]
            step["status"] = "pass" if output.returncode == 0 else "fail"
            result["steps"].append(step)
            if output.returncode != 0:
                result["result"] = "FAILED"
                return result
        result["result"] = "INSTALL_AND_LAUNCH_ACCEPTED"
        result["note"] = ("Successful devicectl launch is not proof of runtime "
                          "stability; inspect device crash logs and app functionality.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Plan or smoke-test a signed IPA on iPhone")
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--device", required=True, help="Paired device UDID")
    parser.add_argument("--execute", action="store_true",
                        help="Perform codesign verification, installation and launch")
    parser.add_argument("--report", type=Path, help="Write JSON result (contains device ID)")
    args = parser.parse_args(argv)
    try:
        report = smoke(args.ipa, args.device, execute=args.execute)
    except (IPAError, OSError, ValueError) as exc:
        parser.exit(1, "ERROR: %s\n" % exc)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["result"] == "FAILED":
        parser.exit(1, "Smoke test failed; see steps and device logs.\n")


if __name__ == "__main__":
    main()
