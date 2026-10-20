"""Cross-build a real iOS/arm64 Mach-O with Apple iPhoneOS SDK on macOS CI.

Validates that LIEF injection leaves the iOS platform/deployment load commands
intact and produces an ad-hoc signable file. It does NOT exercise iOS dyld or
prove that the IPA can install/launch on an actual iPhone.
"""
import importlib.util
import json
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from ipa_patch import apply, arm64_slice
from ipa_macho_inject import _load_commands, validate_macho_integrity

NATIVE = all(importlib.util.find_spec(x) for x in ("lief", "keystone", "capstone"))


@unittest.skipUnless(NATIVE and sys.platform == "darwin",
                     "Requires macOS + native Mach-O dependencies")
class IOSBuildValidation(unittest.TestCase):
    def test_ios_sdk_macho_injection_and_signing(self):
        import lief
        sdk = subprocess.run(
            ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
            text=True, capture_output=True
        )
        if sdk.returncode != 0:
            self.skipTest("iPhoneOS SDK not installed on this runner")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "probe.s"
            thin = root / "Probe"
            source.write_text(
                ".globl _probe\n.p2align 2\n_probe:\n nop\n mov x0, #0\n ret\n"
            )
            build = subprocess.run(
                ["xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64",
                 "-miphoneos-version-min=15.0", "-dynamiclib",
                 "-Wl,-install_name,@rpath/Probe.dylib",
                 "-o", str(thin), str(source)],
                text=True, capture_output=True
            )
            if build.returncode:
                self.fail("Cannot build iOS/arm64 fixture: " + build.stderr)
            original = thin.read_bytes()
            original_binary = lief.MachO.parse(str(thin)).at(0)
            address = int(original_binary.get_section("__text").virtual_address)
            before_versions = [
                bytes(body) for code, body in _load_commands(original)
                if code in (0x32, 0x25)
            ]
            self.assertTrue(before_versions, "Input must be iOS-targeted")
            bundle = root / "Payload" / "Probe.app"
            bundle.mkdir(parents=True)
            bundle.joinpath("Info.plist").write_bytes(plistlib.dumps({
                "CFBundleExecutable": "Probe",
                "CFBundleIdentifier": "patchkit.ios.sdk.test",
                "CFBundlePackageType": "APPL"
            }))
            shutil.copyfile(thin, bundle / "Probe")
            ipa = root / "input.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.write(bundle / "Info.plist", "Payload/Probe.app/Info.plist")
                archive.write(bundle / "Probe", "Payload/Probe.app/Probe")
            manifest = root / "patch.json"
            manifest.write_text(json.dumps({"operations": [
                {"type": "inject_arm64", "name": "patched_code",
                 "asm": "mov x0, #7; ret"},
                {"type": "hook_arm64", "mode": "replace",
                 "address": hex(address),
                 "expected_hex": "1f2003d5", "symbol": "patched_code"}
            ]}))
            output = root / "patched.ipa"
            apply(ipa, manifest, output, allow_unsigned=True)
            with zipfile.ZipFile(output) as archive:
                modified = archive.read("Payload/Probe.app/Probe")
            self.assertIsNotNone(lief.MachO.parse(modified).at(0).get_segment("__PKTEXT"))
            validate_macho_integrity(original, modified)
            after_versions = [
                bytes(body) for code, body in _load_commands(modified)
                if code in (0x32, 0x25)
            ]
            self.assertEqual(before_versions, after_versions)
            destination = root / "signed-ios-macho"
            destination.write_bytes(modified)
            destination.chmod(0o755)
            subprocess.run(
                ["codesign", "--force", "--sign", "-", "--timestamp=none",
                 str(destination)], capture_output=True, text=True, check=True
            )
            subprocess.run(
                ["codesign", "--verify", "--strict", str(destination)],
                capture_output=True, text=True, check=True
            )
            self.assertGreater(arm64_slice(modified).size, arm64_slice(original).size)


if __name__ == "__main__":
    unittest.main()
