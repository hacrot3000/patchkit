"""Device smoke tool is always opt-in; test without a physical iPhone."""
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ipa_patch import IPAError
from tools.ipa_device_smoke import smoke, plan_commands


class DeviceSmokeTests(unittest.TestCase):
    def setUp(self):
        self.root_obj = tempfile.TemporaryDirectory()
        self.addCleanup(self.root_obj.cleanup)
        self.root = Path(self.root_obj.name)
        self.ipa = self.root / "input.ipa"
        with zipfile.ZipFile(self.ipa, "w") as archive:
            archive.writestr("Payload/Test.app/Info.plist", plistlib.dumps({
                "CFBundleExecutable": "Test",
                "CFBundleIdentifier": "org.example.patchkit.test"
            }))
            archive.writestr("Payload/Test.app/Test", b"fixture")

    def test_plan_does_not_execute_or_install(self):
        with patch("tools.ipa_device_smoke.subprocess.run") as runner:
            result = smoke(self.ipa, "DEVICE-123")
        runner.assert_not_called()
        self.assertEqual(result["result"], "PLAN_ONLY")
        self.assertEqual(result["bundle_id"], "org.example.patchkit.test")
        self.assertEqual(len(result["commands"]), 3)
        self.assertIn("$"+"{EXTRACTED_APP}", result["commands"][1])

    def test_rejects_unsafe_device_argument(self):
        with self.assertRaisesRegex(IPAError, "Device identifier"):
            plan_commands("--other", self.root / "App.app", "org.example.App")

    def test_execute_requires_mac(self):
        with patch("tools.ipa_device_smoke.sys.platform", "linux"):
            with self.assertRaisesRegex(IPAError, "requires macOS"):
                smoke(self.ipa, "DEVICE-123", execute=True)

    def test_execute_checks_signature_before_install(self):
        replies = [SimpleNamespace(returncode=1, stdout="", stderr="unsigned")]
        with patch("tools.ipa_device_smoke.sys.platform", "darwin"), \
             patch("tools.ipa_device_smoke.shutil.which", return_value="/usr/bin/xcrun"), \
             patch("tools.ipa_device_smoke.subprocess.run",
                   side_effect=replies) as runner:
            result = smoke(self.ipa, "DEVICE-123", execute=True)
        self.assertEqual(result["result"], "FAILED")
        self.assertEqual(result["steps"][0]["action"], "verify_signature")
        self.assertEqual(runner.call_count, 1)

    def test_install_failure_prevents_launch(self):
        replies = [
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=2, stdout="", stderr="install refused")
        ]
        with patch("tools.ipa_device_smoke.sys.platform", "darwin"), \
             patch("tools.ipa_device_smoke.shutil.which", return_value="/usr/bin/xcrun"), \
             patch("tools.ipa_device_smoke.subprocess.run",
                   side_effect=replies) as runner:
            result = smoke(self.ipa, "DEVICE-123", execute=True)
        self.assertEqual(result["result"], "FAILED")
        self.assertEqual([x["action"] for x in result["steps"]],
                         ["verify_signature", "install"])
        self.assertEqual(runner.call_count, 2)

    def test_success_is_not_marked_runtime_validated(self):
        replies = [SimpleNamespace(returncode=0, stdout="ok", stderr="")
                   for _ in range(3)]
        with patch("tools.ipa_device_smoke.sys.platform", "darwin"), \
             patch("tools.ipa_device_smoke.shutil.which", return_value="/usr/bin/xcrun"), \
             patch("tools.ipa_device_smoke.subprocess.run",
                   side_effect=replies):
            result = smoke(self.ipa, "DEVICE-123", execute=True)
        self.assertEqual(result["result"], "INSTALL_AND_LAUNCH_ACCEPTED")
        self.assertIn("not proof of runtime stability", result["note"])
        self.assertEqual([x["action"] for x in result["steps"]],
                         ["verify_signature", "install", "launch"])


if __name__ == "__main__":
    unittest.main()
