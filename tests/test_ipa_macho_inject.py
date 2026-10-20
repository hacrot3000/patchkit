"""Integration tests for structural ARM64 Mach-O injection.

On macOS, build a minimal ARM64 executable with Apple clang. Linux skips this
integration fixture but still exercises branch encoding and rejection rules.
"""
import importlib.util
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from ipa_patch import IPAError, address_to_offset, arm64_slice, apply
from ipa_macho_inject import _branch, _copyable_stolen

HAVE_NATIVE = all(importlib.util.find_spec(name) for name in ("lief", "keystone", "capstone"))


class BranchValidation(unittest.TestCase):
    def test_branch_forward_and_back(self):
        for start, finish in ((0x1000, 0x2000), (0x2000, 0x1000)):
            raw = _branch(start, finish)
            value, = struct.unpack("<I", raw)
            relative = value & 0x3FFFFFF
            if relative & (1 << 25):
                relative -= 1 << 26
            self.assertEqual(start + relative * 4, finish)

    def test_branch_too_far(self):
        with self.assertRaisesRegex(IPAError, "reach"):
            _branch(0x1000, 0x1000 + (1 << 27))

    @unittest.skipUnless(HAVE_NATIVE, "Capstone/Keystone not installed")
    def test_refuses_pc_relative_relocation(self):
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, arm64_const
        from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        cs.detail = True
        raw, _ = ks.asm("adr x0, #0x1004", addr=0x1000)
        with self.assertRaisesRegex(IPAError, "Cannot safely relocate"):
            _copyable_stolen(cs, arm64_const, bytes(raw), 0x1000)


@unittest.skipUnless(HAVE_NATIVE, "LIEF, Keystone and Capstone not installed")
class MachOIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lief
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.binary = cls.root / "test_arm64"
        cls.source = cls.root / "test_arm64.s"
        cls.source.write_text(".globl _main\n.p2align 2\n_main:\n nop\n mov x0, #0\n ret\n")
        compiler = shutil.which("clang")
        if sys.platform != "darwin" or not compiler:
            raise unittest.SkipTest("Real Mach-O fixture is compiled on macOS CI")
        proc = subprocess.run([
            compiler, "-arch", "arm64", "-Wl,-e,_main",
            "-o", str(cls.binary), str(cls.source)
        ], capture_output=True, text=True)
        if proc.returncode:
            raise RuntimeError("ARM64 Mach-O fixture build failed: " + proc.stderr)
        built = lief.MachO.parse(str(cls.binary))
        if built is None or built.size != 1:
            raise RuntimeError("Fixture is not a parseable ARM64 Mach-O")
        section = built.at(0).get_section("__text")
        if section is None:
            raise RuntimeError("Fixture missing __text")
        cls.address = int(section.virtual_address)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "tmp"):
            cls.tmp.cleanup()

    def setUp(self):
        self.ipa = self.root / (self._testMethodName + ".ipa")
        self.out = self.root / (self._testMethodName + "-patched.ipa")
        self.manifest = self.root / (self._testMethodName + ".json")
        with zipfile.ZipFile(self.ipa, "w") as z:
            z.writestr("Payload/Test.app/Info.plist", plistlib.dumps({
                "CFBundleExecutable": "test_arm64",
                "CFBundleIdentifier": "patchkit.arm64.test",
            }))
            z.write(self.binary, "Payload/Test.app/test_arm64")

    def patch(self, ops):
        import json
        self.manifest.write_text(json.dumps({"operations": ops}))
        apply(self.ipa, self.manifest, self.out, allow_unsigned=True)
        with zipfile.ZipFile(self.out) as zipfile_in:
            return zipfile_in.read("Payload/Test.app/test_arm64")

    def test_growth_and_injection(self):
        import lief
        raw = self.patch([
            {"type": "extend_macho", "size": 0x4000},
            {"type": "inject_arm64", "name": "probe", "asm": "mov x0, #7; ret"},
        ])
        with tempfile.NamedTemporaryFile() as output:
            Path(output.name).write_bytes(raw)
            binary = lief.MachO.parse(output.name).at(0)
            segment = binary.get_segment("__PKTEXT")
            self.assertIsNotNone(segment)
            self.assertEqual(segment.init_protection, 5)
            self.assertGreaterEqual(segment.file_size, 0x4000)
            self.assertIn(bytes.fromhex("e00080d2"), raw)

    def test_expanded_executable_can_be_ad_hoc_signed(self):
        import lief
        raw = self.patch([
            {"type": "inject_arm64", "name": "probe", "asm": "mov x0, #7; ret"},
        ])
        executable = self.root / "signed-test-arm64"
        executable.write_bytes(raw)
        executable.chmod(0o755)
        subprocess.run(["codesign", "--force", "--sign", "-",
                        "--timestamp=none", str(executable)],
                       check=True, capture_output=True, text=True)
        subprocess.run(["codesign", "--verify", "--strict",
                        str(executable)],
                       check=True, capture_output=True, text=True)
        self.assertIsNotNone(
            lief.MachO.parse(str(executable)).at(0).get_segment("__PKTEXT")
        )

    def test_hook_before_and_return(self):
        import lief
        raw = self.patch([
            {"type": "hook_arm64", "address": hex(self.address),
             "expected_hex": "1f2003d5", "asm": "nop"},
        ])
        # LIEF may relocate the original __text section during Mach-O growth.
        current = int(lief.MachO.parse(raw).at(0).get_section("__text").virtual_address)
        selected = arm64_slice(raw)
        at = address_to_offset(raw, selected, current)
        encoded, = struct.unpack_from("<I", raw, at)
        self.assertEqual(encoded & 0xFC000000, 0x14000000)
        disp = encoded & 0x03FFFFFF
        if disp & (1 << 25):
            disp -= 1 << 26
        target = current + 4 * disp
        first = address_to_offset(raw, selected, target)
        self.assertEqual(raw[first:first + 8], bytes.fromhex("1f2003d51f2003d5"))
        jump_back, = struct.unpack_from("<I", raw, first + 8)
        self.assertEqual(jump_back & 0xFC000000, 0x14000000)

    def test_replace_hook_to_named_function(self):
        import lief
        raw = self.patch([
            {"type": "inject_arm64", "name": "new_func", "asm": "mov x0, #7; ret"},
            {"type": "hook_arm64", "mode": "replace", "address": hex(self.address),
             "expected_hex": "1f2003d5", "symbol": "new_func"},
        ])
        current = int(lief.MachO.parse(raw).at(0).get_section("__text").virtual_address)
        selected = arm64_slice(raw)
        pos = address_to_offset(raw, selected, current)
        word, = struct.unpack_from("<I", raw, pos)
        self.assertEqual(word & 0xFC000000, 0x14000000)

    def test_mismatched_original_fails_closed(self):
        import json
        self.manifest.write_text(json.dumps({"operations": [{
            "type": "hook_arm64", "address": hex(self.address),
            "expected_hex": "ffffffff", "asm": "nop"
        }]}))
        with self.assertRaisesRegex(IPAError, "expected_hex mismatch"):
            apply(self.ipa, self.manifest, self.out, allow_unsigned=True)
        self.assertFalse(self.out.exists())

    def test_injection_rejects_arm64e(self):
        import json
        self.manifest.write_text(json.dumps({"operations": [{
            "type": "inject_arm64", "arch": "arm64e",
            "name": "probe", "asm": "ret"
        }]}))
        with self.assertRaisesRegex(IPAError, "refuse arm64e"):
            apply(self.ipa, self.manifest, self.out, allow_unsigned=True)


if __name__ == "__main__":
    unittest.main()
