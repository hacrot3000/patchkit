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

    def test_far_detour_is_aslr_relative(self):
        from ipa_macho_inject import _detour
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, arm64_const
        src, dst = 0x100000000, 0x130001234
        with self.assertRaisesRegex(IPAError, "long_branch"):
            _detour(src, dst)
        raw = _detour(src, dst, permit_x16=True)
        self.assertEqual(len(raw), 12)
        self.assertEqual(raw[8:12], bytes.fromhex("00021fd6"))  # BR x16
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.detail = True
        insns = list(decoder.disasm(raw, src))
        self.assertEqual([i.mnemonic for i in insns], ["adrp", "add", "br"])
        self.assertEqual(insns[0].operands[1].imm + insns[1].operands[2].imm, dst)

    def test_far_detour_rejects_outside_adrp_range(self):
        from ipa_macho_inject import _detour
        with self.assertRaisesRegex(IPAError, "21-bit"):
            _detour(0x1000, 0x1000 + (1 << 34), permit_x16=True)

    def test_ldr_literal_out_of_range_is_rejected(self):
        from ipa_macho_inject import _encode_literal_load
        class Dummy:
            def get_section(self, segment, section):
                class Destination:
                    virtual_address = 0x80000000
                return Destination()
        with self.assertRaisesRegex(IPAError, "reach"):
            _encode_literal_load(
                struct.pack("<I", 0x58000000),
                0x1010, 0x1000,
                [("__TEXT", "__text", 0x1000, 0x100)], Dummy()
            )

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
        cls.source.write_text(".globl _main\n.p2align 2\n_main:\n nop\n mov x0, #0\n ret\n.p2align 3\n_probe_literal:\n .quad 7\n.section __TEXT,__cstring,cstring_literals\n.p2align 2\n_data_string:\n.asciz \"ABCDEFGH\"\n")
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
        cls.literal_address = int(section.virtual_address) + int(section.size) - 8

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

    def test_far_replace_hook_requires_opt_in_and_12_bytes(self):
        import json
        from unittest.mock import patch as mock_patch
        from ipa_macho_inject import expand_macho
        original = self.binary.read_bytes()
        # Original function starts NOP; MOV X0, #0; RET (12 bytes).
        with mock_patch("ipa_macho_inject.BRANCH_RANGE", 4):
            self.manifest.write_text(json.dumps({"operations": [
                {"type": "inject_arm64", "name": "replacement",
                 "asm": "mov x0, #7; ret"},
                {"type": "hook_arm64", "mode": "replace",
                 "address": hex(self.address), "expected_hex": "1f2003d5",
                 "symbol": "replacement", "long_branch": "x16"},
            ]}))
            with self.assertRaisesRegex(IPAError, "requires 12 original bytes"):
                apply(self.ipa, self.manifest, self.out, allow_unsigned=True)
            self.assertFalse(self.out.exists())
            self.manifest.write_text(json.dumps({"operations": [
                {"type": "inject_arm64", "name": "replacement",
                 "asm": "mov x0, #7; ret"},
                {"type": "hook_arm64", "mode": "replace",
                 "address": hex(self.address),
                 "expected_hex": "1f2003d5" + "000080d2" + "c0035fd6",
                 "symbol": "replacement", "long_branch": "x16"},
            ]}))
            apply(self.ipa, self.manifest, self.out, allow_unsigned=True)
        import lief
        with zipfile.ZipFile(self.out) as z:
            raw = z.read("Payload/Test.app/test_arm64")
        image = lief.MachO.parse(raw).at(0)
        current = int(image.get_section("__text").virtual_address)
        pos = address_to_offset(raw, arm64_slice(raw), current)
        self.assertEqual(raw[pos+8:pos+12], bytes.fromhex("00021fd6"))
        executable = self.root / (self._testMethodName + "-program")
        executable.write_bytes(raw)
        executable.chmod(0o755)
        subprocess.run(["codesign", "--force", "--sign", "-",
                        "--timestamp=none", str(executable)],
                       capture_output=True, check=True)
        proc = subprocess.run([str(executable)], capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 7, proc.stderr)

    def test_mismatched_original_fails_closed(self):
        import json
        self.manifest.write_text(json.dumps({"operations": [{
            "type": "hook_arm64", "address": hex(self.address),
            "expected_hex": "ffffffff", "asm": "nop"
        }]}))
        with self.assertRaisesRegex(IPAError, "expected_hex mismatch"):
            apply(self.ipa, self.manifest, self.out, allow_unsigned=True)
        self.assertFalse(self.out.exists())

    def test_hook_rejects_non_instruction_lengths(self):
        import json
        for width in (1, 2, 3, 5, 6, 7):
            with self.subTest(width=width):
                self.manifest.write_text(json.dumps({"operations": [{
                    "type": "hook_arm64", "mode": "replace",
                    "address": hex(self.address), "symbol": "new_func",
                    "expected_hex": "1f" * width
                }, {
                    "type": "inject_arm64", "name": "new_func", "asm": "ret"
                }]}))
                with self.assertRaisesRegex(IPAError, "whole 4-byte"):
                    apply(self.ipa, self.manifest, self.out, allow_unsigned=True)
                self.assertFalse(self.out.exists())

    def test_preserve_nested_bundle_entitlements(self):
        from ipa_patch import snapshot_entitlements
        import json
        bundle = self.root / "Nested.app"
        nested = bundle / "PlugIns" / "Widget.appex"
        nested.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.binary, bundle / "test_arm64")
        shutil.copy2(self.binary, nested / "widget")
        (bundle / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleExecutable": "test_arm64",
            "CFBundleIdentifier": "patchkit.test.nested",
            "CFBundlePackageType": "APPL"
        }))
        (nested / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleExecutable": "widget",
            "CFBundleIdentifier": "patchkit.test.nested.widget",
            "CFBundlePackageType": "XPC!"
        }))
        ent_root = self.root / "root-ent.plist"
        ent_nested = self.root / "widget-ent.plist"
        ent_root.write_bytes(plistlib.dumps({"get-task-allow": True}))
        ent_nested.write_bytes(plistlib.dumps({"get-task-allow": False}))
        for target, entitlement in [(nested, ent_nested), (bundle, ent_root)]:
            subprocess.run(["codesign", "--force", "--sign", "-",
                            "--entitlements", str(entitlement), str(target)],
                           check=True, capture_output=True)
        import zipfile
        with zipfile.ZipFile(self.ipa, "w") as archive:
            for p in sorted(bundle.rglob("*")):
                if p.is_file():
                    archive.write(p, "Payload/Nested.app/" + p.relative_to(bundle).as_posix())
        self.manifest.write_text(json.dumps({"operations": [{
            "type": "patch_address", "target": "executable",
            "address": hex(self.address),
            "expected_hex": "1f2003d5", "new_hex": "c0035fd6"
        }]}))
        apply(self.ipa, self.manifest, self.out, sign_identity="-")
        extracted = self.root / "rechecked"
        extracted.mkdir()
        with zipfile.ZipFile(self.out) as archive:
            archive.extractall(extracted)
        finished = extracted / "Payload" / "Nested.app"
        subprocess.run(["codesign", "--verify", "--deep", "--strict", str(finished)],
                       check=True, capture_output=True)
        def read_entitlements(path):
            output = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(path)],
                                    capture_output=True, check=True)
            return plistlib.loads(output.stdout)
        self.assertEqual(read_entitlements(finished), {"get-task-allow": True})
        self.assertEqual(read_entitlements(finished / "PlugIns" / "Widget.appex"),
                         {"get-task-allow": False})

    def test_conditional_branches_relocate_and_execute(self):
        # The branch jumps from the stolen instruction to original _main+8
        # (RET), skipping _main+4 (MOV X0, #9) if relocation is correct.
        variants = (
            ("b.eq", 0x54000040, "mov x0, #7; cmp x0, #7", 7),
            ("cbz", 0xB4000040, "mov x0, #0", 0),
            ("cbnz", 0xB5000040, "mov x0, #7", 7),
            ("tbz", 0x36000040, "mov x0, #0", 0),
            ("tbnz", 0x37000040, "mov x0, #7", 7),
            ("b", 0x14000002, "mov x0, #7", 7),
        )
        for index, (label, opcode, injected_asm, exit_code) in enumerate(variants):
            with self.subTest(instruction=label):
                # Create a fresh IPA: a malformed result must not be hidden by
                # previous patches from this loop.
                ipa = self.root / ("branch-fixture-%d.ipa" % index)
                output = self.root / ("branch-output-%d.ipa" % index)
                manifest = self.root / ("branch-manifest-%d.json" % index)
                with zipfile.ZipFile(ipa, "w") as archive:
                    archive.writestr("Payload/Test.app/Info.plist", plistlib.dumps({
                        "CFBundleExecutable": "test_arm64",
                        "CFBundleIdentifier": "patchkit.arm64.test"
                    }))
                    archive.write(self.binary, "Payload/Test.app/test_arm64")
                import json
                manifest.write_text(json.dumps({"operations": [
                    {"type": "patch_address", "address": hex(self.address),
                     "expected_hex": "1f2003d5",
                     "new_hex": struct.pack("<I", opcode).hex()},
                    {"type": "patch_address", "address": hex(self.address + 4),
                     "expected_hex": "000080d2", "new_hex": "200180d2"},
                    {"type": "hook_arm64", "mode": "before",
                     "address": hex(self.address),
                     "expected_hex": struct.pack("<I", opcode).hex(),
                     "asm": injected_asm}
                ]}))
                apply(ipa, manifest, output, allow_unsigned=True)
                with zipfile.ZipFile(output) as archive:
                    raw = archive.read("Payload/Test.app/test_arm64")
                executable = self.root / ("branch-exec-%d" % index)
                executable.write_bytes(raw)
                executable.chmod(0o755)
                subprocess.run(["codesign", "--force", "--sign", "-",
                                "--timestamp=none", str(executable)],
                               check=True, capture_output=True)
                proc = subprocess.run([str(executable)],
                                      capture_output=True, timeout=10)
                self.assertEqual(proc.returncode, exit_code,
                                 "%s: %r" % (label, proc.stderr))

    def test_refuses_hook_inside_rx_cstring_data(self):
        import json
        import lief
        image = lief.MachO.parse(str(self.binary)).at(0)
        section = image.get_section("__cstring")
        self.assertIsNotNone(section)
        self.assertEqual(int(section.virtual_address) % 4, 0)
        self.manifest.write_text(json.dumps({"operations": [
            {"type": "inject_arm64", "name": "replacement",
             "asm": "ret"},
            {"type": "hook_arm64", "mode": "replace",
             "address": hex(int(section.virtual_address)),
             "expected_hex": "4142434445464748",
             "symbol": "replacement"}
        ]}))
        with self.assertRaisesRegex(IPAError, "instruction section"):
            apply(self.ipa, self.manifest, self.out, allow_unsigned=True)
        self.assertFalse(self.out.exists())

    def test_reject_branch_into_stolen_region(self):
        # B to itself remains inside the original overwritten region.
        import json
        self.manifest.write_text(json.dumps({"operations": [
            {"type": "patch_address", "address": hex(self.address),
             "expected_hex": "1f2003d5", "new_hex": "00000014"},
            {"type": "hook_arm64", "mode": "before",
             "address": hex(self.address), "expected_hex": "00000014",
             "asm": "nop"}
        ]}))
        with self.assertRaisesRegex(IPAError, "overwritten instruction range"):
            apply(self.ipa, self.manifest, self.out, allow_unsigned=True)
        self.assertFalse(self.out.exists())

    def test_before_hook_relocates_ldr_literal_and_executes(self):
        import lief
        displacement = self.literal_address - self.address
        self.assertEqual(displacement % 4, 0)
        # LDR X0 literal with 19-bit signed PC-relative displacement.
        original = struct.pack("<I",
                               0x58000000 | (((displacement // 4) & 0x7ffff) << 5))
        raw = self.patch([
            {"type": "patch_address", "address": hex(self.address),
             "expected_hex": "1f2003d5", "new_hex": original.hex()},
            {"type": "patch_address", "address": hex(self.address + 4),
             "expected_hex": "000080d2", "new_hex": "1f2003d5"},
            {"type": "hook_arm64", "mode": "before",
             "address": hex(self.address), "expected_hex": original.hex(),
             "asm": "nop"}
        ])
        executable = self.root / (self._testMethodName + "-program")
        executable.write_bytes(raw)
        executable.chmod(0o755)
        subprocess.run(["codesign", "--force", "--sign", "-",
                        "--timestamp=none", str(executable)],
                       check=True, capture_output=True)
        proc = subprocess.run([str(executable)], capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 7, proc.stderr)

    def test_execute_patched_arm64_program(self):
        # Unlike structure-only tests, this exercises dyld and the detour.
        raw = self.patch([
            {"type": "inject_arm64", "name": "new_main",
             "asm": "mov x0, #7; ret"},
            {"type": "hook_arm64", "mode": "replace",
             "address": hex(self.address), "expected_hex": "1f2003d5",
             "symbol": "new_main"},
        ])
        executable = self.root / (self._testMethodName + "-program")
        executable.write_bytes(raw)
        executable.chmod(0o755)
        subprocess.run(["codesign", "--force", "--sign", "-",
                        "--timestamp=none", str(executable)],
                       capture_output=True, check=True)
        proc = subprocess.run([str(executable)], capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 7,
                         "Mach-O did not execute injected code: %r" % proc.stderr)

    def test_before_hook_relocates_adr_target_after_relayout(self):
        import lief
        from ipa_macho_inject import _encode_pc_relative
        encoded = _encode_pc_relative(0, self.address + 4, self.address)
        raw = self.patch([
            {"type": "patch_address", "address": hex(self.address),
             "expected_hex": "1f2003d5", "new_hex": encoded.hex()},
            {"type": "hook_arm64", "mode": "before",
             "address": hex(self.address), "expected_hex": encoded.hex(),
             "asm": "nop"},
        ])
        image = lief.MachO.parse(raw).at(0)
        new_addr = int(image.get_section("__text").virtual_address)
        selected = arm64_slice(raw)
        patched_at = address_to_offset(raw, selected, new_addr)
        word, = struct.unpack_from("<I", raw, patched_at)
        self.assertEqual(word & 0xFC000000, 0x14000000)
        disp = word & 0x03FFFFFF
        if disp & (1 << 25):
            disp -= 1 << 26
        trampoline_addr = new_addr + disp * 4
        trampoline_at = address_to_offset(raw, selected, trampoline_addr)
        self.assertEqual(raw[trampoline_at:trampoline_at + 4],
                         bytes.fromhex("1f2003d5"))
        # The emitted ADR or ADRP+ADD must point into the *relocated* __text.
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, arm64_const
        cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        cs.detail = True
        insns = list(cs.disasm(raw[trampoline_at+4:trampoline_at+12],
                              trampoline_addr + 4))
        self.assertTrue(insns and insns[0].mnemonic in ("adr", "adrp"))
        if insns[0].mnemonic == "adr":
            self.assertEqual(insns[0].operands[-1].imm, new_addr + 4)

    def test_inject_and_hook_framework_executable(self):
        import json
        import lief
        target = "Frameworks/Library.framework/Library"
        with zipfile.ZipFile(self.ipa, "a") as archive:
            archive.write(self.binary, "Payload/Test.app/" + target)
        self.manifest.write_text(json.dumps({"operations": [
            {"type": "inject_arm64", "target": target,
             "name": "framework_code", "asm": "mov x0, #7; ret"},
            {"type": "hook_arm64", "target": target, "mode": "replace",
             "address": hex(self.address), "expected_hex": "1f2003d5",
             "symbol": "framework_code"}
        ]}))
        apply(self.ipa, self.manifest, self.out, allow_unsigned=True)
        with zipfile.ZipFile(self.out) as archive:
            main = archive.read("Payload/Test.app/test_arm64")
            framework = archive.read("Payload/Test.app/" + target)
        self.assertNotIn(b"__PKTEXT", main)
        self.assertIsNotNone(lief.MachO.parse(framework).at(0).get_segment("__PKTEXT"))
        self.assertNotEqual(main, framework)

    def test_auto_patch_arm64_inline(self):
        import lief
        raw = self.patch([{
            "type": "auto_patch_arm64",
            "address": hex(self.address),
            "expected_hex": "1f2003d5",
            "asm": "ret"
        }])
        selected = arm64_slice(raw)
        pos = address_to_offset(raw, selected, self.address)
        self.assertEqual(raw[pos:pos + 4], bytes.fromhex("c0035fd6"))
        self.assertIsNone(lief.MachO.parse(raw).at(0).get_segment("__PKTEXT"))

    def test_auto_patch_arm64_injects_if_too_large(self):
        import lief
        raw = self.patch([{
            "type": "auto_patch_arm64",
            "address": hex(self.address),
            "expected_hex": "1f2003d5",
            "asm": "nop; nop; ret"
        }])
        image = lief.MachO.parse(raw).at(0)
        current = int(image.get_section("__text").virtual_address)
        self.assertIsNotNone(image.get_segment("__PKTEXT"))
        selected = arm64_slice(raw)
        pos = address_to_offset(raw, selected, current)
        branch, = struct.unpack_from("<I", raw, pos)
        self.assertEqual(branch & 0xFC000000, 0x14000000)
        rel = branch & 0x03FFFFFF
        if rel & (1 << 25):
            rel -= 1 << 26
        target = current + rel * 4
        dest = address_to_offset(raw, selected, target)
        self.assertEqual(raw[dest:dest + 12],
                         bytes.fromhex("1f2003d51f2003d5c0035fd6"))

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
