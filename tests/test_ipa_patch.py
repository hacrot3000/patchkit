import hashlib
import importlib.util
import json
import plistlib
import stat
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from ipa_patch import (
    ARM64, IPAError, address_to_offset, apply, arm64_slice, extract_ipa,
)

VMADDR = 0x100000000
OLD = bytes.fromhex("1f2003d5")
NEW = bytes.fromhex("c0035fd6")


def thin_macho():
    length = 0x104
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, ARM64, 0, 2, 1, 72, 0, 0)
    segment = struct.pack(
        "<II16sQQQQiiII", 0x19, 72, b"__TEXT".ljust(16, b"\x00"),
        VMADDR, 0x1000, 0, length, 7, 5, 0, 0
    )
    return header + segment + b"\x00" * (0x100 - 104) + OLD


def make_ipa(path, binary=None):
    binary = thin_macho() if binary is None else binary
    with zipfile.ZipFile(path, "w") as ipa:
        ipa.writestr("Payload/Sample.app/Info.plist", plistlib.dumps({
            "CFBundleExecutable": "Sample", "CFBundleIdentifier": "test.patchkit.sample"
        }))
        executable = zipfile.ZipInfo("Payload/Sample.app/Sample")
        executable.create_system = 3
        executable.external_attr = (stat.S_IFREG | 0o755) << 16
        ipa.writestr(executable, binary)
        ipa.writestr("Payload/Sample.app/note.txt", b"Original note")


def entry(path, name):
    with zipfile.ZipFile(path) as ipa:
        return ipa.read("Payload/Sample.app/" + name)


class IPATests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        self.source = self.root / "input.ipa"
        self.out = self.root / "patched.ipa"
        self.manifest = self.root / "patch.json"
        make_ipa(self.source)

    def write_manifest(self, *operations):
        self.manifest.write_text(json.dumps({"operations": operations}), encoding="utf-8")

    def run_patch(self, **kwargs):
        apply(self.source, self.manifest, self.out, allow_unsigned=True, **kwargs)

    def test_patch_macho_address(self):
        self.write_manifest({"type": "patch_address", "address": hex(VMADDR + 0x100),
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        self.run_patch()
        self.assertEqual(entry(self.out, "Sample")[0x100:0x104], NEW)
        self.assertEqual(entry(self.out, "note.txt"), b"Original note")

    def test_patch_macho_offset(self):
        self.write_manifest({"type": "patch_offset", "offset": "0x100",
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        self.run_patch()
        self.assertEqual(entry(self.out, "Sample")[0x100:0x104], NEW)

    @unittest.skipUnless(importlib.util.find_spec("keystone"), "keystone-engine not installed")
    def test_arm64_assembly(self):
        self.write_manifest({"type": "arm64_asm", "address": hex(VMADDR + 0x100),
                             "expected_hex": OLD.hex(), "asm": "ret"})
        self.run_patch()
        self.assertEqual(entry(self.out, "Sample")[0x100:0x104], NEW)

    def test_fat_arm64_slice(self):
        thin = thin_macho()
        fat = struct.pack(">IIiiIII", 0xCAFEBABE, 1, ARM64, 0, 0x100,
                          len(thin), 12) + b"\x00" * (0x100 - 28) + thin
        selection = arm64_slice(fat)
        self.assertEqual(selection.offset, 0x100)
        self.assertEqual(address_to_offset(fat, selection, VMADDR + 0x100), 0x100)
        make_ipa(self.source, fat)
        self.write_manifest({"type": "patch_address", "address": hex(VMADDR + 0x100),
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        self.run_patch()
        self.assertEqual(entry(self.out, "Sample")[0x200:0x204], NEW)

    def test_replace_resource(self):
        (self.root / "new.txt").write_bytes(b"Updated note")
        self.write_manifest({"type": "replace_file", "target": "note.txt", "source": "new.txt"})
        self.run_patch()
        self.assertEqual(entry(self.out, "note.txt"), b"Updated note")

    def test_replace_bytes_guard(self):
        self.write_manifest({"type": "replace_bytes", "target": "note.txt",
                             "old_hex": b"Original".hex(), "new_hex": b"Replaced".hex()})
        self.run_patch()
        self.assertEqual(entry(self.out, "note.txt"), b"Replaced note")

    def test_mismatch_fails_no_output(self):
        self.write_manifest({"type": "patch_offset", "offset": 0x100,
                             "expected_hex": "ffffffff", "new_hex": NEW.hex()})
        with self.assertRaisesRegex(IPAError, "Expected original bytes"):
            self.run_patch()
        self.assertFalse(self.out.exists())

    def test_reject_length_change(self):
        self.write_manifest({"type": "patch_address", "address": hex(VMADDR + 0x100),
                             "expected_hex": OLD.hex(), "new_hex": "90"})
        with self.assertRaisesRegex(IPAError, "grow or shrink"):
            self.run_patch()

    def test_reject_out_of_slice(self):
        self.write_manifest({"type": "patch_offset", "offset": 0x104,
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        with self.assertRaisesRegex(IPAError, "outside selected"):
            self.run_patch()

    def test_dry_run_validates_without_writing_output(self):
        self.write_manifest({"type": "patch_address", "address": hex(VMADDR + 0x100),
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        initial = self.source.read_bytes()
        apply(self.source, self.manifest, dry_run=True)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.source.read_bytes(), initial)

    def test_dry_run_rejects_bad_expected_bytes(self):
        self.write_manifest({"type": "patch_address", "address": hex(VMADDR + 0x100),
                             "expected_hex": "ffffffff", "new_hex": NEW.hex()})
        with self.assertRaisesRegex(IPAError, "Expected original bytes"):
            apply(self.source, self.manifest, dry_run=True)
        self.assertFalse(self.out.exists())

    def test_repacked_archive_verifies_original_files(self):
        from ipa_patch import verify_repacked_archive
        self.write_manifest({"type": "replace_bytes", "target": "note.txt",
                             "old_hex": b"Original".hex(),
                             "new_hex": b"Replaced".hex()})
        self.run_patch()
        with tempfile.TemporaryDirectory() as folder:
            from ipa_patch import extract_ipa
            root = Path(folder)
            extract_ipa(self.out, root, 1024 * 1024)
            verify_repacked_archive(root, self.out)
            # A tampered file in the output archive must be detected rather
            # than silently accepted by an independent verification step.
            (root / "Payload/Sample.app/note.txt").write_bytes(b"Unexpected!")
            with self.assertRaisesRegex(IPAError, "content mismatch|size changed"):
                verify_repacked_archive(root, self.out)

    def test_repack_preserves_internal_symlinks(self):
        from ipa_patch import extract_ipa, verify_repacked_archive
        link = zipfile.ZipInfo("Payload/Sample.app/note-alias.txt")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.source, "a") as archive:
            archive.writestr(link, "note.txt")
        self.write_manifest({"type": "patch_offset", "offset": 0x100,
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        self.run_patch()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            extract_ipa(self.out, root, 1024 * 1024)
            self.assertTrue((root / "Payload/Sample.app/note-alias.txt").is_symlink())
            verify_repacked_archive(root, self.out)

    def test_signing_is_explicit(self):
        self.write_manifest({"type": "replace_file", "target": "note.txt", "source": "new.txt"})
        with self.assertRaisesRegex(IPAError, "sign-identity"):
            apply(self.source, self.manifest, self.out)

    def test_zip_slip_rejected(self):
        with zipfile.ZipFile(self.source, "a") as archive:
            archive.writestr("../outside.txt", "unsafe")
        self.write_manifest({"type": "patch_offset", "offset": 0x100,
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        with self.assertRaisesRegex(IPAError, "Unsafe ZIP entry"):
            self.run_patch()
        self.assertFalse((self.root / "outside.txt").exists())

    def test_unsafe_symlink_rejected(self):
        with zipfile.ZipFile(self.source, "a") as archive:
            info = zipfile.ZipInfo("Payload/Sample.app/badlink")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "/etc/passwd")
        self.write_manifest({"type": "patch_offset", "offset": 0x100,
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        with self.assertRaisesRegex(IPAError, "Unsafe symbolic link"):
            self.run_patch()

    def test_resource_path_traversal_rejected(self):
        self.write_manifest({"type": "replace_bytes", "target": "../Info.plist",
                             "old_hex": "0102", "new_hex": "0304"})
        with self.assertRaisesRegex(IPAError, "Unsafe ZIP entry"):
            self.run_patch()

    def test_input_sha256_guard(self):
        self.manifest.write_text(json.dumps({
            "input_sha256": "0" * 64,
            "operations": [{"type": "patch_offset", "offset": 0x100,
                            "expected_hex": OLD.hex(), "new_hex": NEW.hex()}]
        }))
        with self.assertRaisesRegex(IPAError, "SHA256 does not match"):
            self.run_patch()
        self.assertFalse(self.out.exists())
        correct = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest.write_text(json.dumps({
            "input_sha256": correct,
            "operations": [{"type": "patch_offset", "offset": 0x100,
                            "expected_hex": OLD.hex(), "new_hex": NEW.hex()}]
        }))
        self.run_patch()
        self.assertEqual(entry(self.out, "Sample")[0x100:0x104], NEW)

    def test_fairplay_encrypted_macho_rejected(self):
        binary = bytearray(thin_macho())
        struct.pack_into("<I", binary, 16, 2)  # ncmds
        struct.pack_into("<I", binary, 20, 96)  # sizeofcmds
        struct.pack_into("<IIIIII", binary, 104, 0x2C, 24, 0x100, 4, 1, 0)
        make_ipa(self.source, bytes(binary))
        self.write_manifest({"type": "patch_offset", "offset": 0x100,
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        with self.assertRaisesRegex(IPAError, "Encrypted Mach-O"):
            self.run_patch()

    def test_large_unpacked_ipa_rejected(self):
        self.write_manifest({"type": "patch_offset", "offset": 0x100,
                             "expected_hex": OLD.hex(), "new_hex": NEW.hex()})
        with self.assertRaisesRegex(IPAError, "maximum allowed"):
            self.run_patch(max_unpacked_mib=0)


if __name__ == "__main__":
    unittest.main()
