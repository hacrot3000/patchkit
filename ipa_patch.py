#!/usr/bin/env python3
"""Patch an iOS IPA offline without changing PatchKit's legacy ELF backend.

This module deliberately supports *in-place, fixed-size* ARM64 edits only.
Mach-O segment growth, relocation, injection and hooks are not implemented.
"""
import argparse
import hashlib
import json
import re
import os
import plistlib
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
MACHO_64_LE = b"\xcf\xfa\xed\xfe"
FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}


class IPAError(ValueError):
    pass


def number(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise IPAError("Expected an integer or 0x-prefixed integer string")
    try:
        return int(value, 0) if isinstance(value, str) else value
    except ValueError as exc:
        raise IPAError("Invalid numeric offset/address: %r" % value) from exc


def hexbytes(value):
    if not isinstance(value, str):
        raise IPAError("Hex bytes must be a string")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise IPAError("Invalid hex bytes") from exc
    if not result:
        raise IPAError("Empty byte sequence is not allowed")
    return result


def safe_member(name):
    if not name or "\\" in name or name.startswith("/"):
        raise IPAError("Unsafe ZIP entry: %r" % name)
    parts = PurePosixPath(name).parts
    if any(p in (".", "..") for p in name.rstrip("/").split("/")) or not parts:
        raise IPAError("Unsafe ZIP entry: %r" % name)
    if parts[0] == "__MACOSX":
        return parts
    return parts


def extract_ipa(ipa, root, max_bytes):
    total = 0
    pending_links = []
    seen = set()
    with zipfile.ZipFile(ipa) as archive:
        for info in archive.infolist():
            parts = safe_member(info.filename)
            key = "/".join(parts)
            if key in seen:
                raise IPAError("Duplicate ZIP entry: %s" % key)
            seen.add(key)
            total += info.file_size
            if total > max_bytes:
                raise IPAError("IPA exceeds maximum allowed uncompressed size")
            dest = root.joinpath(*parts)
            mode = info.external_attr >> 16
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            if stat.S_ISLNK(mode):
                link = archive.read(info).decode("utf-8")
                if not link or os.path.isabs(link) or "\\" in link:
                    raise IPAError("Unsafe symbolic link: %s" % key)
                pending_links.append((dest, link))
                continue
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise IPAError("Unsupported ZIP entry type: %s" % key)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, dest.open("wb") as sink:
                shutil.copyfileobj(source, sink)
            if mode & 0o777:
                dest.chmod(mode & 0o777)
    for dest, link in pending_links:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.symlink_to(link)
    root_real = root.resolve()
    for dest, _ in pending_links:
        try:
            dest.resolve(strict=True).relative_to(root_real)
        except (ValueError, RuntimeError, OSError) as exc:
            raise IPAError("Unsafe or broken symbolic link: %s" % dest) from exc


def app_bundle(root):
    payload = root / "Payload"
    if not payload.is_dir():
        raise IPAError("IPA is missing Payload/")
    apps = [p for p in payload.iterdir() if p.is_dir() and p.suffix == ".app"]
    if len(apps) != 1:
        raise IPAError("Expected exactly one top-level Payload/*.app")
    app = apps[0]
    try:
        info = plistlib.loads((app / "Info.plist").read_bytes())
        name = info["CFBundleExecutable"]
    except (OSError, KeyError, ValueError, TypeError) as exc:
        raise IPAError("Invalid or missing Info.plist / CFBundleExecutable") from exc
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise IPAError("Invalid CFBundleExecutable")
    exe = app / name
    if not exe.is_file() or exe.is_symlink():
        raise IPAError("Missing or unsafe main executable: %s" % name)
    return app, exe


@dataclass(frozen=True)
class Slice:
    offset: int
    size: int
    subtype: int


def arm64_slice(data, flavor="arm64"):
    if flavor not in ("arm64", "arm64e"):
        raise IPAError("Only arm64 and arm64e are supported")
    candidates = []
    if data[:4] == MACHO_64_LE:
        if len(data) < 32:
            raise IPAError("Truncated Mach-O header")
        cpu, subtype = struct.unpack_from("<ii", data, 4)
        candidates.append((cpu, subtype, 0, len(data)))
    elif bytes(data[:4]) in FAT_MAGICS:
        endian, fat64 = FAT_MAGICS[bytes(data[:4])]
        if len(data) < 8:
            raise IPAError("Truncated FAT header")
        count = struct.unpack_from(endian + "I", data, 4)[0]
        if count > 64:
            raise IPAError("Unreasonable FAT slice count")
        width = 32 if fat64 else 20
        if 8 + count * width > len(data):
            raise IPAError("Truncated FAT table")
        for i in range(count):
            at = 8 + i * width
            if fat64:
                cpu, subtype, offset, size, _, _ = struct.unpack_from(
                    endian + "iiQQII", data, at
                )
            else:
                cpu, subtype, offset, size, _ = struct.unpack_from(
                    endian + "iiIII", data, at
                )
            if offset > len(data) or size > len(data) - offset:
                raise IPAError("FAT slice outside file")
            candidates.append((cpu, subtype, offset, size))
    else:
        raise IPAError("Target is not a supported 64-bit Mach-O executable")
    wanted = 2 if flavor == "arm64e" else 0
    for cpu, subtype, offset, size in candidates:
        if cpu == ARM64 and ((subtype & 0xff) == 2) == (wanted == 2):
            if data[offset:offset + 4] != MACHO_64_LE:
                raise IPAError("FAT entry does not contain an ARM64 Mach-O")
            selected = Slice(offset, size, subtype)
            check_unencrypted(data, selected)
            return selected
    raise IPAError("Mach-O has no %s slice" % flavor)



def check_unencrypted(data, selected):
    """Reject FairPlay/encrypted Mach-O code, which cannot be patched this way."""
    base, end = selected.offset, selected.offset + selected.size
    if base + 32 > end:
        raise IPAError("Truncated Mach-O header")
    _, _, _, _, count, commands_size, _, _ = struct.unpack_from(
        "<IiiIIIII", data, base
    )
    cursor, limit = base + 32, base + 32 + commands_size
    if count > 4096 or limit > end:
        raise IPAError("Invalid Mach-O load commands")
    for _ in range(count):
        if cursor + 8 > limit:
            raise IPAError("Truncated Mach-O load command")
        cmd, size = struct.unpack_from("<II", data, cursor)
        if size < 8 or cursor + size > limit:
            raise IPAError("Malformed Mach-O load command")
        if cmd in (0x21, 0x2C):
            if size < 20:
                raise IPAError("Truncated Mach-O encryption command")
            encrypted = struct.unpack_from("<I", data, cursor + 16)[0]
            if encrypted:
                raise IPAError("Encrypted Mach-O (FairPlay) cannot be patched")
        cursor += size

def address_to_offset(data, selected, address):
    base, end = selected.offset, selected.offset + selected.size
    if base + 32 > end:
        raise IPAError("Truncated Mach-O header")
    _, cpu, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from(
        "<IiiIIIII", data, base
    )
    if cpu != ARM64 or ncmds > 4096 or base + 32 + sizeofcmds > end:
        raise IPAError("Invalid Mach-O load commands")
    cursor, limit = base + 32, base + 32 + sizeofcmds
    for _ in range(ncmds):
        if cursor + 8 > limit:
            raise IPAError("Truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize < 8 or cursor + cmdsize > limit:
            raise IPAError("Malformed Mach-O load command")
        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise IPAError("Truncated Mach-O segment")
            _, _, _, vmaddr, _, fileoff, filesize, _, _, _, _ = struct.unpack_from(
                "<II16sQQQQiiII", data, cursor
            )
            if vmaddr <= address < vmaddr + filesize:
                relative = fileoff + (address - vmaddr)
                if relative >= selected.size:
                    raise IPAError("Virtual address maps outside selected slice")
                return relative
        cursor += cmdsize
    raise IPAError("Address is not backed by Mach-O file bytes")


def target_file(app, executable, target):
    if target == "executable":
        return executable
    if not isinstance(target, str) or not target:
        raise IPAError("Invalid target")
    safe_member(target)
    candidate = app.joinpath(*PurePosixPath(target).parts)
    if not candidate.is_file() or candidate.is_symlink():
        raise IPAError("Patch target must be an existing regular file: %s" % target)
    if not candidate.resolve().is_relative_to(app.resolve()):
        raise IPAError("Patch target escapes app bundle")
    return candidate


def patch_operation(app, executable, operation, manifest_dir):
    if not isinstance(operation, dict):
        raise IPAError("Every operation must be a JSON object")
    kind = operation.get("type")
    path = target_file(app, executable, operation.get("target", "executable"))
    if kind == "replace_file":
        source = operation.get("source")
        if not isinstance(source, str) or not source:
            raise IPAError("replace_file requires source")
        src = (manifest_dir / source).resolve()
        if not src.is_file():
            raise IPAError("Replacement file not found: %s" % source)
        shutil.copyfile(src, path)
        return
    data = bytearray(path.read_bytes())
    if kind == "replace_bytes":
        old, new = hexbytes(operation.get("old_hex")), hexbytes(operation.get("new_hex"))
        if len(old) != len(new):
            raise IPAError("replace_bytes must preserve byte length")
        expected = number(operation.get("occurrences", 1))
        # When editing Mach-O, restrict searches to the selected architecture.
        # Otherwise a FAT binary might accidentally patch another slice.
        if bytes(data[:4]) == MACHO_64_LE or bytes(data[:4]) in FAT_MAGICS:
            selected = arm64_slice(data, operation.get("arch", "arm64"))
            start, end = selected.offset, selected.offset + selected.size
        else:
            start, end = 0, len(data)
        region = bytes(data[start:end])
        if expected < 1 or region.count(old) != expected:
            raise IPAError("replace_bytes occurrence count mismatch in %s" % path)
        data[start:end] = region.replace(old, new)
    elif kind in ("patch_offset", "patch_address", "arm64_asm"):
        flavor = operation.get("arch", "arm64")
        selected = arm64_slice(data, flavor)
        if kind == "patch_offset":
            relative = number(operation.get("offset"))
        else:
            relative = address_to_offset(data, selected, number(operation.get("address")))
        if relative < 0:
            raise IPAError("Negative patch offset")
        old = hexbytes(operation.get("expected_hex"))
        if kind == "arm64_asm":
            if relative % 4 or len(old) % 4:
                raise IPAError("ARM64 instructions must be 4-byte aligned")
            asm = operation.get("asm")
            if not isinstance(asm, str) or not asm.strip():
                raise IPAError("arm64_asm requires nonempty asm")
            try:
                from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
            except ImportError as exc:
                raise IPAError("arm64_asm requires the optional keystone-engine package") from exc
            encoder = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            try:
                result, _ = encoder.asm(asm, number(operation["address"]))
            except Exception as exc:
                raise IPAError("ARM64 assembly failed: %s" % exc) from exc
            new = bytes(result)
        else:
            new = hexbytes(operation.get("new_hex"))
        if len(new) != len(old):
            raise IPAError("Fixed-size patches cannot grow or shrink instructions")
        if relative > selected.size or len(old) > selected.size - relative:
            raise IPAError("Patch outside selected Mach-O slice")
        pos = selected.offset + relative
        if bytes(data[pos:pos + len(old)]) != old:
            raise IPAError("Expected original bytes mismatch in %s at 0x%x" % (path, relative))
        data[pos:pos + len(old)] = new
    else:
        raise IPAError("Unknown patch type: %r" % kind)
    path.write_bytes(data)


def signable_paths(app):
    """Enumerate signing targets with nested bundles before their containers."""
    extensions = {".app", ".appex", ".framework", ".xpc", ".dylib"}
    items = []
    for base, dirs, files in os.walk(app, followlinks=False):
        for name in dirs + files:
            candidate = Path(base) / name
            if not candidate.is_symlink() and candidate.suffix in extensions:
                items.append(candidate)
    items.sort(key=lambda p: len(p.relative_to(app).parts), reverse=True)
    return items + [app]


def snapshot_entitlements(app, destination):
    """Read existing entitlements before any executable signature is removed.

    Using the original per-target entitlements avoids stripping extension
    capabilities by accident. Output files live outside the app ZIP tree.
    """
    if sys.platform != "darwin" or not shutil.which("codesign"):
        raise IPAError("Signing requires macOS and codesign")
    saved = {}
    destination.mkdir(parents=True, exist_ok=True)
    for i, path in enumerate(signable_paths(app)):
        relative = path.relative_to(app).as_posix()
        signed = subprocess.run(["codesign", "-d", "--verbose=1", str(path)],
                                capture_output=True)
        if signed.returncode != 0:
            continue  # Unsigned fixture or locally built app
        check = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(path)],
                               capture_output=True)
        if check.returncode != 0:
            raise IPAError("Failed to read original entitlements for %s" % relative)
        raw = check.stdout
        if not raw.strip():
            continue
        try:
            document = plistlib.loads(raw)
        except (ValueError, TypeError, OverflowError) as exc:
            raise IPAError("Invalid original entitlements in %s" % relative) from exc
        if not isinstance(document, dict):
            raise IPAError("Entitlements must be a plist dictionary: %s" % relative)
        out = destination / ("entitlements-%d.plist" % i)
        out.write_bytes(plistlib.dumps(document))
        saved[relative] = out
    return saved


def resign(app, identity, entitlements=None, profile=None, original_entitlements=None):
    if sys.platform != "darwin" or not shutil.which("codesign"):
        raise IPAError("Signing requires macOS and codesign")
    if profile:
        shutil.copyfile(profile, app / "embedded.mobileprovision")
    saved = original_entitlements or {}
    for path in signable_paths(app):
        relative = path.relative_to(app).as_posix()
        path_entitlements = (
            Path(entitlements) if path == app and entitlements
            else saved.get(relative)
        )
        args = ["codesign", "--force", "--sign", identity, "--timestamp=none"]
        if path_entitlements is not None:
            args += ["--entitlements", str(path_entitlements)]
        args.append(str(path))
        subprocess.run(args, check=True)
        if path_entitlements is not None:
            observed = subprocess.run(
                ["codesign", "-d", "--entitlements", ":-", str(path)],
                capture_output=True, check=True
            )
            expected = plistlib.loads(Path(path_entitlements).read_bytes())
            try:
                actual = plistlib.loads(observed.stdout)
            except (ValueError, TypeError) as exc:
                raise IPAError("Cannot validate new entitlements: %s" % relative) from exc
            if actual != expected:
                raise IPAError("Entitlements changed while signing: %s" % relative)
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True)


def repack(root, destination):
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="ipa-patch-", suffix=".ipa",
                                     dir=dest.parent, delete=False) as temp:
        tmp = Path(temp.name)
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for base, dirs, files in os.walk(root, followlinks=False):
                for name in sorted(dirs + files):
                    path = Path(base) / name
                    relative = path.relative_to(root).as_posix()
                    if path.is_symlink():
                        entry = zipfile.ZipInfo(relative)
                        entry.create_system = 3
                        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                        output.writestr(entry, os.readlink(path).encode("utf-8"))
                    elif path.is_file():
                        output.write(path, relative)
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)


def apply(ipa, manifest, output, *, allow_unsigned=False, sign_identity=None,
          entitlements=None, profile=None, max_unpacked_mib=2048):
    ipa, manifest, output = Path(ipa).resolve(), Path(manifest).resolve(), Path(output).resolve()
    if ipa == output:
        raise IPAError("Output must differ from input IPA")
    if not sign_identity and not allow_unsigned:
        raise IPAError("Specify --sign-identity or explicitly --allow-unsigned")
    if entitlements and not sign_identity:
        raise IPAError("--entitlements requires --sign-identity")
    if profile and not sign_identity:
        raise IPAError("--profile requires --sign-identity")
    try:
        spec = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise IPAError("Cannot read patch manifest") from exc
    operations = spec.get("operations") if isinstance(spec, dict) else None
    if not isinstance(operations, list) or not operations:
        raise IPAError("Manifest must contain a nonempty operations array")
    source_hash = spec.get("input_sha256")
    if source_hash is not None:
        if not isinstance(source_hash, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", source_hash):
            raise IPAError("input_sha256 must be 64 hexadecimal characters")
        digest = hashlib.sha256()
        with ipa.open("rb") as original:
            for block in iter(lambda: original.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest().lower() != source_hash.lower():
            raise IPAError("Input IPA SHA256 does not match manifest")
    with tempfile.TemporaryDirectory(prefix="patchkit-ipa-") as temp:
        root = Path(temp) / "ipa"
        root.mkdir()
        extract_ipa(ipa, root, max_unpacked_mib * 1024 * 1024)
        app, executable = app_bundle(root)
        preserved = (snapshot_entitlements(app, Path(temp) / "__preserved_signatures")
                     if sign_identity else {})
        structural = []
        structural_started = False
        for i, operation in enumerate(operations):
            try:
                if not isinstance(operation, dict):
                    raise IPAError("Every operation must be a JSON object")
                if operation.get("type") in ("inject_arm64", "hook_arm64", "extend_macho"):
                    structural_started = True
                    structural.append(operation)
                    continue
                if structural_started:
                    raise IPAError("All Mach-O expansion operations must be last in the manifest")
                patch_operation(app, executable, operation, manifest.parent)
            except (IPAError, OSError) as exc:
                raise IPAError("Operation %d failed: %s" % (i + 1, exc)) from exc
        if structural:
            from ipa_macho_inject import expand_macho
            details = expand_macho(executable, structural)
            print("Mach-O expansion: %s" % json.dumps(details, sort_keys=True))
        if sign_identity:
            resign(app, sign_identity, entitlements, profile, preserved)
        repack(root, output)
    if not sign_identity:
        print("WARNING: output IPA is NOT re-signed and cannot be installed as-is.", file=sys.stderr)
    print("Wrote %s" % output)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Patch iOS IPA (fixed-size ARM64 and resources)")
    parser.add_argument("ipa", type=Path, help="Input IPA")
    parser.add_argument("manifest", type=Path, help="JSON patch manifest")
    parser.add_argument("-o", "--output", required=True, type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sign-identity", help="macOS codesign identity")
    group.add_argument("--allow-unsigned", action="store_true",
                       help="Output a non-installable IPA for inspection / external re-signing")
    parser.add_argument("--entitlements", type=Path, help="Entitlements plist when signing")
    parser.add_argument("--profile", type=Path, help="Provisioning profile when signing")
    parser.add_argument("--max-unpacked-mib", type=int, default=2048)
    args = parser.parse_args(argv)
    try:
        if args.max_unpacked_mib < 1:
            raise IPAError("--max-unpacked-mib must be positive")
        apply(args.ipa, args.manifest, args.output, allow_unsigned=args.allow_unsigned,
              sign_identity=args.sign_identity, entitlements=args.entitlements,
              profile=args.profile, max_unpacked_mib=args.max_unpacked_mib)
    except (IPAError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        parser.exit(1, "ERROR: %s\n" % exc)


if __name__ == "__main__":
    main()
