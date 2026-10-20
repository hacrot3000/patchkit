"""Opt-in Mach-O ARM64 code expansion and function detours.

Requires LIEF, Keystone and Capstone. This uses a new RX segment rather than
shifting instructions inside __TEXT. Only regular arm64 (not arm64e) is allowed
for automatic detours; PC-relative instructions cannot be copied blindly.
"""
import json
import os
import struct
import tempfile
from pathlib import Path

from ipa_patch import IPAError, address_to_offset, arm64_slice, hexbytes, number

SEGMENT = "__PKTEXT"
NOP = bytes.fromhex("1f2003d5")
MAX_CAPACITY = 4 * 1024 * 1024
BRANCH_RANGE = 1 << 27


def _dependencies():
    try:
        import lief
        from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, arm64_const
    except ImportError as exc:
        raise IPAError(
            "Mach-O expansion requires: pip install 'lief>=0.17,<2' "
            "keystone-engine capstone"
        ) from exc
    return lief, Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN), Cs(
        CS_ARCH_ARM64, CS_MODE_ARM
    ), arm64_const


def _assemble(assembler, script, address):
    if not isinstance(script, str) or not script.strip():
        raise IPAError("ARM64 assembly must be a non-empty string")
    try:
        raw, _ = assembler.asm(script, addr=address)
    except Exception as exc:
        raise IPAError("Cannot assemble code at 0x%x: %s" % (address, exc)) from exc
    if not raw or len(raw) % 4:
        raise IPAError("Assembly must produce whole 4-byte ARM64 instructions")
    return bytes(raw)


def _branch(from_address, to_address):
    displacement = to_address - from_address
    if displacement % 4 or not -BRANCH_RANGE <= displacement < BRANCH_RANGE:
        raise IPAError(
            "ARM64 B out of +/-128MiB reach: 0x%x -> 0x%x; "
            "automatic long-range trampolines are not supported"
            % (from_address, to_address)
        )
    return struct.pack("<I", 0x14000000 | ((displacement >> 2) & 0x03FFFFFF))


def _copyable_stolen(disassembler, constants, original, address):
    if len(original) % 4 or len(original) < 4:
        raise IPAError("Hook overwrite must span whole ARM64 instructions")
    instructions = list(disassembler.disasm(original, address))
    if len(instructions) != len(original) // 4:
        raise IPAError("Cannot decode all overwritten ARM64 instructions")
    for instr in instructions:
        name = instr.mnemonic.lower()
        # Branches, PC-relative references and PAC/BTI instructions cannot be
        # relocated by simply copying bytes into the hook trampoline.
        if (name in ("adr", "adrp", "b", "bl", "br", "blr", "ret",
                     "cbz", "cbnz", "tbz", "tbnz")
                or name.startswith(("b.", "pac", "aut", "bra", "blr", "bti"))
                or (name in ("ldr", "ldrsw", "prfm", "ldrsb", "ldrsh")
                    and instr.operands
                    and instr.operands[-1].type == constants.ARM64_OP_IMM)):
            raise IPAError("Cannot safely relocate original instruction: %s %s "
                           "at 0x%x" % (instr.mnemonic, instr.op_str, instr.address))
    return original


def _verify_hook(source, hook, disassembler, constants):
    if "address" not in hook:
        raise IPAError("hook_arm64 requires address")
    addr = number(hook["address"])
    if addr % 4:
        raise IPAError("Hook address must be 4-byte aligned")
    expected = hexbytes(hook.get("expected_hex"))
    selected = arm64_slice(source)
    if selected.offset != 0:
        raise IPAError("Automatic hook requires a thin, single-architecture arm64 Mach-O")
    offset = address_to_offset(source, selected, addr)
    if offset + len(expected) > selected.size:
        raise IPAError("Hook overwrite exceeds Mach-O file")
    if source[offset:offset + len(expected)] != expected:
        raise IPAError("Hook expected_hex mismatch at 0x%x" % addr)
    mode = hook.get("mode", "before")
    if mode not in ("before", "replace"):
        raise IPAError("hook_arm64 mode must be before or replace")
    if mode == "before":
        _copyable_stolen(disassembler, constants, expected, addr)
        if not isinstance(hook.get("asm"), str):
            raise IPAError("before hook requires asm")
    elif not isinstance(hook.get("symbol"), str):
        raise IPAError("replace hook requires an injected symbol")
    # Prevent accidental hook of data or non-executable ranges.
    _, _, _, _, count, cmd_size, _, _ = struct.unpack_from("<IiiIIIII", source, 0)
    cursor = 32
    executable = False
    for _ in range(count):
        if cursor + 8 > len(source):
            raise IPAError("Malformed Mach-O load commands")
        cmd, size = struct.unpack_from("<II", source, cursor)
        if size < 8 or cursor + size > 32 + cmd_size:
            raise IPAError("Malformed Mach-O load commands")
        if cmd == 0x19:
            values = struct.unpack_from("<II16sQQQQiiII", source, cursor)
            vmaddr, vmsize, initprot = values[3], values[4], values[8]
            if vmaddr <= addr and addr + len(expected) <= vmaddr + vmsize:
                executable = bool(initprot & 4)
                break
        cursor += size
    if not executable:
        raise IPAError("Hook address must lie in an executable Mach-O segment")
    return addr, expected, mode


def _parse_lief(lief, path):
    fat = lief.MachO.parse(str(path))
    if fat is None or fat.size != 1:
        raise IPAError("LIEF needs a single-architecture thin Mach-O for code expansion")
    binary = fat.at(0)
    if binary is None or binary.header.cpu_type != lief.MachO.Header.CPU_TYPE.ARM64:
        raise IPAError("Mach-O expansion only supports arm64")
    if binary.get_segment(SEGMENT) is not None:
        raise IPAError("Mach-O already contains reserved " + SEGMENT)
    return fat, binary


def _require_ops(operations):
    size = 0
    symbols = set()
    hooks = []
    for item in operations:
        if item.get("target", "executable") != "executable":
            raise IPAError("Mach-O expansion supports the main executable only")
        kind = item.get("type")
        if item.get("arch", "arm64") != "arm64":
            raise IPAError("Automatic injection and hooking refuse arm64e")
        if kind == "inject_arm64":
            symbol = item.get("name")
            if not isinstance(symbol, str) or not symbol.isidentifier():
                raise IPAError("inject_arm64 requires a unique identifier name")
            if symbol in symbols:
                raise IPAError("Duplicate injected symbol: " + symbol)
            symbols.add(symbol)
            if not isinstance(item.get("asm"), str) or not item["asm"].strip():
                raise IPAError("inject_arm64 requires asm")
            size += max(256, len(item["asm"]) * 5)
        elif kind == "hook_arm64":
            hooks.append(item)
            size += 1024
        elif kind == "extend_macho":
            amount = number(item.get("size"))
            if amount <= 0 or amount > MAX_CAPACITY:
                raise IPAError("extend_macho size must be 1..%d" % MAX_CAPACITY)
            size += amount
        else:
            raise IPAError("Unknown structural patch type: %r" % kind)
    for hook in hooks:
        if hook.get("mode", "before") == "replace" and hook.get("symbol") not in symbols:
            raise IPAError("replace hook references unknown injected symbol")
    # LIEF may page-align a new segment, but actual payload stays 4-byte aligned.
    capacity = ((size + 16383) // 16384) * 16384
    if capacity > MAX_CAPACITY:
        raise IPAError("Maximum injectable code capacity exceeded")
    return capacity


def expand_macho(path, operations, report=None):
    """Expand an executable with RX __PKTEXT then apply verified ARM64 hooks.

    Files are replaced only after LIEF output reparses and all patch sites pass.
    """
    path = Path(path)
    if not operations:
        return {}
    lief, assembler, disassembler, constants = _dependencies()
    data = path.read_bytes()
    chosen = arm64_slice(data)
    if chosen.offset != 0 or chosen.size != len(data):
        raise IPAError("Structural Mach-O changes currently require a thin arm64 binary")
    capacity = _require_ops(operations)
    verified_hooks = {}
    for index, item in enumerate(operations):
        if item["type"] == "hook_arm64":
            verified_hooks[index] = _verify_hook(data, item, disassembler, constants)
    fat, binary = _parse_lief(lief, path)
    # Original signature cannot survive executable modifications; top-level IPA
    # signing or explicit --allow-unsigned is handled by ipa_patch.py.
    binary.remove_signature()
    segment = lief.MachO.SegmentCommand(SEGMENT, list(NOP * (capacity // 4)))
    segment.max_protection = 5  # VM_PROT_READ | VM_PROT_EXECUTE (not RWX)
    segment.init_protection = 5
    if binary.add(segment) is None:
        raise IPAError("LIEF could not allocate the new Mach-O executable segment")
    with tempfile.TemporaryDirectory(prefix="patchkit-lief-") as temp:
        intermediate = Path(temp) / "expanded"
        fat.write(str(intermediate))
        raw = bytearray(intermediate.read_bytes())
        selected = arm64_slice(raw)
        rebuilt = lief.MachO.parse(str(intermediate))
        if rebuilt is None or rebuilt.size != 1:
            raise IPAError("Expanded Mach-O cannot be reparsed by LIEF")
        new_segment = rebuilt.at(0).get_segment(SEGMENT)
        if new_segment is None:
            raise IPAError("LIEF did not write the injected segment")
        if new_segment.init_protection & 5 != 5 or new_segment.init_protection & 2:
            raise IPAError("New code segment protection is not RX")
        base = int(new_segment.virtual_address)
        start = int(new_segment.file_offset)
        available = min(int(new_segment.file_size), len(raw) - start)
        if start < 0 or available < capacity:
            raise IPAError("New segment does not have reserved file-backed capacity")
        cursor, named = 0, {}
        pending = []
        for index, item in enumerate(operations):
            kind = item["type"]
            cursor = (cursor + 3) & ~3
            if kind == "extend_macho":
                cursor += (number(item["size"]) + 3) & ~3
                continue
            address = base + cursor
            if kind == "inject_arm64":
                payload = _assemble(assembler, item["asm"], address)
                named[item["name"]] = address
            else:
                old_addr, stolen, mode = verified_hooks[index]
                if mode == "before":
                    body = _assemble(assembler, item["asm"], address)
                    payload = body + stolen
                    payload += _branch(address + len(payload), old_addr + len(stolen))
                    pending.append((old_addr, stolen, address))
                else:
                    payload = b""
                    pending.append((old_addr, stolen, item["symbol"]))
            if cursor + len(payload) > capacity or cursor + len(payload) > available:
                raise IPAError("Injected code exceeds allocated Mach-O code segment")
            raw[start + cursor:start + cursor + len(payload)] = payload
            cursor += len(payload)
        patch_sites = []
        for old_addr, stolen, destination in pending:
            target = named[destination] if isinstance(destination, str) else destination
            branch = _branch(old_addr, target)
            pos = address_to_offset(raw, selected, old_addr)
            if raw[pos:pos + len(stolen)] != stolen:
                raise IPAError("Hook original bytes changed during Mach-O reconstruction")
            patch_sites.append((pos, stolen, branch + NOP * (len(stolen) // 4 - 1)))
        # Two detours may not overwrite overlapping ranges.
        occupied = set()
        for pos, previous, patched in patch_sites:
            touched = set(range(pos, pos + len(previous)))
            if occupied & touched:
                raise IPAError("Overlapping hook sites")
            occupied |= touched
            raw[pos:pos + len(previous)] = patched
        intermediate.write_bytes(raw)
        # Reparse to catch invalid load commands and validate new binary structure.
        checked = lief.MachO.parse(str(intermediate))
        if checked is None or checked.size != 1 or not checked.at(0).get_segment(SEGMENT):
            raise IPAError("Patched Mach-O failed structural verification")
        path.write_bytes(raw)
    info = {"segment": SEGMENT, "base": hex(base), "allocated": capacity,
            "used": cursor, "symbols": {name: hex(addr) for name, addr in named.items()},
            "hook_count": len(pending)}
    if report is not None:
        report.update(info)
    return info
