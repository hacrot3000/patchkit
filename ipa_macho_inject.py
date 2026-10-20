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
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    return lief, Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN), disassembler, arm64_const


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



def _validate_relocatable_stolen(disassembler, constants, original, address):
    if len(original) < 4 or len(original) % 4:
        raise IPAError("Hook must overwrite whole ARM64 instructions")
    instructions = list(disassembler.disasm(original, address))
    if len(instructions) != len(original) // 4:
        raise IPAError("Cannot decode all overwritten ARM64 instructions")
    for instruction in instructions:
        if instruction.mnemonic.lower() in ("adr", "adrp"):
            if (len(instruction.operands) < 2 or
                    instruction.operands[-1].type != constants.ARM64_OP_IMM or
                    not instruction.op_str.split(",")[0].strip().startswith("x")):
                raise IPAError("Unsupported ADR/ADRP operands")
        else:
            _copyable_stolen(disassembler, constants, instruction.bytes,
                             instruction.address)


def _relocate_stolen(disassembler, constants, assembler, original, address,
                     trampoline_address, original_binary, rebuilt_binary):
    """Relocate safe ARM64 instructions, including ADR and ADRP.

    A PC-relative destination must map into a known section after LIEF
    relayout. Other kinds (BL, literal load, conditional branch, PAC/BTI)
    are intentionally rejected rather than silently copied.
    """
    _validate_relocatable_stolen(disassembler, constants, original, address)
    relocated = bytearray()
    for instruction in disassembler.disasm(original, address):
        mnemonic = instruction.mnemonic.lower()
        if mnemonic not in ("adr", "adrp"):
            relocated.extend(instruction.bytes)
            continue
        destination = int(instruction.operands[-1].imm)
        section = original_binary.section_from_virtual_address(destination)
        if section is None or not section.segment_name:
            raise IPAError("Cannot remap ADR/ADRP target outside known section")
        new_section = rebuilt_binary.get_section(section.segment_name, section.name)
        if new_section is None:
            raise IPAError("ADR/ADRP destination section missing after rebuild")
        destination = int(new_section.virtual_address) + destination - int(section.virtual_address)
        register = instruction.op_str.split(",")[0].strip()
        pc = trampoline_address + len(relocated)
        if mnemonic == "adrp":
            script = "adrp %s, #0x%x" % (register, destination & ~0xfff)
            payload = _assemble(assembler, script, pc)
        elif -(1 << 20) <= destination - pc < (1 << 20):
            payload = _assemble(assembler, "adr %s, #0x%x" % (
                register, destination), pc)
        else:
            # ADR has +/-1MiB reach. ADRP+ADD preserves register semantics
            # without borrowing a scratch register and is PC/ASLR-relative.
            payload = _assemble(
                assembler,
                "adrp %s, #0x%x; add %s, %s, #0x%x" % (
                    register, destination & ~0xfff, register, register,
                    destination & 0xfff
                ), pc
            )
        relocated.extend(payload)
    return bytes(relocated)


def _verify_hook(source, hook, disassembler, constants):
    if "address" not in hook:
        raise IPAError("hook_arm64 requires address")
    addr = number(hook["address"])
    if addr % 4:
        raise IPAError("Hook address must be 4-byte aligned")
    expected = hexbytes(hook.get("expected_hex"))
    # Both before- and replace-hooks overwrite whole ARM64 instructions.  A
    # shorter replacement branch would otherwise grow/shrink the Mach-O bytes
    # through Python bytearray slice assignment.
    if len(expected) < 4 or len(expected) % 4:
        raise IPAError("Hook expected_hex must contain whole 4-byte ARM64 instructions")
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
        _validate_relocatable_stolen(disassembler, constants, expected, addr)
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



def _load_commands(data):
    """Read raw Mach-O load commands for post-rebuild integrity checks."""
    if len(data) < 32:
        raise IPAError("Truncated Mach-O header")
    magic, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from(
        "<IiiIIIII", data, 0
    )
    if magic != 0xFEEDFACF or ncmds > 4096 or 32 + sizeofcmds > len(data):
        raise IPAError("Invalid Mach-O header/load command table")
    commands = []
    cursor, end = 32, 32 + sizeofcmds
    for _ in range(ncmds):
        if cursor + 8 > end:
            raise IPAError("Truncated Mach-O load command")
        kind, size = struct.unpack_from("<II", data, cursor)
        if size < 8 or cursor + size > end or size % 8:
            raise IPAError("Malformed or unaligned Mach-O load command")
        commands.append((kind, data[cursor:cursor + size]))
        cursor += size
    if cursor != end:
        raise IPAError("Mach-O load command size mismatch")
    return commands


def validate_macho_integrity(original, rebuilt):
    """Verify critical load commands and LINKEDIT extents survived LIEF layout.

    This is a fail-closed structural check, NOT a proof of dyld compatibility.
    Real device testing is still necessary.
    """
    before, after = _load_commands(original), _load_commands(rebuilt)
    # dyld linking metadata, entrypoint, chained fixups and symbol indexes must
    # not silently disappear while inserting a new LC_SEGMENT_64.
    critical = {
        0x80000028,  # LC_MAIN
        0x22, 0x80000022,  # LC_DYLD_INFO and LC_DYLD_INFO_ONLY
        0x80000033, 0x80000034,  # EXPORTS_TRIE, CHAINED_FIXUPS
        0x26, 0x29,  # FUNCTION_STARTS, DATA_IN_CODE
        0x2, 0xB,  # SYMTAB, DYSYMTAB
        0xC, 0x18, 0x1F, 0x20,  # load family of dylibs
        0x8000001C,  # LC_RPATH
    }
    for kind in critical:
        old_count = sum(cmd == kind for cmd, _ in before)
        new_count = sum(cmd == kind for cmd, _ in after)
        if old_count != new_count:
            raise IPAError("Critical Mach-O command changed (0x%x): %d -> %d" %
                           (kind, old_count, new_count))
    file_size = len(rebuilt)
    # Most LINKEDIT data commands use uint32 dataoff/datasize at +8/+12.
    linkedit_data = {0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E,
                     0x80000033, 0x80000034}
    segments = []
    main = []
    for cmd, raw in after:
        if cmd in linkedit_data:
            if len(raw) < 16:
                raise IPAError("Truncated LINKEDIT data command")
            offset, size = struct.unpack_from("<II", raw, 8)
            if size and (offset > file_size or size > file_size - offset):
                raise IPAError("LINKEDIT data command outside Mach-O file")
        elif cmd == 0x19:
            if len(raw) < 72:
                raise IPAError("Truncated LC_SEGMENT_64")
            _, _, _, vmaddr, vmsize, fileoff, filesize, _, initprot, _, _ = (
                struct.unpack_from("<II16sQQQQiiII", raw, 0)
            )
            if fileoff > file_size or filesize > file_size - fileoff:
                raise IPAError("Mach-O segment outside rebuilt file")
            segments.append((vmaddr, vmsize, fileoff, filesize, initprot))
        elif cmd == 0x80000028:
            if len(raw) < 24:
                raise IPAError("Truncated LC_MAIN")
            main.append(struct.unpack_from("<Q", raw, 8)[0])
        elif cmd == 0x2:
            if len(raw) < 24:
                raise IPAError("Truncated LC_SYMTAB")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", raw, 8)
            if (symoff > file_size or nsyms * 16 > file_size - symoff
                    or stroff > file_size or strsize > file_size - stroff):
                raise IPAError("Mach-O symbol/string table outside file")
    ranges = sorted((start, start + size) for _, _, start, size, _ in segments if size)
    for previous, following in zip(ranges, ranges[1:]):
        if previous[1] > following[0]:
            raise IPAError("Overlapping Mach-O file-backed segments")
    for entryoff in main:
        if not any(fileoff <= entryoff < fileoff + filesize and prot & 4
                   for _, _, fileoff, filesize, prot in segments):
            raise IPAError("LC_MAIN entry point is not in executable file-backed segment")
    return {"segments": len(segments), "linkedit_checked": True,
            "main_entrypoints": len(main)}

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
    # LIEF can shift __TEXT's virtual addresses when expanding load commands.
    # Record every hook relative to its original named section, not as a fixed
    # virtual address, so detours and return branches target the rebuilt image.
    original_sections = {}
    for index, (old_addr, _, _) in verified_hooks.items():
        section = binary.section_from_virtual_address(old_addr)
        if section is None or not section.name or not section.segment_name:
            raise IPAError("Cannot identify the source section for hook 0x%x" % old_addr)
        if old_addr >= section.virtual_address + section.size:
            raise IPAError("Hook is outside the recognized Mach-O section")
        original_sections[index] = (
            section.segment_name, section.name, old_addr - section.virtual_address
        )
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
        validate_macho_integrity(data, raw)
        selected = arm64_slice(raw)
        rebuilt = lief.MachO.parse(str(intermediate))
        if rebuilt is None or rebuilt.size != 1:
            raise IPAError("Expanded Mach-O cannot be reparsed by LIEF")
        rebuilt_binary = rebuilt.at(0)
        new_segment = rebuilt_binary.get_segment(SEGMENT)
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
                seg_name, section_name, delta = original_sections[index]
                relocated = rebuilt_binary.get_section(seg_name, section_name)
                if relocated is None or delta + len(stolen) > relocated.size:
                    raise IPAError("Source code section disappeared during Mach-O rebuild")
                current_addr = int(relocated.virtual_address) + delta
                if mode == "before":
                    body = _assemble(assembler, item["asm"], address)
                    replay = _relocate_stolen(
                        disassembler, constants, assembler, stolen, old_addr,
                        address + len(body), binary, rebuilt_binary
                    )
                    payload = body + replay
                    payload += _branch(address + len(payload), current_addr + len(stolen))
                    pending.append((current_addr, stolen, address))
                else:
                    payload = b""
                    pending.append((current_addr, stolen, item["symbol"]))
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
        validate_macho_integrity(data, raw)
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
