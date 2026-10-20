# IPA patching (experimental)

The IPA tool is a **separate Python 3 CLI**. The original ELF ./patch command
and its Python 2 dependencies are unchanged.

## What works

- Safely unpack and rebuild a Payload/*.app IPA (including safe symlinks).
- Locate the main executable using CFBundleExecutable.
- Apply **fixed-size** byte patches to ARM64/ARM64e thin or FAT Mach-O binaries
  using slice-relative offsets or segment-mapped virtual addresses.
- Verify the exact original bytes before changing the executable.
- Assemble fixed-size ARM64 replacements with optional Keystone.
- **Experimental**: use LIEF to grow a *thin arm64* Mach-O with a new RX
  `__PKTEXT` segment, inject ARM64 assembly, and install verified
  direct-branch function detours with optional return trampolines.
- Replace bytes in existing bundle resources or replace existing resource files.
- Auto-select inline ARM64 replacement or out-of-line injection with
  `auto_patch_arm64` when the new ASM outgrows the original instruction region.
- Target the executable inside an embedded framework or app extension by using
  `"target": "Frameworks/Foo.framework/Foo"` or `"target": "PlugIns/Bar.appex/Bar"`.
- Optionally re-sign on macOS with codesign, supplying your own signing identity,
  entitlements and provisioning profile. Original per-bundle entitlements are
  captured before rewriting and preserved when nested bundles are signed.
  Any embedded profiles are checked against the signed bundle identifiers,
  entitlements and profile expiration dates.

**Not supported:** arbitrary reflow/resizing of existing __TEXT instructions,
relocating arbitrary PC-relative stolen instructions (ADR/ADRP, in-range
LDR/LDRSW literals, and external B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ branches
in mapped sections are supported), automatic branch islands for 4-byte hook
sites beyond +/-128MiB, FAT/universal or
arm64e automatic hooks, pointer authentication and
BTI handling, Swift symbol resolution, FairPlay decryption, App Store IPA DRM,
on-device hotpatching or bypassing signing rules. Thin arm64 segment growth is
implemented, but still requires device-level testing for production readiness.

**Signing is mandatory for installation.** An unsigned/unre-signed artifact is
intended solely for inspection or an external authorized signing pipeline.
A modified IPA is not guaranteed to be accepted by iOS or App Store distribution.

## Requirements

- Python 3.9+ standard library for hex/resource patches.
- Optional: pip install keystone-engine for the arm64_asm operation.
- For inject/hook/growth: `pip install 'lief>=0.17,<2' keystone-engine 'capstone>=5,<6'`.
  On macOS, if Keystone cannot load libkeystone.dylib from pip, install
  `brew install keystone` and ensure the dylib is visible to the Python binding.
- macOS with codesign and an appropriate Apple signing certificate/profile
  for the --sign-identity option (not available on Linux).
- The original, unencrypted IPA, with authorization to modify and re-sign it.

## Example manifest

Save as patches.json. To pin the exact input release, you may add an optional
top-level `"input_sha256": "<64 hex characters>"` next to `"operations"`;
the tool refuses to patch a different IPA (recommended for release automation).


    {
      "operations": [
        {
          "type": "patch_address",
          "target": "executable",
          "arch": "arm64",
          "address": "0x100001000",
          "expected_hex": "1f2003d5",
          "new_hex": "1f2003d5"
        },
        {
          "type": "patch_offset",
          "target": "executable",
          "arch": "arm64",
          "offset": "0x1000",
          "expected_hex": "1f2003d5",
          "new_hex": "1f2003d5"
        },
        {
          "type": "arm64_asm",
          "target": "executable",
          "arch": "arm64",
          "address": "0x100001000",
          "expected_hex": "1f2003d5",
          "asm": "nop"
        },
        {
          "type": "replace_bytes",
          "target": "config.json",
          "old_hex": "74657374",
          "new_hex": "64656d6f",
          "occurrences": 1
        },
        {
          "type": "replace_file",
          "target": "Assets/settings.json",
          "source": "my-settings.json"
        }
      ]
    }

This example illustrates the schema, **not a sequence to run as-is**: three
operations target the same instruction. Use only the operation(s) you actually
intend and the original bytes/addresses from your own IPA.

- target is "executable" or a path relative to the top-level .app bundle.
- offset is relative to the selected Mach-O architecture slice, **not** to
  the outer IPA ZIP and not necessarily to the start of a FAT file.
- address is a VM address mapped using LC_SEGMENT_64; ASLR runtime slide is
  **not** included. Look up file image addresses, not live addresses.
- expected_hex is required for direct code edits and must match exactly.
- new_hex must be the same length as expected_hex.
- arm64_asm must assemble to exactly the expected byte length; this tool does
  not relocate or preserve overwritten instructions.
- replace_bytes searches in a single target file, requires exactly
  occurrences matches (defaults to 1), and preserves byte length.
- replace_file replaces an existing file; source paths are relative to the
  manifest file location.
- When input_sha256 is supplied, the original entire IPA ZIP is SHA256-checked
  before unpacking.
- Place all `extend_macho`, `inject_arm64` and `hook_arm64` operations at the
  end of the manifest; other operations run first, and structural operations
  share one new RX segment.
- Multiple operations run in manifest order and fail immediately on mismatch.
  The original IPA is not changed. The output is committed atomically only
  after patching/signing succeeds.

## Run

On Linux (inspection only, output cannot be installed as-is):

    python3 ipa_patch.py original.ipa patches.json \
      -o patched-unresigned.ipa --allow-unsigned

To validate a patch and Mach-O layout **without writing or signing an IPA**:

    python3 ipa_patch.py original.ipa patches.json --dry-run

On macOS (use the correct certificate, entitlements and profile for the app):

    python3 ipa_patch.py original.ipa patches.json \
      -o patched-signed.ipa \
      --sign-identity "Apple Development: Your Name (TEAMID)" \
      --entitlements app.entitlements --profile dev.mobileprovision \
      --require-profiles

For applications containing extensions or frameworks, the tool signs embedded
binaries/bundles inside-out, restores each originally signed bundle's original
entitlements (unless an explicit root --entitlements file is provided), then
signs the top-level application and calls codesign --verify. Existing nested
embedded.mobileprovision files remain within the bundle; --profile replaces
only the top-level application's profile. Passing codesign verification does **not** guarantee the
entitlements, provisioning profile, bundle IDs, and distribution method are
compatible with a target device. Verify installation and launch on a real
device with the intended distribution channel.

## Provisioning profile checks (macOS signing)

During `--sign-identity`, PatchKit reads the **actual signed entitlements**
from every app/extension containing `embedded.mobileprovision`, decodes the
profile CMS via macOS `security cms -D`, and checks:

- Profile expiration date, TeamIdentifier, and exact signed bundle ID/team
  combination (including Apple's terminal-wildcard profile App ID support).
- Whether the profile grants requested application IDs, keychain groups,
  app groups, push environment and other known provisioning-bound entitlements.
- Whether an explicit `--profile` has a profile for every nested
  `.app`/`.appex` as well. Each extension requires **its own appropriate**
  provisioning profile; reusing the main app's profile is not sufficient.

Use `--require-profiles` on signed release candidates to fail when any app
or extension is missing an embedded provisioning profile. Without this flag,
an existing embedded profile is still validated, but unsigned test fixtures
without profiles remain supported.

**Important:** These checks are compatibility checks, **not** Apple's CMS
certificate-chain verification, revocation checking, signing identity-to-team
certificate verification, UDID eligibility testing or proof of actual iOS
installation. `security cms -D` decodes the CMS payload; `codesign --verify`
checks code signatures. Installation must still be tested on an authorized
physical iPhone with the intended Apple provisioning and distribution method.

The patcher rejects known provisioning conflicts rather than silently changing
protected signed entitlements. It cannot automatically issue an Apple
Development/Distribution certificate or generate new team-specific profiles.

For more detail on legacy ELF patching, see ../README.md.

## Safety / testing

Run the deterministic synthetic-fixture tests:

    python3 -m unittest discover -s tests -v

Encrypted Mach-O slices are rejected. The IPA extractor rejects absolute/parent-traversal paths, duplicate members,
unsafe symlinks, special device files and excessive advertised uncompressed
size (default 2048 MiB; override with --max-unpacked-mib). Never patch encrypted
binaries. Patch instructions only at verified addresses and test independently
per iOS device architecture / OS version.

The legacy ELF engine uses Python 2; do not run it through this new CLI.


## ARM64 code injection and automatic function hooks (experimental)

All structural operations are grouped at the **end** of the manifest, for
example:

```json
{
  "operations": [
    {
      "type": "extend_macho",
      "size": 16384
    },
    {
      "type": "inject_arm64",
      "name": "replacement",
      "asm": "mov x0, #7; ret"
    },
    {
      "type": "hook_arm64",
      "mode": "replace",
      "address": "0x100003000",
      "expected_hex": "1f2003d5",
      "symbol": "replacement"
    }
  ]
}
```

This is a **schema example only**. Use the address/expected bytes from your
own unencrypted Mach-O. The source executable must be a **thin arm64** binary;
the tool intentionally refuses automatic hook/expansion on FAT, arm64e, PAC
and unknown relocation cases. `extend_macho` grows the executable by creating
new file-backed RX space, rather than shifting existing code. Each new Mach-O
starts with an empty reserved `__PKTEXT` segment and LIEF updates its layout.
The new segment is read+execute, **not** writable+executable.

For an inline hook that resumes the original function after the overwritten
instruction(s), use:

```json
{
  "type": "hook_arm64",
  "mode": "before",
  "address": "0x100003000",
  "expected_hex": "1f2003d5",
  "asm": "nop"
}
```

In `before` mode, the generated detour runs your injected instructions,
replays the original complete instructions that were replaced, and branches
back to the next original address. This is only supported when those original
instructions are position-independent **or** are supported ADR/ADRP, LDR/LDRSW
literal and external branch references whose destination can be remapped into
an existing Mach-O section. External B/BL, B.cond, CBZ/CBNZ and TBZ/TBNZ
retain their original branch condition/register tests, and are re-encoded
only while their specific immediate remains in range. Branches into stolen
instructions are refused. LDR/LDRSW literals must remain within +/-1MiB;
BTI, PAC/AUT and unimplemented PC-relative instructions remain refused.
ADR may expand from one to two instructions in the trampoline when necessary. The manifest author is
responsible for ABI correctness: custom assembly must preserve any register,
flags, link register, and stack state used by the interrupted function. In
`replace` mode, the hook branches to the named injected function instead of
executing the original. Injected replacement functions must implement the
appropriate ABI and return/branch behavior themselves.

Detours prefer the register-free ARM64 `B` instruction (4-byte overwrite)
within **+/-128 MiB**. For farther destinations, an explicit opt-in can use
`ADRP x16 + ADD x16 + BR x16` (12-byte overwrite), provided that the original
code region supplies at least 12 verified bytes and ADRP's +/-4GiB reach
is sufficient. This variant intentionally clobbers scratch register x16, so
it can change program behavior if the intercepted function depends on x16.
Never enable it without auditing the interrupted ABI/register state.
The CLI reports the new segment base,
symbol addresses, capacity, and the number of hooks applied. These addresses
are unslid Mach-O VM addresses (not runtime ASLR addresses).

**Critical limitation:** passing structural tests or `codesign --verify`
does not prove that a patched iOS app will launch successfully. Modern iOS
may enforce additional loader, branch protection, entitlements or runtime
constraints. Validate installation and functionality on an authorized test
device before treating an output as distributable.

### CI validation

The test workflow runs fast synthetic IPA checks on Linux and macOS.
On macOS it also builds a minimal arm64 Mach-O executable, inserts an RX
segment, injects code and **executes** patched binaries, including long-range
opt-in branches, PC-relative LDR literal relocation, and external conditional
branches (B.cond, CBZ/CBNZ, TBZ/TBNZ). Tests do not install
the patched IPA on iPhone.


## Automatic patch expansion

The `auto_patch_arm64` operation accepts the original address, exact original
bytes, and a replacement assembly block:

```json
{
  "operations": [
    {
      "type": "auto_patch_arm64",
      "address": "0x100003000",
      "expected_hex": "1f2003d5",
      "asm": "nop; nop; ret"
    }
  ]
}
```

If the generated assembly fits within `expected_hex`, the tool writes an
in-place replacement and pads the remainder with ARM64 NOP. Otherwise, it
automatically emits an `inject_arm64` operation into RX `__PKTEXT` and uses
a `replace` hook at the original address. This is a replacement, **not** a
wrapper around the original function: the manifest author is responsible for
return behavior and ABI. All structural operations must appear after ordinary
patches. The operation is currently supported on regular ARM64 only.

Set `"target"` to select another Mach-O binary inside the IPA, e.g. an
embedded framework/extension executable. Each target gets its own expansion
segment. Nested signed bundles are signed again from the inside out, preserving
their previously encoded entitlements.

## Structural verification and actual execution

After writing the IPA, PatchKit reads every generated ZIP entry again,
checks member identity, original vs packed SHA-256 and symlink targets before
atomically replacing the output path. Hooks must target Mach-O sections marked S_ATTR_PURE_INSTRUCTIONS or
S_ATTR_SOME_INSTRUCTIONS, not data or strings inside a segment with RX
protection. The code-expansion pipeline also checks
that critical load commands remain present, LINKEDIT tables fall within the output file, file-backed segments do
not overlap, and LC_MAIN points to an executable segment. This guards against
some LIEF relayout failures; it does not prove that dyld chained-fixup payloads
and pointer relocations remain semantically correct.

The macOS CI suite **executes** patched ARM64 Mach-O programs after
ad-hoc codesign (in addition to checking disassembly, injected segment layout,
hook return branches, and nested entitlements). CI also cross-builds a real
iPhoneOS SDK ARM64 **MH_EXECUTE** (rather than a dylib standing in for an
executable), performs injection/hooking, confirms its
LC_BUILD_VERSION / deployment target load commands survive LIEF relayout, and
verifies ad-hoc codesign. The iOS binary cannot be executed by macOS CI.
Neither these tests nor codesign verification prove actual iPhone installation,
dyld execution, App Store eligibility, iOS arm64e support, or compatibility with
a real provisioning profile.

Use only IPA files you own or are authorized to modify. The patcher does not
remove FairPlay encryption or bypass iOS code-signing requirements.

For manual testing on an authorized paired iPhone, see
[On-device IPA smoke test](IPA_DEVICE_VALIDATION.md). The opt-in helper first
verifies the signature, then uses Xcode devicectl to install and request launch.
CI tests its failure handling but cannot attest to iPhone runtime behavior.


### Explicit long-range branch mode

A hook or `auto_patch_arm64` instruction can declare `"long_branch": "x16"`:

```json
{
  "type": "hook_arm64",
  "mode": "replace",
  "address": "0x100003000",
  "expected_hex": "1f2003d5000080d2c0035fd6",
  "symbol": "replacement",
  "long_branch": "x16"
}
```

If a direct B is within reach, the tool still uses B and NOP-pads the
verified overwritten region. If B is out of reach, it uses ADRP/ADD/BR x16,
which computes the destination relative to the executable's current PC page
and remains valid under ASLR. The tool never embeds an unslid absolute
function pointer. If the verified original region is under 12 bytes or the
target exceeds ADRP's signed page range, patching fails without an output.

This is an advanced opt-in specifically because clobbering x16 may invalidate
the code's expected register state. In `before` mode the same opt-in applies
to both detour and trampoline return. Be especially cautious with compiler
generated stubs and pointer-authenticated iOS call sequences.
