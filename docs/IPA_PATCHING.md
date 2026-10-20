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
- Replace bytes in existing bundle resources or replace existing resource files.
- Optionally re-sign on macOS with codesign, supplying your own signing identity,
  entitlements and provisioning profile.

**Not supported:** automatic code injection, function hooks/trampolines, resizing
Mach-O segments, relocations, pointer-authentication-aware patching, FairPlay
decryption, App Store IPA DRM, on-device hotpatching or bypassing signing rules.

**Signing is mandatory for installation.** An unsigned/unre-signed artifact is
intended solely for inspection or an external authorized signing pipeline.
A modified IPA is not guaranteed to be accepted by iOS or App Store distribution.

## Requirements

- Python 3.9+ standard library for hex/resource patches.
- Optional: pip install keystone-engine for the arm64_asm operation.
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
- Multiple operations run in manifest order and fail immediately on mismatch.
  The original IPA is not changed. The output is committed atomically only
  after patching/signing succeeds.

## Run

On Linux (inspection only, output cannot be installed as-is):

    python3 ipa_patch.py original.ipa patches.json \
      -o patched-unresigned.ipa --allow-unsigned

On macOS (use the correct certificate, entitlements and profile for the app):

    python3 ipa_patch.py original.ipa patches.json \
      -o patched-signed.ipa \
      --sign-identity "Apple Development: Your Name (TEAMID)" \
      --entitlements app.entitlements --profile dev.mobileprovision

For applications containing extensions or frameworks, the tool signs embedded
binaries/bundles inside-out, then the top-level application, and calls
codesign --verify. Passing codesign verification does **not** guarantee the
entitlements, provisioning profile, bundle IDs, and distribution method are
compatible with a target device. Verify installation and launch on a real
device with the intended distribution channel.

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
