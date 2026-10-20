# On-device IPA smoke test (Mac + authorized iPhone)

This is the final **manual/device** checkpoint after Linux/macOS tests,
iPhoneOS SDK cross-build checks and Apple codesign. Passing those CI checks
does not establish that an IPA installs, launches or works on an iPhone.

## Prerequisites

- A properly signed IPA you own or are authorized to modify.
- A Mac with Xcode and a paired, trusted iPhone.
- A suitable Apple provisioning profile, matching entitlements and an
  eligible device registration for development/ad-hoc distribution.
- Device unlocked, Developer Mode enabled when required.

For profile-complete release candidates use:

```sh
python3 ipa_patch.py input.ipa patches.json \
  -o signed-output.ipa \
  --sign-identity "Apple Development: ..." \
  --profile app.mobileprovision \
  --require-profiles
```

Each app extension needs its own matching embedded profile. The profile checks
are compatibility checks, not certificate chain or device registration proof.

## Procedure

Find the paired device:

```sh
xcrun devicectl list devices
```

Preview without installation:

```sh
python3 tools/ipa_device_smoke.py signed-output.ipa --device "<DEVICE_UDID>"
```

Explicitly opt in to installing and requesting launch:

```sh
python3 tools/ipa_device_smoke.py signed-output.ipa \
  --device "<DEVICE_UDID>" --execute \
  --report device-smoke-result.json
```

The tool extracts the IPA, verifies the app code signature with
`codesign --verify --deep --strict`, installs with `xcrun devicectl
device install app` and launches with `xcrun devicectl device process
launch`. It stops on the first failed step.

The JSON report includes the device identifier, commands and command output;
review/redact it before sharing. Successful execution means only
`INSTALL_AND_LAUNCH_ACCEPTED`, **not** that the patch works, that runtime is
stable, or that all extension entitlements have been honored.

## Manual checks after launch

1. Confirm the app installs with the intended bundle ID/team and opens.
2. Invoke the patched feature and verify the result against an unmodified
   control build.
3. Keep the app running, then background/foreground it and retry.
4. Exercise app extensions, bundled frameworks and capabilities affected by
   the patch.
5. Inspect crash logs in Xcode Devices and Simulators or macOS Console.
6. Repeat on intended iOS versions/devices, especially where PAC/arm64e is
   used by the original software.

The helper is currently unit-tested with mocked device commands; no physical
iPhone was connected for this development cycle. It cannot decrypt FairPlay,
bypass code signing or turn an unsigned IPA into an installable app.
