# Keymaster Hardware Test

A small Android diagnostic app for checking whether Android Keystore is using hardware-backed
secure storage. It requests no permissions.

The app generates an RSA 2048-bit key in `AndroidKeyStore`, signs and verifies a payload with
it, then reports a verdict. The test key is deleted when the test finishes, so no key material
is left on the device.

## Output

| Verdict | Meaning |
| --- | --- |
| `✅ KEYSTORE REPORTS HARDWARE BACKING` | Key generated, signed and verified; Android reports it as hardware-backed |
| `❌ KEYSTORE REPORTS SOFTWARE KEYS` | The same, but the key is not hardware-backed |
| `❌ KEYSTORE MALFUNCTIONING` | Key generated, but the sign/verify round trip failed |
| `❌ TEST FAILED` | The probe threw, for example no Keystore or a provider error |

Alongside the verdict it shows the sign/verify result, the key's security level (StrongBox,
Trusted Environment, or Software), whether the key reports as inside secure hardware, its
origin, and its size.

## What this does not prove

**A green verdict is not a security assessment.** It means the Keystore works and reports
hardware backing, not that the device is trustworthy.

- **Provisioning is not checked.** A device with a blank or erased keybox, common after
  reflashing or a restore, still generates keys, signs, and reports hardware backing, because
  the Keymaster HAL is running. It just derives its master key from a default value, so those
  keys are not protected by a device-unique secret.
- **Verified boot is a separate trust domain.** `ro.boot.verifiedbootstate=green` says nothing
  about Keymaster provisioning.
- **`isInsideSecureHardware()` is deprecated** as of Android 12 and can report `false` on builds
  that do have a Trusted Environment. Android 12+ uses `getSecurityLevel()`; older releases can
  produce a false negative.
- **Keymaster backing says nothing about FDE/FBE** (full-disk encryption).

The only test that separates a provisioned Keystore from an unprovisioned one is **key
attestation**, which binds the Root of Trust to Google's certificate authority. An unprovisioned
Keymaster cannot produce a valid chain. This app does not perform attestation.

## Why?

Useful when diagnosing a device where hardware-backed Keystore or Qualcomm Keymaster may be
malfunctioning. It distinguishes between:

- a Keystore that generates keys and signs correctly
- a software-backed Keystore
- a Keystore that generates keys but fails to sign
- a Keystore that cannot generate keys at all

## Requirements

- Android 6.0 (API 23) or newer
- No root required

## Building

See [COMPILING.md](COMPILING.md).

## License

MIT. See [LICENSE](LICENSE).
