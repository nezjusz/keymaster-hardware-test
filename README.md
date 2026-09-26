# Keymaster Hardware Test

A small Android diagnostic app for checking whether Android Keystore is using hardware-backed secure storage.

The app generates an RSA 2048-bit key using `AndroidKeyStore` and reports:

- whether the key was generated successfully
- whether the key is stored inside secure hardware
- the key origin
- the key size

## Why?

This tool is useful when diagnosing Android devices where hardware-backed Keystore or Qualcomm Keymaster may be malfunctioning.

It can help distinguish between:

- a working hardware-backed Keystore
- software-backed Keystore
- failures during key generation

### Important

This app **does not perform Key Attestation** and does not attempt to verify the integrity of the device's Trusted Execution Environment.

`Inside Secure Hardware: true` confirms that the generated key is reported by Android as being protected by secure hardware. It does **not** by itself prove that a device's FDE/FBE encryption key is hardware-backed.

## Requirements

- Android 6.0 (API 23) or newer
- Android Keystore
- No root required

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

## Disclaimer

This is a diagnostic tool, not a security certification or a complete assessment of a device's security architecture.