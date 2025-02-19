# Changelog

## Version 3.0.0

Date: 2025-02-18

- Removed extraneous file decrypt methods
- Improved zeroize handling for keys
- Improved error handling
- Switch to the orion cryptography library, dramatically reducing the number
  of required dependencies
- Fixed scrypt key length output. The previous implementation was fixed
  at 32 bytes

## Version 2.0.2

Date: 2024-07-07

- Upgrade dependencies

## Version 2.0.1

Date: 2024-05-13

- Performance improvement for buffer copy during encrypt chunks

## Version 2.0.0

Date: 2024-05-13

- Require public keys in API surface in order to remove an internal
  x25519 operation.

## Version 1.0.1

Date: 2024-02-01

- Removed extraneous wasm feature. Use the js feature of your getrandom
  dependency for wasm support.

## Version 1.0.0

Date: 2023-12-28

- Added function for decryption to a specified path

## Version 0.11.0

- Add HKDF-SHA256 API
- Derive a symmetric key from the payload key and noise handshake hash set
  as the info parameter to hkdf-sha256

## Version 0.10.1

- Upgrade dependencies

## Version 0.10.0

- Add ability to build on wasm32-unknown-unknown
- Upated cryptography APIs

## Version 0.9.0

- Initial Release
