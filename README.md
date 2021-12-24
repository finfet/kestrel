# Kestrel

Modern, secure, and easy to use file encryption.

## About

Kestrel is a data-at-rest file encryption program. Think PGP, but less unwieldy.

Kestrel makes it easy to encrypt files for yourself or friends.

## Features and Advantages

- Encrypt files to anyone. Grab their public key or use a password.
- Quickly encrypt and decrypt files of any size.
- Strong security and privacy guarantees. Uses X25519, ChaCha20-Poly1305
  and the Noise Protocol. Guarantees sender authentication.
- Keys are simple strings that are easy to manage and copy-paste.
- Private keys are always encrypted.
- Single binary that is easy to run anywhere.
- Supports Linux, macOS, Windows.
- BSDs will also likely work but are untested.

## Disadvantages

- Does not handle signatures. You can't sign files with this. However,
  sender authentication is guaranteed.
- Does not solve the key distribution problem. You have to acquire known-good
  public keys through some other means.

## Installation

```
cargo install kestrel-cli
```

## Contributing

Patches welcome. Please send feedback and bug reports for any issues that
you may have.

## License

BSD 3 Clause

## Usage

```
USAGE:
    kestrel encrypt FILE -t NAME -f NAME [-o FILE] [-k KEYRING]
    kestrel decrypt FILE -t NAME [-o FILE] [-k KEYRING]
    kestrel key generate -o FILE
    kestrel key change-pass PRIVATE-KEY
    kestrel key extract-pub PRIVATE-KEY
    kestrel password encrypt|decrypt FILE [-o FILE]

    Aliases enc, dec, pass, and gen can be used as encrypt, decrypt,
    password, and generate respectively.
    Option -k is required unless KESTREL_KEYRING env var is set.

OPTIONS:
    -t, --to        Recipient key name. Decrypt requires a private key.
    -f, --from      Sender key name. Must be a private key.
    -o, --output    Output file name.
    -k, --keyring   Location of a keyring file.
    -h, --help      Print help information.
    -v, --version   Print version information.
```

## Security Design Overview

The application uses a standard combination of the Noise Protocol and a
chunked file encryption scheme.

The noise protocol (Noise_X_25519_ChaChaPoly_SHA256) is used to encrypt a
payload key that is then used for ChaCha20-Poly1305 file encryption. Files are
split into encrypted and authenticated chunks.

Users can also use a password instead of public keys. Scrypt is to derive a
symmetric key for file encryption.

See more in the [security-notes](docs/security-notes.md)

## Security Warning

To the best of my knowledge, Kestrel is secure. However, this software has not
yet undergone a formal security audit. Swim at your own risk.
