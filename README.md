<p><img src="https://user-images.githubusercontent.com/13957897/147846912-5bca7cd7-c3f5-4822-afeb-70a3e1baa556.png" alt="Kestrel Logo" width="600"></p>

**File encryption done right**

## About

Kestrel is a data-at-rest file encryption program that lets you encrypt files
to anyone with a public key.


## Features and Advantages

- Encrypt files using a public key or password.
- Strong security and privacy guarantees. Uses X25519, ChaCha20-Poly1305
  and the Noise Protocol. Guarantees sender authentication.
- Handles files of any size.
- Keys are simple strings that are easy to manage and copy-paste.
- Private keys are always encrypted.
- Single binary that is easy to run anywhere.
- Supports Linux, macOS, Windows.


## Disadvantages

- Does not handle signatures. You can't sign files with this. However,
  sender authentication is guaranteed.
- Does not solve the key distribution problem. You have to acquire
  known-good public keys through some other means.


## Installation

Tested on Linux, macOS, Windows 10

Download from the [Official Site](https://getkestrel.com)

Or grab the [GitHub release](https://github.com/finfet/kestrel/releases/latest)

If you have cargo you can also use `cargo install kestrel-cli`


## Usage Examples

Generate a new private key
```
kestrel key gen -o keyring.txt
```

Encrypt a file
```
kestrel encrypt example.txt --to alice --from alice -k keyring.txt
```

Decrypt a file
```
kestrel decrypt example.txt.ktl -t alice -k keyring.txt
```

Encrypt a file using a password
```
kestrel pass enc example.txt
```

Set the environment variable `KESTREL_KEYRING` to use a default keyring file.

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

## Documentation

View the [documentation](https://getkestrel.com/docs/)

Source code for the documentation can be found in the
[kestrel-doc](https://github.com/finfet/kestrel-doc) repository.


## Contributing

Patches welcome. Please send feedback and bug reports for any issues that
you may have.


## License

BSD 3 Clause


## Security Design Overview

Kestrel uses a standard combination of the Noise Protocol and a
chunked file encryption scheme.

The noise protocol (Noise_X_25519_ChaChaPoly_SHA256) is used to encrypt a
payload key. This payload key is then used for ChaCha20-Poly1305 file
encryption. Files are split into encrypted and authenticated chunks.

Users can also use a password instead of public keys. Scrypt is to derive a
symmetric key for file encryption.

See more in the [security documentation](https://getkestrel.com/docs/security-information.html)

## Security Warning

To the best of my knowledge, Kestrel is secure. However, this software has
not yet undergone a formal security audit. Swim at your own risk.
