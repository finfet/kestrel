<p><img src="https://user-images.githubusercontent.com/13957897/149721971-bdd844e6-0a9d-43fa-9205-04a8daa9fab6.png" alt="Kestrel Logo" width="600"></p>

**File encryption done right**

## About

Kestrel is a data-at-rest file encryption program that lets you encrypt files
to anyone with a public key.


## Features and Advantages

- Encrypt files using a public key or a password.
- Strong security and privacy guarantees. Uses X25519, ChaCha20-Poly1305
  and the Noise Protocol. Guarantees sender authentication.
- Secure defaults with zero configuration needed.
- Supports files of any size.
- Keys are simple strings that are easy to manage and copy-paste.
- Private keys are always encrypted.
- Single binary that is easy to run anywhere.
- Supports Linux, macOS, Windows.


## Disadvantages

- Does not handle signatures. You can't sign files with this. However,
  sender authentication is guaranteed.
- Does not solve the key distribution problem. You have to acquire
  known-good public keys through some other means.


## Security Properties

- **Sender authentication**: When you successfully decrypt a file, you can be
  certain that it came from someone that you know and that it hasn't been
  tampered with in any way.
- **Metadata protection**: Encrypted files contain absolutely zero information
  about the sender or recipient.
- **Deniability**: Unlike using a digital signature for authentication, Kestrel
  provides sender authentication without non-repudiation. You are not
  cryptographically bound to the messages that you send. If the recipient tries
  to reveal a message, you are able to deny that you sent that message.
- **Partial forward secrecy**: An attacker must compromise the _recipient's_
  private key in order to decrypt a file. Someone else getting their private
  key compromised doesn't affect the files that they had previously sent to you.

Kestrel uses a combination of the Noise Protocol and a chunked file encryption
scheme. Read the [security documentation](https://getkestrel.com/docs/security-information.html)
for more details.


## Advantages compared to other applications

**GPG**

GPG is a massively complex tool with many use cases, features, and shortcomings.
In general, Kestrel provides better default security guarantees with no
configuration required. In particular, by default, GPG does not provide sender
authentication or metadata protection. Sender authentication can be
added by including signatures, but this removes deniability. In contrast,
Kestrel includes sender authentication while preserving deniability and
protecting metadata.

**age**

age is a newer tool with strong defaults and is a great choice in comparison
to GPG. However, age does not provide sender authentication. A successfully
decrypted file could have come from anyone, including a malicious user.
Mitigating this would require keeping track of file hashes out of band.
Kestrel solves this issue by providing sender authentication.

## Installation

Tested on Linux, macOS, Windows 10

Download from the [Official Site](https://getkestrel.com)

Or grab the [GitHub release](https://github.com/finfet/kestrel/releases/latest)

If you have cargo you can also use `cargo install kestrel-cli`


## Usage Examples

Generate a new private key
```
$ kestrel key gen -o keyring.txt
Key name: alice
New password:
Confirm password:
```

Encrypt a file
```
$ kestrel encrypt example.txt --to alice --from alice -k keyring.txt
```

Decrypt a file
```
$ kestrel decrypt example.txt.ktl -t alice -k keyring.txt
```

Encrypt a file using a password
```
$ kestrel pass enc example.txt
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


## Security Warning

To the best of my knowledge, Kestrel is secure. However, this software has
not yet undergone a formal security audit. Swim at your own risk.
