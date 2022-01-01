# Security Information

## Overview

The application uses a standard combination of the Noise Protocol and a
chunked file encryption scheme.

The noise protocol (Noise_X_25519_ChaChaPoly_SHA256) is used to encrypt a
payload key that is then used for ChaCha20-Poly1305 file encryption. Files
are split into encrypted and authenticated chunks.

Users can also use a password instead of public keys. This password is used
with scrypt to derive a symmetric key for file encryption.

## Public Key Based Encryption

The X pattern of a noise protocol handshake is used to perform public key
authenticated encryption between sender and recipient.

Senders are required to obtain the public key of their recipient before they
can send a message. Tweet out your public key, send a letter, or meet in
person. Whatever works. Just make sure that your contacts can obtain a
legitimate copy of your public key.

**Encryption**

1. A fresh 256 bit symmetric key is generated from a CSPRNG. This is the
   payload key.
2. A noise handshake is performed between the sender and recipient with the
   payload key included as the noise payload. The result is a noise handshake
   message that includes the encrypted payload key and encrypted sender public
   key.
3. The plaintext is encrypted using the payload key and the chunked encryption
   format.

**Decryption**

1. The recipient must choose to decrypt using the key that the sender chose as
   the recipient. Because the ciphertext contains no identifying information
   from either the sender or recipient, the recipient must choose the right key
   pair from which to attempt decryption. If the recipient has, for example,
   a work key pair, and a personal key pair, the recipient must know to decrypt
   with either the work key or the personal key. Obviously decryption could be
   attempted with both keys if the recipient is unsure.
2. The recipient decrypts the noise handshake message. If successful, this
   results in the payload key and the sender's public key.
3. The ciphertext is decrypted using the payload key and the chunked
   encryption format.

### Chunked Encryption

Files can be dozens of gigabytes in size and don't fit into memory. So they are
split into encrypted and authenticated chunks. Each chunk has a chunk number
starting from zero and incrementing sequentially. The chunk number is also
used as the nonce for the encryption function. Chunks are 64k in size. The last
chunk has a last chunk indicator signifying that it is the last chunk in the
message. The chunks in a message CANNOT be re-ordered, modified, removed,
duplicated, or truncated. In order to achieve this the chunk number must
increase sequentially (0, 1, 2, 3, …) and must contain only a single last
chunk indicator.

### Security Properties

**Overview**

- When you receive a file, you know that the file hasn't been modified
  and that it came from a specific known public key.
- If your private key gets compromised later, the attacker can't read the
  messages that you've sent. The only way to decrypt the messages is to
  compromise your recipient's private key.
- If your private key gets compromised, the attacker can pretend to be you.
  You need to get a new key pair and be able to communicate the new public key
  to your contacts.
- Messages can be replayed. Replay prevention is out of scope for this
  application. However, replay is considered benign in this context. Imagine
  sending your encrypted tax files to an accountant. The attacker can resend
  your encrypted file to the accountant, but the accountant will end up with a
  benign, redundant copy.
- The encryption is meant to work as you would expect it to. If you get a file,
  you know who it came from, and that it hasn't been read or tampered with.
  When you send a file, only the person that you sent it to can read it.

**Guarantees from the noise protocol**

Each payload is assigned a "source" property regarding the degree of
authentication of the sender provided to the recipient, and a "destination"
property regarding the degree of confidentiality provided to the sender.

Source properties

Sender authentication vulnerable to key-compromise impersonation (KCI).
The sender authentication is based on a static-static DH ("ss") involving both
parties' static key pairs. If the recipient's long-term private key has been
compromised, this authentication can be forged.

Destination Properties

Encryption to a known recipient, forward secrecy for sender compromise only,
vulnerable to replay. This payload is encrypted based only on DHs involving the
recipient's static key pair. If the recipient's static private key is
compromised, even at a later date, this payload can be decrypted. This message
can also be replayed, since there's no ephemeral contribution from the
recipient.

## Password Based Encryption

Scrypt is used to derive a symmetric key from a password which is then used
with the chunked file encryption format.

Encryption/Decryption

1. A symmetric key is derived from a password using the scrypt parameters
   N = 15, r = 8, and p = 1.
2. The file is encrypted or decrypted using the derived key and the chunked
   encryption format.

