// Copyright 2021-2022 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

//! The Kestrel cryptography library.
//! This library provides implementations of ChaCha20-Poly1305, X25519,
//! SHA-256, HMAC-SHA-256 and the Noise X protocol.
//!
//! The goal of this library is not to provide a general cryptographic
//! library, but the functions provided here could certainly be used as such.

pub mod decrypt;
pub mod encrypt;
pub mod errors;
mod noise;

use getrandom::getrandom;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use zeroize::Zeroize;

use errors::ChaPolyDecryptError;
use noise::HandshakeState;

pub const CHUNK_SIZE: usize = 65536;
pub const SCRYPT_N_V1: u32 = 32768;
pub const SCRYPT_R_V1: u32 = 8;
pub const SCRYPT_P_V1: u32 = 1;

#[non_exhaustive]
pub enum AsymFileFormat {
    V1,
}

#[non_exhaustive]
pub enum PassFileFormat {
    V1,
}

/// Noise Payload Key
pub type PayloadKey = [u8; 32];

/// X25519 Public Key
#[derive(Clone, Zeroize)]
pub struct PublicKey {
    key: [u8; 32],
}

/// X25519 Private Key
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey {
    key: [u8; 32],
}

/// KeyPair holding a [`PrivateKey`] and [`PublicKey`]
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

impl From<&PrivateKey> for KeyPair {
    fn from(sk: &PrivateKey) -> Self {
        let pk = sk.to_public();
        Self {
            private_key: sk.clone(),
            public_key: pk,
        }
    }
}

impl PublicKey {
    // Expose the key 32 byte public key
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }
}

/// Convert a raw 32 byte public key into a PublicKey
impl From<&[u8]> for PublicKey {
    fn from(raw_key: &[u8]) -> PublicKey {
        let pk: [u8; 32] = raw_key.try_into().unwrap();
        PublicKey { key: pk }
    }
}

impl PrivateKey {
    /// Generate a new private key from 32 secure random bytes
    pub fn generate() -> PrivateKey {
        let key = secure_random(32);
        let key: [u8; 32] = key.try_into().unwrap();
        PrivateKey { key }
    }

    /// Expose the raw 32 byte private key
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// Derive the public key from the private key
    pub fn to_public(&self) -> PublicKey {
        PublicKey::from(&x25519_derive_public(&self.key)[..])
    }

    /// X25519 Key Exchange between private and a public key,
    /// returning the raw shared secret
    pub fn diffie_hellman(&self, public_key: &PublicKey) -> [u8; 32] {
        x25519(self.as_bytes(), public_key.as_bytes())
    }
}

/// Convert a raw 32 byte private key into a PrivateKey
impl From<&[u8]> for PrivateKey {
    fn from(raw_key: &[u8]) -> PrivateKey {
        let sk: [u8; 32] = raw_key.try_into().expect("Key must be 32 bytes");
        PrivateKey { key: sk }
    }
}

/// RFC 7748 compliant X25519.
/// k is the private key and u is the public key.
/// Keys must be 32 bytes.
pub fn x25519(k: &[u8], u: &[u8]) -> [u8; 32] {
    let sk: [u8; 32] = k.try_into().expect("Private key must be 32 bytes");
    let pk: [u8; 32] = u.try_into().expect("Public key must be 32 bytes");
    x25519_dalek::x25519(sk, pk)
}

/// Derive an X25519 public key from a private key.
/// The private key must be 32 bytes.
pub fn x25519_derive_public(private_key: &[u8]) -> [u8; 32] {
    let sk: [u8; 32] = private_key
        .try_into()
        .expect("Private key must be 32 bytes");
    x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// Encrypt the payload key using the noise X protocol.
/// Passing None to ephemeral generates a new key pair. This is almost
/// certainly what you want.
/// Returns the handshake messsage ciphertext.
pub fn noise_encrypt(
    sender: &PrivateKey,
    recipient: &PublicKey,
    ephemeral: Option<&PrivateKey>,
    prologue: &[u8],
    payload_key: &PayloadKey,
) -> Vec<u8> {
    let sender_keypair = sender.into();
    let ephem_keypair = ephemeral.map(|e| e.into());
    let mut handshake_state = HandshakeState::initialize(
        true,
        prologue,
        Some(sender_keypair),
        ephem_keypair,
        Some(recipient.clone()),
        None,
    );

    // Encrypt the payload key
    let (ciphertext, _) = handshake_state.write_message(payload_key);

    ciphertext
}

/// Decrypt the payload key using the noise protocol.
/// Returns the payload key, and the sender's [PublicKey]
pub fn noise_decrypt(
    recipient: &PrivateKey,
    prologue: &[u8],
    handshake_message: &[u8],
) -> Result<(PayloadKey, PublicKey), ChaPolyDecryptError> {
    let recipient_pair = recipient.into();
    let initiator = false;
    let mut handshake_state = noise::HandshakeState::initialize(
        initiator,
        prologue,
        Some(recipient_pair),
        None,
        None,
        None,
    );

    // Decrypt the payload key
    let (payload_key, _) = handshake_state.read_message(handshake_message)?;
    let payload_key: [u8; 32] = payload_key.try_into().unwrap();

    let sender_pubkey = handshake_state
        .get_pubkey()
        .expect("Expected to send the sender's public key");

    Ok((payload_key, sender_pubkey))
}

/// ChaCha20-Poly1305 encrypt function as specified by the noise protcol.
/// The nonce is stored as a little endian integer in the lowest eight
/// bytes of the nonce. The top four bytes of the nonce are zeros.
/// Returns the ciphertxt and 16 byte Poly1305 tag appended.
#[allow(clippy::let_and_return)]
pub(crate) fn chapoly_encrypt_noise(
    key: &[u8],
    nonce: u64,
    ad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    // For ChaCha20-Poly1305 the noise spec says that the nonce should use
    // little endian.
    let nonce_bytes = nonce.to_le_bytes();
    let mut final_nonce_bytes = [0u8; 12];
    final_nonce_bytes[4..].copy_from_slice(&nonce_bytes);

    chapoly_encrypt_ietf(key, &final_nonce_bytes, plaintext, ad)
}

/// RFC 8439 ChaCha20-Poly1305 encrypt function.
/// The key must be 32 bytes and the nonce must be 12 bytes.
/// Returns the ciphertext
#[allow(clippy::let_and_return, clippy::redundant_field_names)]
pub fn chapoly_encrypt_ietf(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let secret_key = Key::from_slice(key);
    let the_nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(secret_key);
    let pt_and_aad = Payload {
        msg: plaintext,
        aad: aad,
    };

    let ct_and_tag = cipher
        .encrypt(the_nonce, pt_and_aad)
        .expect("ChaCha20-Poly1305 encryption failed.");

    ct_and_tag
}

/// ChaCha20-Poly1305 decrypt function as specified by the noise protocol.
/// The nonce is stored as a little endian integer in the lowest eight
/// bytes of the nonce. The top four bytes of the nonce are zeros.
/// The poly1305 tag must be included as the last 16 bytes of the ciphertext.
/// Returns the plaintext.
pub(crate) fn chapoly_decrypt_noise(
    key: &[u8],
    nonce: u64,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ChaPolyDecryptError> {
    assert_eq!(key.len(), 32);

    // For ChaCha20-Poly1305 the noise spec says that the nonce should use
    // little endian.
    let nonce_bytes = nonce.to_le_bytes();
    let mut final_nonce_bytes = [0u8; 12];
    final_nonce_bytes[4..].copy_from_slice(&nonce_bytes);

    chapoly_decrypt_ietf(key, &final_nonce_bytes, ciphertext, ad)
}

/// RFC 8439 ChaCha20-Poly1305 decrypt function.
/// The key must be 32 bytes and the nonce must be 12 bytes
/// The 16 byte poly1305 tag must be appended to the ciphertext
/// Returns the plaintext
#[allow(clippy::redundant_field_names)]
pub fn chapoly_decrypt_ietf(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ChaPolyDecryptError> {
    let secret_key = Key::from_slice(key);
    let the_nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(secret_key);
    let ct_and_aad = Payload {
        msg: ciphertext,
        aad: aad,
    };

    match cipher.decrypt(the_nonce, ct_and_aad) {
        Ok(pt) => Ok(pt),
        Err(_) => Err(ChaPolyDecryptError),
    }
}

/// SHA-256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let res: [u8; 32] = Sha256::digest(data).as_slice().try_into().unwrap();
    res
}

/// HMAC-SHA-256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    let res = mac.finalize();
    res.into_bytes().try_into().unwrap()
}

fn hkdf_noise(chaining_key: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let counter1: [u8; 1] = [0x01];
    let mut counter2: [u8; 33] = [0u8; 33];
    let temp_key = hmac_sha256(chaining_key, ikm);
    let output1 = hmac_sha256(&temp_key, &counter1);
    counter2[..32].copy_from_slice(&output1);
    counter2[32..].copy_from_slice(&[0x02]);
    let output2 = hmac_sha256(&temp_key, &counter2);
    (output1, output2)
}

/// Derives a secret key from a password and a salt using scrypt.
/// Recommended parameters are n = 32768, r = 8, p = 1
/// Parameter n must be larger than 1 and a power of 2
pub fn scrypt(password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, dk_len: usize) -> Vec<u8> {
    assert!(n > 1, "n must be >1");
    assert!(n % 2 == 0, "n must be a power of 2");
    let n = log2(n);
    let scrypt_params = scrypt::Params::new(n, r, p).unwrap();
    let mut key = vec![0u8; dk_len];

    scrypt::scrypt(password, salt, &scrypt_params, &mut key).expect("scrypt kdf failed");

    key
}

// Get the log2 of a u32
fn log2(x: u32) -> u8 {
    assert!(x != 0);
    let mut x = x;
    let mut res = 0;
    while x > 1 {
        x >>= 1;
        res += 1;
    }

    res
}

/// Generates the specified amount of bytes from a CSPRNG
pub fn secure_random(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    getrandom(&mut data).expect("CSPRNG gen failed");
    data
}

#[cfg(test)]
mod tests {
    use super::{
        chapoly_decrypt_ietf, chapoly_decrypt_noise, chapoly_encrypt_ietf, chapoly_encrypt_noise,
        hmac_sha256, log2, scrypt, sha256, x25519,
    };
    use super::{PrivateKey, PublicKey};

    #[test]
    fn test_log2() {
        assert_eq!(log2(32768), 15);
        assert_eq!(log2(1), 0);
        assert_eq!(log2(8), 3);
    }

    #[test]
    fn test_chapoly_encrypt() {
        let expected =
            hex::decode("cc459a8b9d29617bb70791e7b158dfaf36585f656aec0ada3899fdcd").unwrap();
        let pt = b"Hello world!";
        let key: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let nonce: u64 = 0;
        let ad = [0x00, 0x00, 0x00, 0x0C];

        let ct_and_tag = chapoly_encrypt_noise(&key, nonce, &ad, pt);

        assert_eq!(&expected[..], &ct_and_tag[..]);
    }

    #[test]
    fn test_chapoly_enc_empty_pt() {
        let expected_ct = hex::decode("c7a7077a5e9d774b510100904c7dc805").unwrap();
        let key = hex::decode("68301045a4494999d59ffa818ee5fafc2878bf96c32acf5fa40dbe93e8ac98ce")
            .unwrap();
        let nonce = [0u8; 12];
        let aad: [u8; 1] = [0x01];

        let ct = chapoly_encrypt_ietf(key.as_slice(), &nonce, &[], &aad);

        assert_eq!(expected_ct.as_slice(), ct.as_slice());
    }

    #[test]
    fn test_decrypt() {
        let key = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .unwrap();
        let nonce: u64 = 0;
        let ad = hex::decode("0000000C").unwrap();
        let expected = b"Hello world!";
        let ct_and_tag =
            hex::decode("cc459a8b9d29617bb70791e7b158dfaf36585f656aec0ada3899fdcd").unwrap();

        let pt = chapoly_decrypt_noise(&key, nonce, &ad, &ct_and_tag).unwrap();

        assert_eq!(expected, pt.as_slice());
    }

    #[test]
    fn test_chapoly_dec_empty_pt() {
        let ct = hex::decode("c7a7077a5e9d774b510100904c7dc805").unwrap();
        let key = hex::decode("68301045a4494999d59ffa818ee5fafc2878bf96c32acf5fa40dbe93e8ac98ce")
            .unwrap();
        let nonce = [0u8; 12];
        let aad: [u8; 1] = [0x01];

        let pt = chapoly_decrypt_ietf(key.as_slice(), &nonce, ct.as_slice(), &aad).unwrap();

        let expected_pt: [u8; 0] = [];
        assert_eq!(&expected_pt, pt.as_slice());
    }

    #[test]
    fn test_sha256() {
        let data = b"hello";
        let got = sha256(data);
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap();
        assert_eq!(&got, expected.as_slice());
    }

    #[test]
    fn test_scrypt() {
        let password = b"hackme";
        let salt = b"yellowsubmarine.";
        let result = scrypt(password, salt, 32768, 8, 1, 32);
        let expected =
            hex::decode("3ebb9ac0d1da595f755407fe8fc246fe67fe6075730fc6e853351c2834bd6157")
                .unwrap();

        assert_eq!(&expected, &result);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"yellowsubmarine.yellowsubmarine.";
        let message = b"Hello, world!";
        let expected =
            hex::decode("3cb82dc71c26dfe8be75805f6438027d5170f3fdcd8057f0a55d1c7c1743224c")
                .unwrap();
        let result = hmac_sha256(key, message);

        assert_eq!(&expected, &result);
    }

    #[test]
    fn test_rfc7748_diffie_hellman_vectors() {
        let alice_private_expected =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let alice_public_expected =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let bob_private_expected =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap();
        let bob_public_expected =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap();
        let expected_shared_secret =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap();

        let alice_private = PrivateKey::from(alice_private_expected.as_slice());
        let alice_public = PublicKey::from(alice_public_expected.as_slice());
        assert_eq!(
            &alice_public_expected,
            &alice_private.to_public().as_bytes()
        );

        let bob_private = PrivateKey::from(bob_private_expected.as_slice());
        let bob_public = PublicKey::from(bob_public_expected.as_slice());

        let alice_to_bob = x25519(alice_private.as_bytes(), bob_public.as_bytes());
        let bob_to_alice = x25519(bob_private.as_bytes(), alice_public.as_bytes());
        let alice_to_bob2 = alice_private.diffie_hellman(&bob_public);

        assert_eq!(&alice_to_bob, &bob_to_alice);
        assert_eq!(&alice_to_bob, &alice_to_bob2);
        assert_eq!(&alice_to_bob, expected_shared_secret.as_slice());
    }

    #[test]
    fn test_private_to_public() {
        let alice_private_expected =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let alice_public_expected =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let got_public = PrivateKey::from(&alice_private_expected[..]).to_public();

        assert_eq!(&alice_public_expected[..], got_public.as_bytes());
    }
}
