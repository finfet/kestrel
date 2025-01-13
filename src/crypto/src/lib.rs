// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

//! The Kestrel cryptography library.
//! This library provides implementations of ChaCha20-Poly1305, X25519,
//! SHA-256, HMAC-SHA-256 and the Noise X protocol.
//!
//! The goal of this library is not to serve as a general purpose
//! cryptographic library, but the functions provided here could certainly
//! be used as such.

// @@SECURITY: We're doing a best effort job to zero all key data after use.
// The APIs of some of the underlying crypto libraries result in some key
// data being left on the stack.

pub mod decrypt;
pub mod encrypt;
pub mod errors;
mod noise;
mod scrypt;

use getrandom::getrandom;

use orion::hazardous::aead::chacha20poly1305 as chapoly;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

extern crate scrypt as rc_scrypt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use errors::{ChaPolyDecryptError, DhError, NoiseError};
use noise::HandshakeState;

const CHUNK_SIZE: u32 = 65536;
const SCRYPT_N: u32 = 32768;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const TAG_SIZE: usize = 16;

/// Key file format
#[derive(Copy, Clone, PartialEq)]
#[non_exhaustive]
pub enum AsymFileFormat {
    V1,
}

/// Password file format
#[derive(Copy, Clone, PartialEq)]
#[non_exhaustive]
pub enum PassFileFormat {
    V1,
}

/// File format versions
#[derive(Copy, Clone, PartialEq)]
#[non_exhaustive]
pub enum FileFormat {
    AsymV1,
    PassV1,
}

/// Payload Key encrypted by the noise protocol
#[derive(Clone)]
pub struct PayloadKey {
    key: [u8; 32],
}

impl PayloadKey {
    /// Create a new Key. Keys must be 32 bytes
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: key.try_into().expect("Keys must be 32 bytes"),
        }
    }

    /// Get the bytes of the key
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_slice()
    }
}

impl Drop for PayloadKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for PayloadKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for PayloadKey {}

/// X25519 Public Key
#[derive(Clone)]
pub struct PublicKey {
    key: Vec<u8>,
}

/// X25519 Private Key
#[derive(Clone)]
pub struct PrivateKey {
    key: Vec<u8>,
}

impl PublicKey {
    // Expose the key 32 byte public key
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }
}

/// Convert a raw 32 byte public key into a PublicKey
impl TryFrom<&[u8]> for PublicKey {
    type Error = &'static str;

    fn try_from(raw_key: &[u8]) -> Result<PublicKey, Self::Error> {
        if raw_key.len() != 32 {
            return Err("Public keys must be 32 bytes");
        }
        let pk = raw_key.to_vec();
        Ok(PublicKey { key: pk })
    }
}

impl PrivateKey {
    /// Generate a new private key from 32 secure random bytes
    pub fn generate() -> PrivateKey {
        let key = secure_random(32);
        PrivateKey { key }
    }

    /// Expose the raw 32 byte private key
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// Derive the public key from the private key
    pub fn to_public(&self) -> Result<PublicKey, DhError> {
        let pk = x25519_derive_public(&self.key)?;
        Ok(PublicKey::try_from(pk.as_slice()).unwrap())
    }

    /// X25519 Key Exchange between private and a public key,
    /// returning the raw shared secret
    pub fn diffie_hellman(&self, public_key: &PublicKey) -> Result<Vec<u8>, DhError> {
        x25519(self.as_bytes(), public_key.as_bytes())
    }
}

/// Convert a raw 32 byte private key into a PrivateKey
impl TryFrom<&[u8]> for PrivateKey {
    type Error = &'static str;

    fn try_from(raw_key: &[u8]) -> Result<PrivateKey, Self::Error> {
        if raw_key.len() != 32 {
            return Err("Private keys must be 32 bytes");
        }
        let sk = raw_key.to_vec();
        Ok(PrivateKey { key: sk })
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

impl ZeroizeOnDrop for PrivateKey {}

/// RFC 7748 compliant X25519.
/// k is the private key and u is the public key.
/// Keys must be 32 bytes.
pub fn x25519(k: &[u8], u: &[u8]) -> Result<Vec<u8>, DhError> {
    let mut sk: [u8; 32] = k.try_into().expect("Private key must be 32 bytes");
    let pk: [u8; 32] = u.try_into().expect("Public key must be 32 bytes");

    let mut dh = x25519_dalek::x25519(sk, pk);
    let res = dh.to_vec();
    dh.zeroize();
    sk.zeroize();

    Ok(res)
}

/// Derive an X25519 public key from a private key.
/// The private key must be 32 bytes.
pub fn x25519_derive_public(private_key: &[u8]) -> Result<Vec<u8>, DhError> {
    x25519(private_key, &x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// A struct containing the result of a [`noise_encrypt`]
pub struct NoiseEncryptMsg {
    pub ciphertext: Vec<u8>,
    pub handshake_hash: [u8; 32],
}

/// Encrypt the payload key using the noise X protocol.
///
/// Passing None for ephemeral, and ephemeral_public will generate
/// fresh keys. This is almost certainly what you want.
///
/// Sender and ephemeral private and public keys must match.
/// prologue is included in the handshake hash, ensuring the handshake fails
/// if the data isn't identical.
/// payload must be <= 65439 bytes. The resulting message is a maximum of
/// 65535 bytes.
///
/// Returns the handshake message ciphertext.
pub fn noise_encrypt(
    sender: &PrivateKey,
    sender_public: &PublicKey,
    recipient: &PublicKey,
    ephemeral: Option<&PrivateKey>,
    ephemeral_public: Option<&PublicKey>,
    prologue: &[u8],
    payload_key: &PayloadKey,
) -> Result<NoiseEncryptMsg, NoiseError> {
    let mut handshake_state = HandshakeState::init_x(
        true,
        prologue,
        sender.clone(),
        sender_public.clone(),
        ephemeral.cloned(),
        ephemeral_public.cloned(),
        Some(recipient.clone()),
    );

    let noise_handshake = handshake_state.write_message(payload_key.as_bytes())?;
    let handshake_hash = noise_handshake.handshake_hash;
    let ciphertext = noise_handshake.message;

    Ok(NoiseEncryptMsg {
        ciphertext,
        handshake_hash,
    })
}

/// A struct containing the result of a [`noise_decrypt`]
/// PublicKey is the sender's public key
pub struct NoiseDecryptMsg {
    pub payload_key: PayloadKey,
    pub public_key: PublicKey,
    pub handshake_hash: [u8; 32],
}

/// Decrypt the payload key using the noise protocol.
/// The given recipient public key must match the recipient private key.
/// Returns the payload key, and the sender's [PublicKey]
pub fn noise_decrypt(
    recipient: &PrivateKey,
    recipient_public: &PublicKey,
    prologue: &[u8],
    handshake_message: &[u8],
) -> Result<NoiseDecryptMsg, NoiseError> {
    let initiator = false;
    let mut handshake_state = noise::HandshakeState::init_x(
        initiator,
        prologue,
        recipient.clone(),
        recipient_public.clone(),
        None,
        None,
        None,
    );

    // Decrypt the payload key
    let noise_handshake = handshake_state.read_message(handshake_message)?;
    let handshake_hash = noise_handshake.handshake_hash;
    if noise_handshake.message.len() != 32 {
        return Err(NoiseError::Other(
            "Expected payload key to be 32 bytes.".to_string(),
        ));
    }

    let payload_key = PayloadKey::new(noise_handshake.message.as_slice());
    let sender_pubkey = handshake_state
        .get_pubkey()
        .expect("Expected to get the sender's public key");

    Ok(NoiseDecryptMsg {
        payload_key,
        public_key: sender_pubkey,
        handshake_hash,
    })
}

/// ChaCha20-Poly1305 encrypt function as specified by the noise protocol.
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
/// The aad should be an empty slice if not used.
/// Returns the ciphertext.
#[allow(clippy::let_and_return, clippy::redundant_field_names)]
pub fn chapoly_encrypt_ietf(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let nonce = chapoly::Nonce::from_slice(nonce).expect("Nonce must be 12 bytes");
    let mut ct_and_tag = vec![0u8; plaintext.len() + TAG_SIZE];
    let key = chapoly::SecretKey::from_slice(key).expect("Key must be 32 bytes");
    chapoly::seal(
        &key,
        &nonce,
        plaintext,
        Some(aad),
        ct_and_tag.as_mut_slice(),
    )
    .expect("ChaCha20-Poly11305 encryption failed");

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
/// The key must be 32 bytes and the nonce must be 12 bytes.
/// The 16 byte poly1305 tag must be appended to the ciphertext.
/// Returns the plaintext.
#[allow(clippy::redundant_field_names)]
pub fn chapoly_decrypt_ietf(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ChaPolyDecryptError> {
    let nonce = chapoly::Nonce::from_slice(nonce).expect("Nonce must be 12 bytes");
    let key = chapoly::SecretKey::from_slice(key).expect("Key must be 32 bytes");
    let pt_size = std::cmp::max(ciphertext.len() - TAG_SIZE, 0);
    let mut plaintext = vec![0u8; pt_size];

    chapoly::open(
        &key,
        &nonce,
        ciphertext,
        Some(aad),
        plaintext.as_mut_slice(),
    )
    .map_err(|_| ChaPolyDecryptError)?;

    Ok(plaintext)
}

/// SHA-256
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).as_slice().to_vec()
}

/// HMAC-SHA-256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().as_slice().to_vec()
}

fn hkdf_noise(chaining_key: &[u8], ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let counter1: [u8; 1] = [0x01];
    let mut counter2: [u8; 33] = [0u8; 33];
    let temp_key = hmac_sha256(chaining_key, ikm);
    let output1 = hmac_sha256(&temp_key, &counter1);
    counter2[..32].copy_from_slice(&output1);
    counter2[32..].copy_from_slice(&[0x02]);
    let output2 = hmac_sha256(&temp_key, &counter2);
    counter2.zeroize();
    (output1, output2)
}

/// HKDF-SHA256
/// If no info or salt is required, use the empty slice.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk: Hkdf<Sha256> = Hkdf::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, okm.as_mut_slice())
        .expect("Unexpected HKDF length");

    okm
}

/// Derives a secret key from a password and a salt using scrypt.
/// Recommended parameters are n = 32768, r = 8, p = 1
/// Parameter n must be larger than 1 and a power of 2.
pub fn scrypt(password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, dk_len: usize) -> Vec<u8> {
    scrypt::scrypt(password, salt, n as usize, r as usize, p as usize, dk_len)
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
        hkdf_sha256, hmac_sha256, scrypt, sha256, x25519,
    };
    use super::{PrivateKey, PublicKey};

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
    fn test_hkdf_sha256() {
        // RFC-5869 Test Case 1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let length = 42;

        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        let result_okm = hkdf_sha256(&salt, &ikm, &info, length);

        assert_eq!(&expected_okm, &result_okm);

        // RFC-5869 Test Case 3
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = &[];
        let info = &[];
        let length = 42;

        let expected_okm = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        .unwrap();

        let result_okm = hkdf_sha256(salt, &ikm, info, length);
        assert_eq!(&expected_okm, &result_okm);
    }

    #[test]
    fn test_scrypt() {
        let password = b"hackme";
        let salt = b"yellowsubmarine.";

        let expected1 =
            hex::decode("3ebb9ac0d1da595f755407fe8fc246fe67fe6075730fc6e853351c2834bd6157")
                .unwrap();
        let result1 = scrypt(password, salt, 32768, 8, 1, 32);
        assert_eq!(&expected1, &result1);

        let expected2 = hex::decode("3ebb9ac0d1da595f").unwrap();
        let result2 = scrypt(password, salt, 32768, 8, 1, 8);
        assert_eq!(&expected2, &result2);

        let expected3 = hex::decode("87b33dba57a7633a3df7741eabee3de0").unwrap();
        let result3 = scrypt(password, salt, 1024, 8, 1, 16);
        assert_eq!(&expected3, &result3);
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

        let alice_private = PrivateKey::try_from(alice_private_expected.as_slice()).unwrap();
        let alice_public = PublicKey::try_from(alice_public_expected.as_slice()).unwrap();
        assert_eq!(
            &alice_public_expected,
            &alice_private.to_public().unwrap().as_bytes()
        );

        let bob_private = PrivateKey::try_from(bob_private_expected.as_slice()).unwrap();
        let bob_public = PublicKey::try_from(bob_public_expected.as_slice()).unwrap();

        let alice_to_bob = x25519(alice_private.as_bytes(), bob_public.as_bytes()).unwrap();
        let bob_to_alice = x25519(bob_private.as_bytes(), alice_public.as_bytes()).unwrap();
        let alice_to_bob2 = alice_private.diffie_hellman(&bob_public).unwrap();

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
        let got_public = PrivateKey::try_from(&alice_private_expected[..])
            .unwrap()
            .to_public()
            .unwrap();

        assert_eq!(&alice_public_expected[..], got_public.as_bytes());
    }
}
