pub mod errors;

use std::convert::TryInto;

use getrandom::getrandom;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use x25519_dalek::X25519_BASEPOINT_BYTES;

use crate::crypto::errors::DecryptError;

/// X25519 Public Key
pub struct PublicKey {
    key: [u8; 32],
}

/// X25519 Private Key
pub struct PrivateKey {
    key: [u8; 32],
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
    pub fn new() -> PrivateKey {
        let mut key = [0u8; 32];
        getrandom(&mut key).expect("CSPRNG failed");
        PrivateKey { key }
    }

    /// Expose the raw 32 byte private key
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// Derive the public key from the private key
    pub fn to_public(&self) -> PublicKey {
        let pk = x25519_dalek::x25519(self.key, X25519_BASEPOINT_BYTES);
        PublicKey::from(pk.as_ref())
    }
}

/// Convert a raw 32 byte private key into a PrivateKey
impl From<&[u8]> for PrivateKey {
    fn from(raw_key: &[u8]) -> PrivateKey {
        let sk: [u8; 32] = raw_key.try_into().unwrap();
        PrivateKey { key: sk }
    }
}

/// Performs X25519 diffie hellman, returning the shared secret.
pub fn x25519(private_key: &PrivateKey, public_key: &PublicKey) -> [u8; 32] {
    x25519_dalek::x25519(private_key.key, public_key.key)
}

/// Performs ChaCha20-Poly1305 encryption
/// Returns the ciphertxt and 16 byte Poly1305 tag appended
#[allow(clippy::let_and_return)]
pub fn chapoly_encrypt(key: &[u8], nonce: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // For ChaCha20-Poly1305 the noise spec says that the nonce should use
    // little endian.
    let nonce_bytes = nonce.to_le_bytes();
    let mut final_nonce_bytes = [0u8; 12];
    final_nonce_bytes[4..].copy_from_slice(&nonce_bytes);

    let secret_key = Key::from_slice(key);
    let the_nonce = Nonce::from_slice(&final_nonce_bytes);
    let cipher = ChaCha20Poly1305::new(secret_key);
    let pt_and_ad = Payload {
        msg: plaintext,
        aad: ad,
    };

    let ct_and_tag = cipher
        .encrypt(the_nonce, pt_and_ad)
        .expect("ChaCha20-Poly1305 encryption failed.");

    ct_and_tag
}

// Performs ChaCha20-Poly1305 decryption
// The Poly1305 tag must be included as the last 16 bytes of the ciphertext
pub fn chapoly_decrypt(
    key: &[u8],
    nonce: u64,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    assert_eq!(key.len(), 32);

    // For ChaCha20-Poly1305 the noise spec says that the nonce should use
    // little endian.
    let nonce_bytes = nonce.to_le_bytes();
    let mut final_nonce_bytes = [0u8; 12];
    final_nonce_bytes[4..].copy_from_slice(&nonce_bytes);

    let secret_key = Key::from_slice(key);
    let the_nonce = Nonce::from_slice(&final_nonce_bytes);
    let cipher = ChaCha20Poly1305::new(secret_key);
    let ct_and_ad = Payload {
        msg: ciphertext,
        aad: ad,
    };

    match cipher.decrypt(the_nonce, ct_and_ad) {
        Ok(result) => Ok(result),
        Err(_) => Err(DecryptError),
    }
}

/// Derives a secret key from a password and a salt using scrypt
pub fn key_from_pass(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let scrypt_params = scrypt::Params::new(14, 8, 1).unwrap();
    let mut key = [0u8; 32];

    scrypt::scrypt(password, salt, &scrypt_params, &mut key).expect("scrypt kdf failed");

    key.to_vec()
}

#[cfg(test)]
mod test {
    use super::{chapoly_decrypt, chapoly_encrypt, key_from_pass, x25519};
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

        let ct_and_tag = chapoly_encrypt(&key, nonce, &ad, pt);

        println!("{}", hex::encode(&ct_and_tag));

        assert_eq!(&expected[..], &ct_and_tag[..]);
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

        let pt = chapoly_decrypt(&key, nonce, &ad, &ct_and_tag).unwrap();

        assert_eq!(expected, pt.as_slice());
    }

    #[test]
    fn test_key_from_pass() {
        let password = b"hackme";
        let salt = b"yellowsubmarine.";
        let result = key_from_pass(password, salt);
        let expected =
            hex::decode("2e4a8df526366fdd0ab881ef012ea0f2edaf041a0b9a275def08c015697283b0")
                .unwrap();

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

        let alice_to_bob = x25519(&alice_private, &bob_public);
        let bob_to_alice = x25519(&bob_private, &alice_public);

        assert_eq!(&alice_to_bob, &bob_to_alice);
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
