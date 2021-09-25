pub mod errors;
mod noise;

use std::convert::TryInto;

use getrandom::getrandom;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use x25519_dalek::X25519_BASEPOINT_BYTES;

use hmac::{Hmac, Mac, NewMac};
use sha2::{Digest, Sha256};

use errors::ChaPolyDecryptError;
use noise::HandshakeState;

// WREN_SALT_VER_01 with trailing zero bytes
const WREN_SALT: [u8; 32] = [
    0x57, 0x52, 0x45, 0x4e, 0x5f, 0x53, 0x41, 0x4c, 0x54, 0x5f, 0x56, 0x45, 0x52, 0x5f, 0x30, 0x31,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// X25519 Public Key
#[derive(Clone, Copy)]
pub struct PublicKey {
    key: [u8; 32],
}

/// X25519 Private Key
#[derive(Clone, Copy)]
pub struct PrivateKey {
    key: [u8; 32],
}

#[derive(Clone, Copy)]
pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl KeyPair {
    fn new(private_key: &PrivateKey, public_key: &PublicKey) -> Self {
        Self {
            private_key: private_key.clone(),
            public_key: public_key.clone(),
        }
    }
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

/// Encrypt the payload key using the noise X protocol.
/// Passing None to ephemeral generates a new key pair. This is almost
/// certainly what you want. Returns the channel bound file encryption key
/// and the noise handshake message.
pub fn noise_encrypt(
    sender: &PrivateKey,
    recipient: &PublicKey,
    ephemeral: Option<&PrivateKey>,
    prologue: &[u8],
    payload_key: [u8; 32],
) -> ([u8; 32], Vec<u8>) {
    let sender_keypair = sender.into();
    let ephem_keypair = ephemeral.map_or(None, |e| Some(e.into()));
    let mut handshake_state = HandshakeState::initialize(
        true,
        prologue,
        Some(sender_keypair),
        ephem_keypair,
        Some(recipient.clone()),
        None,
    );

    // Encrypt the payload key
    let (ciphertext, _) = handshake_state.write_message(&payload_key);

    let handshake_hash = handshake_state.symmetric_state.get_handshake_hash();

    // ikm = payload_key || handshake_hash
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&payload_key);
    ikm[32..].copy_from_slice(&handshake_hash);

    let derived_key = derive_key(&ikm);

    (derived_key, ciphertext)
}

/// Decrypt the payload key using the noise protocol.
/// Returns the channel bound file encryption key and the sender's [PublicKey]
pub fn noise_decrypt(
    recipient: &PrivateKey,
    prologue: &[u8],
    handshake_message: &[u8],
) -> Result<([u8; 32], PublicKey), ChaPolyDecryptError> {
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
    let (payload_key, _) = handshake_state.read_message(handshake_message)?;

    let handshake_hash = handshake_state.symmetric_state.get_handshake_hash();
    let sender_pubkey = handshake_state
        .get_pubkey()
        .expect("Expected to send the sender's public key");

    // ikm = payload_key || handshake_hash
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(payload_key.as_slice());
    ikm[32..].copy_from_slice(&handshake_hash);

    let derived_key = derive_key(&ikm);

    Ok((derived_key, sender_pubkey))
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
) -> Result<Vec<u8>, ChaPolyDecryptError> {
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
        Err(_) => Err(ChaPolyDecryptError),
    }
}

/// SHA-256
pub fn hash(data: &[u8]) -> [u8; 32] {
    let res: [u8; 32] = Sha256::digest(data).as_slice().try_into().unwrap();
    res
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    let res = mac.finalize();
    let res = res.into_bytes().try_into().unwrap();
    res
}

fn noise_hkdf(chaining_key: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let counter1: [u8; 1] = [0x01];
    let mut counter2: [u8; 33] = [0u8; 33];
    let temp_key = hmac_sha256(chaining_key, ikm);
    let output1 = hmac_sha256(&temp_key, &counter1);
    counter2[..32].copy_from_slice(&output1);
    counter2[32..].copy_from_slice(&[0x02]);
    let output2 = hmac_sha256(&temp_key, &counter2);
    (output1, output2)
}

/// Derives a secret key from a password and a salt using scrypt
pub fn key_from_pass(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let scrypt_params = scrypt::Params::new(15, 8, 1).unwrap();
    let mut key = [0u8; 32];

    scrypt::scrypt(password, salt, &scrypt_params, &mut key).expect("scrypt kdf failed");

    key.to_vec().try_into().unwrap()
}

/// Derive a pseudorandom key from input key material
/// Performs HMAC_SHA256(salt, ikm) using [`WREN_SALT`] and the ikm.
/// This is equivalent to hkdf-extract
fn derive_key(ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(&WREN_SALT, ikm)
}

/// Generates 16 CSPRNG bytes to use as a salt for [`key_from_pass`]
pub fn gen_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    getrandom(&mut salt).expect("CSPRNG for salt gen failed");
    salt
}

/// Generate a fresh 32 byte symmetric key from a CSPRNG
pub fn gen_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom(&mut key).expect("CSPRNG for key gen failed.");
    key
}

#[cfg(test)]
mod test {
    use super::{chapoly_decrypt, chapoly_encrypt, hash, key_from_pass, x25519};
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
    fn test_hash() {
        let data = b"wren";
        let got = hash(data);
        let expected =
            hex::decode("b1e3c2ec1a80a8ccdbcdb04b26a5896ea2c7ef8b3774dbb004bd3b1aaa195bec")
                .unwrap();
        assert_eq!(&got, expected.as_slice());
    }

    #[test]
    fn test_key_from_pass() {
        let password = b"hackme";
        let salt = b"yellowsubmarine.";
        let result = key_from_pass(password, salt);
        let expected =
            hex::decode("3ebb9ac0d1da595f755407fe8fc246fe67fe6075730fc6e853351c2834bd6157")
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
