use std::convert::TryInto;

use rand::thread_rng;
use rand::Rng;

use x25519_dalek::X25519_BASEPOINT_BYTES;

/// X25519 Private Key
pub struct PrivateKey {
    key: [u8; 32],
}

/// X25519 Public Key
pub struct PublicKey {
    key: [u8; 32],
}

impl PrivateKey {
    /// Generate a new private key from 32 secure random bytes
    pub fn new() -> PrivateKey {
        let mut csprng = thread_rng();
        let mut key = [0u8; 32];
        csprng.fill(&mut key[..]);
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
