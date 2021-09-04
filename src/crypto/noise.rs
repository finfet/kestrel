use crate::crypto::errors::DecryptError;
use crate::crypto::{chapoly_decrypt, chapoly_encrypt, hash, noise_hkdf, PrivateKey, PublicKey};

const HASH_LEN: usize = 32;
const DH_LEN: usize = 32;

struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

enum MessageToken {
    E,
    S,
    EE,
    ES,
    SE,
    SS,
}

struct CipherState {
    key: Option<[u8; 32]>,
    nonce: u64,
}

struct SymmetricState {
    cipher_state: CipherState,
    chaining_key: [u8; HASH_LEN],
    hash_output: [u8; HASH_LEN],
}

struct HandshakeState {
    symmetric_state: SymmetricState,
    s: Option<KeyPair>,  // The local static key pair
    e: Option<KeyPair>,  // The local ephemeral key pair
    rs: Option<KeyPair>, // The remote party's static public key
    re: Option<KeyPair>, // The remote party's ephemeral public key
    initiator: bool,
    message_pattern: [MessageToken; 4],
}

impl CipherState {
    fn new() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    fn initialize_key(&mut self, key: Option<[u8; 32]>) {
        self.key = key;
    }

    fn has_key(&self) -> bool {
        self.key.is_some()
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }

    fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let key = self
            .key
            .as_ref()
            .expect("X pattern must have a key initialized");
        let nonce = self.nonce;
        let ciphertext = chapoly_encrypt(key, nonce, ad, plaintext);
        assert!(nonce + 1 < u64::MAX - 1);
        self.set_nonce(nonce + 1);
        ciphertext
    }

    fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let key = self
            .key
            .as_ref()
            .expect("X pattern must have a key initialized");
        let nonce = self.nonce;
        let plaintext = chapoly_decrypt(key, nonce, ad, ciphertext)?;
        assert!(nonce + 1 < u64::MAX - 1);
        self.set_nonce(nonce + 1);
        Ok(plaintext)
    }

    // Rekey() function not needed by this application
}

impl SymmetricState {
    fn new() -> Self {
        let mut cipher_state = CipherState::new();
        let mut hash_output = [0u8; 32];
        let protocol_name = "Noise_X_25519_ChaChaPoly_SHA256".as_bytes();
        if protocol_name.len() <= HASH_LEN {
            hash_output[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            hash_output = hash(protocol_name);
        }

        cipher_state.initialize_key(None);

        let chaining_key = hash_output;

        Self {
            cipher_state,
            hash_output,
            chaining_key,
        }
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (chaining_key, temp_key) = noise_hkdf(&self.chaining_key, ikm);
        self.chaining_key = chaining_key;
        self.cipher_state.initialize_key(Some(temp_key));
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut h = Vec::new();
        h.extend_from_slice(&self.hash_output);
        h.extend_from_slice(data);
        self.hash_output = hash(h.as_slice());
    }

    // MixKeyAndHash() function not needed by this application

    fn get_handshake_hash(&self) -> [u8; 32] {
        self.hash_output
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = self
            .cipher_state
            .encrypt_with_ad(&self.hash_output, plaintext);
        self.mix_hash(&ciphertext);
        ciphertext
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let plaintext = self
            .cipher_state
            .decrypt_with_ad(&self.hash_output, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn split(&self) -> (CipherState, CipherState) {
        let (temp_k1, temp_k2) = noise_hkdf(&self.chaining_key, &[]);
        let mut c1 = CipherState::new();
        let mut c2 = CipherState::new();
        c1.initialize_key(Some(temp_k1));
        c2.initialize_key(Some(temp_k2));

        (c1, c2)
    }
}
