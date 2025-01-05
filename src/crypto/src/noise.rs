// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

//! Noise Protocol X pattern implementation

use std::collections::VecDeque;

use zeroize::Zeroizing;

use crate::errors::NoiseError;
use crate::{
    chapoly_decrypt_noise, chapoly_encrypt_noise, hkdf_noise, sha256, PayloadKey, PrivateKey,
    PublicKey,
};

const HASH_LEN: usize = 32;
const DH_LEN: usize = 32;

pub type Key = PayloadKey;

#[derive(Clone)]
struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

impl KeyPair {
    fn new(sk: PrivateKey, pk: PublicKey) -> Self {
        KeyPair {
            private_key: sk,
            public_key: pk,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum Token {
    E,
    S,
    EE,
    ES,
    SE,
    SS,
}

pub struct CipherState {
    key: Option<Key>,
    nonce: u64,
}

pub struct SymmetricState {
    cipher_state: CipherState,
    chaining_key: Key,
    hash_output: [u8; HASH_LEN],
}

pub struct HandshakeState {
    pub symmetric_state: SymmetricState,
    s: Option<KeyPair>,    // The local static key pair
    e: Option<KeyPair>,    // The local ephemeral key pair
    rs: Option<PublicKey>, // The remote party's static public key
    re: Option<PublicKey>, // The remote party's ephemeral public key
    initiator: bool,
    message_patterns: VecDeque<Vec<Token>>,
}

#[allow(dead_code)]
pub struct NoiseHandshake {
    pub message: Vec<u8>,
    pub cipher_state: CipherState,
    pub handshake_hash: [u8; 32],
}

impl CipherState {
    pub fn new() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    pub fn initialize_key(&mut self, key: Option<Key>) {
        self.key = key;
        self.nonce = 0;
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        assert!(nonce < u64::MAX);
        self.nonce = nonce;
    }

    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let key = self
            .key
            .as_ref()
            .expect("X pattern must have a key initialized");
        let nonce = self.nonce;
        let ciphertext = chapoly_encrypt_noise(key.as_bytes(), nonce, ad, plaintext);
        self.set_nonce(nonce + 1);
        ciphertext
    }

    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let key = self
            .key
            .as_ref()
            .expect("X pattern must have a key initialized");
        let nonce = self.nonce;
        let plaintext = chapoly_decrypt_noise(key.as_bytes(), nonce, ad, ciphertext)?;
        self.set_nonce(nonce + 1);
        Ok(plaintext)
    }

    #[allow(dead_code)]
    pub fn rekey(&mut self) {
        unimplemented!("Rekey is not used by this application.");
    }
}

impl SymmetricState {
    fn new(protocol_name: &str) -> Self {
        let mut cipher_state = CipherState::new();
        let mut hash_output = [0u8; 32];
        let protocol_name = protocol_name.as_bytes();
        if protocol_name.len() <= HASH_LEN {
            hash_output[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            hash_output = sha256(protocol_name).try_into().unwrap();
        }

        cipher_state.initialize_key(None);

        let chaining_key = Key::new(&hash_output);

        Self {
            cipher_state,
            hash_output,
            chaining_key,
        }
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (chaining_key, temp_key) = hkdf_noise(self.chaining_key.as_bytes(), ikm);
        let chaining_key = Zeroizing::new(chaining_key);
        let temp_key = Zeroizing::new(temp_key);
        self.chaining_key = Key::new(chaining_key.as_ref());
        self.cipher_state
            .initialize_key(Some(Key::new(temp_key.as_ref())));
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut h = Vec::new();
        h.extend_from_slice(&self.hash_output);
        h.extend_from_slice(data);
        self.hash_output = sha256(h.as_slice()).try_into().unwrap();
    }

    #[allow(dead_code)]
    fn mix_key_and_hash() {
        unimplemented!("MixKeyAndHash() is not needed by this application");
    }

    pub fn get_handshake_hash(&self) -> [u8; 32] {
        self.hash_output
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = self
            .cipher_state
            .encrypt_with_ad(&self.hash_output, plaintext);
        self.mix_hash(&ciphertext);
        ciphertext
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let plaintext = self
            .cipher_state
            .decrypt_with_ad(&self.hash_output, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn split(&self) -> (CipherState, CipherState) {
        let (temp_k1, temp_k2) = hkdf_noise(self.chaining_key.as_bytes(), &[]);
        let temp_k1 = Zeroizing::new(temp_k1);
        let temp_k2 = Zeroizing::new(temp_k2);
        let mut c1 = CipherState::new();
        let mut c2 = CipherState::new();
        c1.initialize_key(Some(Key::new(temp_k1.as_ref())));
        c2.initialize_key(Some(Key::new(temp_k2.as_ref())));

        (c1, c2)
    }
}

impl HandshakeState {
    /// Implementation of the noise X pattern Noise_X_25519_ChaChaPoly_SHA256
    ///
    /// Initializes a handshake state.
    /// When sending a message (initiator == true): rs is required.
    /// The sender public and private keys must match. Passing None for the
    /// ephemeral keys will generate fresh keys.
    pub fn init_x(
        initiator: bool,
        prologue: &[u8],
        s: PrivateKey,
        spk: PublicKey,
        e: Option<PrivateKey>,
        epk: Option<PublicKey>,
        rs: Option<PublicKey>,
    ) -> Self {
        let mut symmetric_state = SymmetricState::new("Noise_X_25519_ChaChaPoly_SHA256");
        symmetric_state.mix_hash(prologue);

        let s_pair: KeyPair = KeyPair::new(s, spk);

        let e_pair: Option<KeyPair> = if e.is_some() && epk.is_some() {
            let epriv = e.unwrap();
            let epub = epk.unwrap();
            Some(KeyPair::new(epriv, epub))
        } else {
            None
        };

        // Public key mixing here is hardcoded for the X pattern.
        if initiator {
            assert!(rs.is_some());
            let rs_public_key = rs.as_ref().unwrap();
            symmetric_state.mix_hash(rs_public_key.as_bytes());
        } else {
            symmetric_state.mix_hash(s_pair.public_key.as_bytes());
        }

        let mut message_patterns: VecDeque<Vec<Token>> = VecDeque::new();
        // X pattern
        let pattern = vec![Token::E, Token::ES, Token::S, Token::SS];
        message_patterns.push_back(pattern);
        Self {
            symmetric_state,
            s: Some(s_pair),
            e: e_pair,
            rs,
            re: None,
            initiator,
            message_patterns,
        }
    }

    /// Return the sender's public key after a noise read_message
    pub fn get_pubkey(&self) -> Option<PublicKey> {
        // We only want the sender's key if we're the recipient
        if self.initiator {
            return None;
        }

        if let Some(pk) = &self.rs {
            return Some(pk.clone());
        }

        None
    }

    /// Write a Noise Handshake Message.
    ///
    /// payload must be <= 65439 bytes. The resulting message is a maximum of
    /// 65535 bytes.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<NoiseHandshake, NoiseError> {
        let mut message_buffer = Vec::<u8>::new();
        let message_pattern = self
            .message_patterns
            .pop_front()
            .expect("X pattern consists of a single pattern");
        for pattern in message_pattern {
            match pattern {
                Token::E => {
                    if self.e.is_none() {
                        let ephem_private_key = PrivateKey::generate();
                        let ephem_public_key = ephem_private_key.to_public()?;
                        let ephem_pair = KeyPair {
                            private_key: ephem_private_key,
                            public_key: ephem_public_key,
                        };
                        self.e = Some(ephem_pair);
                    }
                    let ephem_pair = self.e.as_ref().unwrap();

                    message_buffer.extend_from_slice(ephem_pair.public_key.as_bytes());
                    self.symmetric_state
                        .mix_hash(ephem_pair.public_key.as_bytes());
                }
                Token::S => {
                    let s = self.s.as_ref().unwrap();
                    let enc_pubkey = self
                        .symmetric_state
                        .encrypt_and_hash(s.public_key.as_bytes());
                    message_buffer.extend_from_slice(enc_pubkey.as_slice());
                }
                Token::EE => {
                    unimplemented!("EE not used in the X pattern");
                }
                Token::ES => {
                    // In the X scheme, we can't be a responder while writing
                    // a message.
                    debug_assert!(self.initiator);
                    let e = self.e.as_ref().unwrap();
                    let rs = self.rs.as_ref().unwrap();
                    let shared_secret = e.private_key.diffie_hellman(rs)?;
                    let shared_secret = Zeroizing::new(shared_secret);
                    self.symmetric_state.mix_key(shared_secret.as_ref());
                }
                Token::SE => {
                    unimplemented!("SE not used in the X pattern");
                }
                Token::SS => {
                    let s = self.s.as_ref().unwrap();
                    let rs = self.rs.as_ref().unwrap();
                    let shared_secret = s.private_key.diffie_hellman(rs)?;
                    let shared_secret = Zeroizing::new(shared_secret);
                    self.symmetric_state.mix_key(shared_secret.as_ref());
                }
            }
        }

        let enc_payload = self.symmetric_state.encrypt_and_hash(payload);
        message_buffer.extend_from_slice(enc_payload.as_slice());

        let handshake_hash = self.symmetric_state.get_handshake_hash();

        // X pattern is one way so we don't need the second cipher state
        let (cipher_state, _) = self.symmetric_state.split();

        Ok(NoiseHandshake {
            message: message_buffer,
            cipher_state,
            handshake_hash,
        })
    }

    /// Read a noise handshake message
    pub fn read_message(&mut self, message: &[u8]) -> Result<NoiseHandshake, NoiseError> {
        let message_pattern = self
            .message_patterns
            .pop_front()
            .expect("X pattern consists of a single message");
        let mut msgidx: usize = 0;
        assert!(
            message.len() >= 64 && message.len() <= 65535,
            "Noise X pattern handshake message must >= 64 and <= 65535 bytes"
        );
        for pattern in message_pattern {
            match pattern {
                Token::E => {
                    let remote_ephem_bytes = &message[msgidx..(msgidx + DH_LEN)];
                    let re = PublicKey::try_from(remote_ephem_bytes).map_err(|_| {
                        NoiseError::Other("Invalid remote emphem public key size".to_string())
                    })?;
                    self.re = Some(re.clone());
                    self.symmetric_state.mix_hash(re.as_bytes());
                    msgidx += DH_LEN;
                }
                Token::S => {
                    let index_len: usize = if self.symmetric_state.cipher_state.has_key() {
                        DH_LEN + 16
                    } else {
                        DH_LEN
                    };
                    let enc_pubkey_and_tag = &message[msgidx..msgidx + index_len];
                    let rs_bytes = self.symmetric_state.decrypt_and_hash(enc_pubkey_and_tag)?;
                    msgidx += index_len;

                    let rs = PublicKey::try_from(rs_bytes.as_ref()).map_err(|_| {
                        NoiseError::Other("Invalid remote static public key size".to_string())
                    })?;
                    self.rs = Some(rs);
                }
                Token::EE => {
                    unimplemented!("EE not used in the X pattern");
                }
                Token::ES => {
                    // In the X scheme, we can't be an initiator while reading
                    // a message
                    debug_assert!(!self.initiator);
                    let s = self.s.as_ref().unwrap();
                    let re = self.re.as_ref().unwrap();
                    let shared_secret = s.private_key.diffie_hellman(re)?;
                    let shared_secret = Zeroizing::new(shared_secret);
                    self.symmetric_state.mix_key(shared_secret.as_ref());
                }
                Token::SE => {
                    unimplemented!("SE not used in the X pattern");
                }
                Token::SS => {
                    let s = self.s.as_ref().unwrap();
                    let rs = self.rs.as_ref().unwrap();
                    let shared_secret = s.private_key.diffie_hellman(rs)?;
                    let shared_secret = Zeroizing::new(shared_secret);
                    self.symmetric_state.mix_key(shared_secret.as_ref());
                }
            }
        }

        let dec_payload_buffer = self.symmetric_state.decrypt_and_hash(&message[msgidx..])?;

        let handshake_hash = self.symmetric_state.get_handshake_hash();

        // X pattern is one way so we don't need the second cipher state
        let (cipher_state, _) = self.symmetric_state.split();

        Ok(NoiseHandshake {
            message: dec_payload_buffer,
            cipher_state,
            handshake_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::HandshakeState;
    use super::{PrivateKey, PublicKey};

    #[test]
    fn test_write_message() {
        let prologue = hex::decode("50726f6c6f677565313233").unwrap();
        let initiator_priv_bytes =
            hex::decode("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")
                .unwrap();
        let ephem_priv_bytes =
            hex::decode("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
                .unwrap();
        let remote_static_pub_bytes =
            hex::decode("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62")
                .unwrap();
        let payload = hex::decode("4c756477696720766f6e204d69736573").unwrap();
        let expected_ciphertext = hex::decode("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79446c15957a594079a5bdeae05d01e089fbb7cc6ea2ecfd209b941f73c9235213bc14ed87a1a4a0b164c11a5999be0f7bf1fdc3aaa6de60cb3c98302f370fdb03ea6fe2cf18324b0812663aed65fc9eafdf")
            .unwrap();

        let exp_handshake_hash =
            hex::decode("e5cdeb715c9553e966ccd446aff7f6df1556d0ecda39ddb49ef24c876fe249b7")
                .unwrap();
        // Vectors for the transport messages
        let transport_payload1 = hex::decode("4d757272617920526f746862617264").unwrap();
        let exp_transport_ct1 =
            hex::decode("9868def631af6242aaf00c35218275832d8d022af1c67b9fc5e8ba90f4d91b").unwrap();
        let trasnport_payload2 = hex::decode("462e20412e20486179656b").unwrap();
        let exp_transport_ct2 =
            hex::decode("9fdd2576d757f880de49b32b80abf53afec16ddc86769f0e92daff").unwrap();

        let static_priv = PrivateKey::try_from(initiator_priv_bytes.as_ref()).unwrap();
        let static_pub = static_priv.to_public().unwrap();

        let ephem_priv = PrivateKey::try_from(ephem_priv_bytes.as_ref()).unwrap();
        let ephem_pub = ephem_priv.to_public().unwrap();

        let remote_static_pub = PublicKey::try_from(remote_static_pub_bytes.as_ref()).unwrap();

        let initiator = true;
        let mut handshake_state = HandshakeState::init_x(
            initiator,
            prologue.as_slice(),
            static_priv,
            static_pub,
            Some(ephem_priv),
            Some(ephem_pub),
            Some(remote_static_pub),
        );

        // handshake message
        let mut noise_data = handshake_state.write_message(&payload).unwrap();
        assert_eq!(&noise_data.message, &expected_ciphertext);

        let handshake_hash = handshake_state.symmetric_state.get_handshake_hash();
        assert_eq!(&handshake_hash, exp_handshake_hash.as_slice());

        // transport message 1
        let got_transport_ct1 = noise_data
            .cipher_state
            .encrypt_with_ad(&[], &transport_payload1);
        assert_eq!(&exp_transport_ct1, &got_transport_ct1);

        // transport message 2
        let got_transport_ct2 = noise_data
            .cipher_state
            .encrypt_with_ad(&[], &trasnport_payload2);
        assert_eq!(&exp_transport_ct2, &got_transport_ct2);
    }

    #[test]
    fn test_read_message() {
        let prologue = hex::decode("50726f6c6f677565313233").unwrap();
        let handshake_message = hex::decode("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79446c15957a594079a5bdeae05d01e089fbb7cc6ea2ecfd209b941f73c9235213bc14ed87a1a4a0b164c11a5999be0f7bf1fdc3aaa6de60cb3c98302f370fdb03ea6fe2cf18324b0812663aed65fc9eafdf").unwrap();
        // The sender's public key that is sent encrypted in the handshake message.
        let expected_public_key =
            hex::decode("6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a")
                .unwrap();
        let responder_static_bytes =
            hex::decode("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")
                .unwrap();
        let expected_handshake_payload = hex::decode("4c756477696720766f6e204d69736573").unwrap();
        let expected_transport_payload1 = hex::decode("4d757272617920526f746862617264").unwrap();
        let transport_ciphertext1 =
            hex::decode("9868def631af6242aaf00c35218275832d8d022af1c67b9fc5e8ba90f4d91b").unwrap();
        let expected_transport_payload2 = hex::decode("462e20412e20486179656b").unwrap();
        let transport_ciphertext2 =
            hex::decode("9fdd2576d757f880de49b32b80abf53afec16ddc86769f0e92daff").unwrap();

        let responder_private = PrivateKey::try_from(responder_static_bytes.as_slice()).unwrap();
        let responder_public = responder_private.to_public().unwrap();

        let initiator = false;
        let mut handshake_state = HandshakeState::init_x(
            initiator,
            prologue.as_slice(),
            responder_private,
            responder_public,
            None,
            None,
            None,
        );

        // Hanshake message
        let mut noise_data = handshake_state.read_message(&handshake_message).unwrap();

        assert_eq!(&expected_handshake_payload, &noise_data.message);
        // Check that we know what the sender's public key is
        let sender_pub = handshake_state.rs.unwrap();
        assert_eq!(&expected_public_key, sender_pub.as_bytes());

        // Transport message 1
        let got_transport_payload1 = noise_data
            .cipher_state
            .decrypt_with_ad(&[], &transport_ciphertext1)
            .unwrap();
        assert_eq!(&expected_transport_payload1, &got_transport_payload1);

        // Transport message 2
        let got_transport_payload2 = noise_data
            .cipher_state
            .decrypt_with_ad(&[], &transport_ciphertext2)
            .unwrap();
        assert_eq!(&expected_transport_payload2, &got_transport_payload2);
    }
}
