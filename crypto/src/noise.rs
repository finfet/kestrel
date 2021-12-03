// Copyright 2021 Kyle Schreiber
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;

use crate::errors::ChaPolyDecryptError;
use crate::{
    chapoly_decrypt, chapoly_encrypt, hash, noise_hkdf, x25519, KeyPair, PrivateKey, PublicKey,
};

const HASH_LEN: usize = 32;
const DH_LEN: usize = 32;

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
    key: Option<[u8; 32]>,
    nonce: u64,
}

pub struct SymmetricState {
    cipher_state: CipherState,
    chaining_key: [u8; HASH_LEN],
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

impl CipherState {
    pub fn new() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    pub fn initialize_key(&mut self, key: Option<[u8; 32]>) {
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
        let ciphertext = chapoly_encrypt(key, nonce, ad, plaintext);
        self.set_nonce(nonce + 1);
        ciphertext
    }

    pub fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ChaPolyDecryptError> {
        let key = self
            .key
            .as_ref()
            .expect("X pattern must have a key initialized");
        let nonce = self.nonce;
        let plaintext = chapoly_decrypt(key, nonce, ad, ciphertext)?;
        self.set_nonce(nonce + 1);
        Ok(plaintext)
    }

    #[allow(dead_code)]
    pub fn rekey(&mut self) {
        let pt = [0u8; 32];
        let key = self.key.unwrap();
        let gen_key = chapoly_encrypt(&key, u64::MAX, &[], &pt);
        let mut key = [0u8; 32];
        key.copy_from_slice(&gen_key[..32]);
        self.key = Some(key);
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

    #[allow(dead_code)]
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

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ChaPolyDecryptError> {
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

impl HandshakeState {
    /// Initialize a handshake state.
    /// When sending a message (initiator == true): s and rs are required, and
    /// e is optional.
    /// When receiving a message (initiator == false): s is required.
    pub fn initialize(
        initiator: bool,
        prologue: &[u8],
        s: Option<KeyPair>,
        e: Option<KeyPair>,
        rs: Option<PublicKey>,
        re: Option<PublicKey>,
    ) -> Self {
        let mut symmetric_state = SymmetricState::new("Noise_X_25519_ChaChaPoly_SHA256");
        symmetric_state.mix_hash(prologue);

        // Public key mixing here is hardcoded for the X pattern.
        assert!(s.is_some());
        if initiator {
            assert!(rs.is_some());
            let rs_public_key = rs.as_ref().unwrap();
            symmetric_state.mix_hash(rs_public_key.as_bytes());
        } else {
            let s_pair = s.as_ref().unwrap();

            symmetric_state.mix_hash(s_pair.public_key.as_bytes());
        }

        let mut message_patterns: VecDeque<Vec<Token>> = VecDeque::new();
        // X pattern
        let pattern = vec![Token::E, Token::ES, Token::S, Token::SS];
        message_patterns.push_back(pattern);
        Self {
            symmetric_state,
            s,
            e,
            rs,
            re,
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

    pub fn write_message(&mut self, payload: &[u8]) -> (Vec<u8>, CipherState) {
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
                        let ephem_public_key = ephem_private_key.to_public();
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
                    self.symmetric_state.mix_key(&x25519(&e.private_key, rs));
                }
                Token::SE => {
                    unimplemented!("SE not used in the X pattern");
                }
                Token::SS => {
                    let s = self.s.as_ref().unwrap();
                    let rs = self.rs.as_ref().unwrap();
                    self.symmetric_state.mix_key(&x25519(&s.private_key, rs));
                }
            }
        }

        let enc_payload = self.symmetric_state.encrypt_and_hash(payload);
        message_buffer.extend_from_slice(enc_payload.as_slice());

        // X pattern is one way so we don't need the second cipher state
        let (cipher_state, _) = self.symmetric_state.split();

        (message_buffer, cipher_state)
    }

    pub fn read_message(
        &mut self,
        message: &[u8],
    ) -> Result<(Vec<u8>, CipherState), ChaPolyDecryptError> {
        let message_pattern = self
            .message_patterns
            .pop_front()
            .expect("X pattern consists of a single message");
        let mut msgidx: usize = 0;
        for pattern in message_pattern {
            match pattern {
                Token::E => {
                    let remote_ephem_bytes = &message[msgidx..(msgidx + DH_LEN)];
                    let re = PublicKey::from(remote_ephem_bytes);
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

                    let rs = PublicKey::from(rs_bytes.as_ref());
                    self.rs = Some(rs);
                }
                Token::EE => {
                    unimplemented!("EE not used in the X pattern")
                }
                Token::ES => {
                    // In the X scheme, we can't be an initiator while reading
                    // a message
                    debug_assert!(!self.initiator);
                    let s = self.s.as_ref().unwrap();
                    let re = self.re.as_ref().unwrap();
                    self.symmetric_state.mix_key(&x25519(&s.private_key, re));
                }
                Token::SE => {
                    unimplemented!("SE not used in the X pattern")
                }
                Token::SS => {
                    let s = self.s.as_ref().unwrap();
                    let rs = self.rs.as_ref().unwrap();
                    self.symmetric_state.mix_key(&x25519(&s.private_key, rs));
                }
            }
        }

        let dec_payload_buffer = self.symmetric_state.decrypt_and_hash(&message[msgidx..])?;

        // X pattern is one way so we don't need the second cipher state
        let (cipher_state, _) = self.symmetric_state.split();

        Ok((dec_payload_buffer, cipher_state))
    }
}

#[cfg(test)]
mod test {
    use super::HandshakeState;
    use super::{KeyPair, PrivateKey, PublicKey};

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

        let static_priv = PrivateKey::from(initiator_priv_bytes.as_ref());
        let static_pub = static_priv.to_public();
        let static_pair = KeyPair {
            private_key: static_priv,
            public_key: static_pub,
        };

        let ephem_priv = PrivateKey::from(ephem_priv_bytes.as_ref());
        let ephem_pub = ephem_priv.to_public();
        let ephem_pair = KeyPair {
            private_key: ephem_priv,
            public_key: ephem_pub,
        };

        let remote_static_pub = PublicKey::from(remote_static_pub_bytes.as_ref());

        let initiator = true;
        let mut handshake_state = HandshakeState::initialize(
            initiator,
            prologue.as_slice(),
            Some(static_pair),
            Some(ephem_pair),
            Some(remote_static_pub),
            None,
        );

        // handshake message
        let (handshake_buffer, mut cipherstate) = handshake_state.write_message(&payload);
        assert_eq!(&handshake_buffer, &expected_ciphertext);

        let handshake_hash = handshake_state.symmetric_state.get_handshake_hash();
        assert_eq!(&handshake_hash, exp_handshake_hash.as_slice());

        // transport message 1
        let got_transport_ct1 = cipherstate.encrypt_with_ad(&[], &transport_payload1);
        assert_eq!(&exp_transport_ct1, &got_transport_ct1);

        // transport message 2
        let got_transport_ct2 = cipherstate.encrypt_with_ad(&[], &trasnport_payload2);
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

        let responder_private = PrivateKey::from(responder_static_bytes.as_slice());
        let responder_public = responder_private.to_public();
        let responder_pair = KeyPair {
            private_key: responder_private,
            public_key: responder_public,
        };

        let initiator = false;
        let mut handshake_state = HandshakeState::initialize(
            initiator,
            prologue.as_slice(),
            Some(responder_pair),
            None,
            None,
            None,
        );

        // Hanshake message
        let (got_handshake_payload, mut cipherstate) = handshake_state
            .read_message(&handshake_message[..])
            .unwrap();

        assert_eq!(&expected_handshake_payload[..], &got_handshake_payload[..]);
        // Check that we know what the sender's public key is
        let sender_pub = handshake_state.rs.unwrap();
        assert_eq!(&expected_public_key[..], sender_pub.as_bytes());

        // Transport message 1
        let got_transport_payload1 = cipherstate
            .decrypt_with_ad(&[], &transport_ciphertext1[..])
            .unwrap();
        assert_eq!(
            &expected_transport_payload1[..],
            &got_transport_payload1[..]
        );

        // Transport message 2
        let got_transport_payload2 = cipherstate
            .decrypt_with_ad(&[], &transport_ciphertext2[..])
            .unwrap();
        assert_eq!(
            &expected_transport_payload2[..],
            &got_transport_payload2[..]
        );
    }
}
