// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

use crate::errors::KeyringError;

use kestrel_crypto::{PrivateKey, PublicKey};

use ct_codecs::{Base64, Decoder, Encoder};
use zeroize::Zeroizing;

const PRIVATE_KEY_VERSION: [u8; 4] = [0x65, 0x67, 0x6b, 0x30];
const MAX_NAME_SIZE: usize = 128;
const SCRYPT_N: u32 = 32768;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

const PRIVATE_KEY_CT_LEN: usize = 84;
const PUBLIC_KEY_LEN: usize = 32;

#[derive(Debug, Clone)]
pub(crate) struct EncodedPk(String);

#[derive(Debug, Clone)]
pub(crate) struct EncodedSk(String);

impl EncodedPk {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<&str> for EncodedPk {
    type Error = &'static str;

    // Decode a base64 encoded public key to make sure that it is the right
    // amount of bytes
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match Base64::decode_to_vec(s, None) {
            Ok(s) => {
                if s.len() != 36 {
                    return Err("Invalid Public Key length");
                }
            }
            Err(_) => {
                return Err("Invalid Public Key format");
            }
        }

        Ok(EncodedPk(s.into()))
    }
}

impl EncodedSk {
    pub fn as_bytes(&self) -> Vec<u8> {
        Base64::decode_to_vec(&self.0, None).expect("Invalid format for encoded Private Key")
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<&str> for EncodedSk {
    type Error = &'static str;

    // Decode a base64 encoded private key to make sure that it is the
    // right amount of bytes
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match Base64::decode_to_vec(s, None) {
            Ok(s) => {
                if s.len() != PRIVATE_KEY_CT_LEN {
                    return Err("Invalid Private Key length");
                }
            }
            Err(_) => {
                return Err("Could not decode private key");
            }
        }

        Ok(EncodedSk(s.into()))
    }
}

#[derive(Debug)]
pub(crate) struct Key {
    pub name: String,
    pub public_key: EncodedPk,
    pub private_key: Option<EncodedSk>,
}

#[derive(Debug)]
pub(crate) struct Keyring {
    keys: Vec<Key>,
}

impl Keyring {
    pub(crate) fn new(config: &str) -> Result<Keyring, KeyringError> {
        let keys = Keyring::parse_config(config)?;
        Ok(Keyring { keys })
    }

    pub(crate) fn get_key(&self, name: &str) -> Option<&Key> {
        self.keys.iter().find(|&key| key.name.as_str() == name)
    }

    pub(crate) fn get_name_from_key(&self, pk: &EncodedPk) -> Option<String> {
        for key in &self.keys {
            if key.public_key.as_str() == pk.as_str() {
                return Some(key.name.clone());
            }
        }
        None
    }

    /// Encrypt a private key using ChaCha20-Poly1305 with a key derived from
    /// a password using scrypt. The salt MUST be used only once.
    pub(crate) fn lock_private_key(
        private_key: &PrivateKey,
        password: &[u8],
        salt: [u8; 32],
    ) -> EncodedSk {
        let mut encoded_bytes = Vec::<u8>::new();

        encoded_bytes.extend_from_slice(&PRIVATE_KEY_VERSION);
        encoded_bytes.extend_from_slice(&salt);

        let key = kestrel_crypto::scrypt(password, &salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32);
        let key = Zeroizing::new(key);

        let nonce = [0u8; 12];
        let ciphertext = kestrel_crypto::chapoly_encrypt_ietf(
            &key,
            &nonce,
            private_key.as_bytes(),
            &PRIVATE_KEY_VERSION,
        );

        encoded_bytes.extend_from_slice(ciphertext.as_slice());

        let encoded_key = Base64::encode_to_string(&encoded_bytes).expect("Base64 encoding failed");
        EncodedSk(encoded_key)
    }

    /// Decrypt a private key.
    pub(crate) fn unlock_private_key(
        locked_sk: &EncodedSk,
        password: &[u8],
    ) -> Result<PrivateKey, KeyringError> {
        let key_bytes = locked_sk.as_bytes();
        let key_bytes = key_bytes.as_slice();
        if key_bytes.len() != PRIVATE_KEY_CT_LEN {
            return Err(KeyringError::PrivateKeyLength);
        }
        let version_aad = &key_bytes[..4];
        if version_aad != PRIVATE_KEY_VERSION {
            return Err(KeyringError::PrivateKeyFormat);
        }
        let salt = &key_bytes[4..36];
        let ciphertext = &key_bytes[36..84];
        let key = kestrel_crypto::scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32);
        let key = Zeroizing::new(key);

        let nonce = [0u8; 12];
        let plaintext = kestrel_crypto::chapoly_decrypt_ietf(&key, &nonce, ciphertext, version_aad)
            .map_err(|_| KeyringError::PrivateKeyDecrypt)?;
        let private_key =
            PrivateKey::try_from(plaintext.as_slice()).expect("Invalid private key length");
        Ok(private_key)
    }

    /// Encode a PublicKey
    /// Public keys are 32 bytes with a 4 byte SHA-256 checksum
    /// appended at the end. Represented as base64.
    pub(crate) fn encode_public_key(public_key: &PublicKey) -> EncodedPk {
        let pk = public_key.as_bytes();
        let checksum = kestrel_crypto::sha256(pk);
        let mut encoded = [0u8; 36];
        encoded[..32].copy_from_slice(pk);
        encoded[32..].copy_from_slice(&checksum[..4]);

        EncodedPk(Base64::encode_to_string(encoded).expect("Base64 encoding failed"))
    }

    /// Decode a PublicKey
    /// Public keys are base64 encoded with a 4 byte SHA-256 checksum appended
    pub(crate) fn decode_public_key(encoded_pk: &EncodedPk) -> Result<PublicKey, KeyringError> {
        let enc_pk =
            Base64::decode_to_vec(encoded_pk.as_str(), None).expect("Public key decode failed");
        let enc_pk_bytes = enc_pk.as_slice();
        if enc_pk_bytes.len() < PUBLIC_KEY_LEN {
            return Err(KeyringError::PublicKeyLength);
        }
        let pk = &enc_pk_bytes[..32];
        let checksum = &enc_pk_bytes[32..];

        let exp_checksum = kestrel_crypto::sha256(pk);
        let exp_checksum: &[u8] = &exp_checksum[..4];

        if checksum != exp_checksum {
            return Err(KeyringError::PublicKeyChecksum);
        }

        let public_key = PublicKey::try_from(pk).expect("Invalid public key length");

        Ok(public_key)
    }

    /// Write a `[Key]` in the keyring config file format.
    pub(crate) fn serialize_key(
        name: &str,
        public_key: &EncodedPk,
        private_key: &EncodedSk,
    ) -> String {
        let key_config = format!(
            "[Key]\nName = {}\nPublicKey = {}\nPrivateKey = {}\n",
            name,
            public_key.as_str(),
            private_key.as_str()
        );
        key_config
    }

    fn parse_config(config: &str) -> Result<Vec<Key>, KeyringError> {
        let mut keyring_parser = KeyringParser::new(config);
        let keys = keyring_parser.parse()?;
        Ok(keys)
    }

    pub fn valid_key_name(name: &str) -> bool {
        if name.is_empty() || name.len() > MAX_NAME_SIZE {
            return false;
        }
        true
    }
}

// Parser for keyring config data
//
// ABNF Grammar
//
// keyring = *blanks / *section
// section = "[" "Key" "]" newline *content
// content = *blanks / (name / public-key / private-key)
// name = "Name" *WSP "=" *WSP 1*utf8 newline
// public-key = "PublicKey" *WSP "=" *WSP base64 newline
// private-key = "PrivateKey" *WSP "=" *WSP base64 newline
// comment = "#"*utf8 newline
// base64 = 4*(ALPHA / DIGIT / "+" / "/" / "=")
// blanks = newline / comment / WSP
// newline = [CR] LF
// utf8 = OCTET ; utf-8 encoded bytes excluding CR and LF
struct KeyringParser {
    idx: usize,
    chars: Vec<char>,
}

const CHAR_CR: char = '\x0d';
const CHAR_LF: char = '\x0a';
const CHAR_TAB: char = '\t';
const CHAR_SPACE: char = ' ';

impl KeyringParser {
    // Create a new keyring parser
    pub fn new(config: &str) -> Self {
        Self {
            idx: 0,
            chars: config.chars().collect(),
        }
    }

    // Parse keyring configuration data
    pub fn parse(&mut self) -> Result<Vec<Key>, KeyringError> {
        self.idx = 0;

        let mut done = false;
        let mut keys = Vec::new();
        while !done {
            let ch = match self.get_char() {
                Ok(c) => c,
                Err(_) => {
                    done = true;
                    continue;
                }
            };
            if ch == '[' {
                let key = self.parse_section()?;
                keys.push(key);
            } else if ch == '#' {
                self.parse_comment()?;
            } else if ch == CHAR_CR || ch == CHAR_LF || ch == CHAR_SPACE || ch == CHAR_TAB {
                continue;
            } else {
                return Err(KeyringError::ParseConfig(
                    "Found invalid data in configuration file".to_string(),
                ));
            }
        }

        Ok(keys)
    }

    fn parse_section(&mut self) -> Result<Key, KeyringError> {
        let section_name = self.parse_section_name()?;
        if section_name.as_str() != "Key" {
            return Err(KeyringError::ParseConfig(
                "Invalid section name".to_string(),
            ));
        }

        let mut name = String::new();
        let mut public_key: Option<EncodedPk> = None;
        let mut private_key: Option<EncodedSk> = None;

        let mut done = false;
        while !done {
            let ch = match self.peek_char() {
                Ok(c) => c,
                Err(e) => {
                    if !name.is_empty() && public_key.is_some() {
                        // We're at the end of the file but found all of
                        // the data we need
                        done = true;
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            };

            if ch == CHAR_CR || ch == CHAR_LF || ch == CHAR_SPACE || ch == CHAR_TAB {
                self.get_char()?;
                continue;
            } else if ch == '#' {
                self.get_char()?;
                self.parse_comment()?;
                continue;
            } else if ch == '[' {
                done = true;
                continue;
            }

            let res = self.parse_key_value();
            if let Err(e) = res {
                if !name.is_empty() && public_key.is_some() {
                    done = true;
                    continue;
                } else {
                    return Err(e);
                }
            }

            let (key, value) = res.unwrap();
            let key = key.as_str();
            let value = value.as_str();

            if key == "PublicKey" {
                let pk = self.extract_public_key(value)?;
                if public_key.is_none() {
                    public_key = Some(pk);
                } else {
                    return Err(KeyringError::ParseConfig("Found too many PublicKey".into()));
                }
            } else if key == "PrivateKey" {
                let sk = self.extract_private_key(value)?;
                if private_key.is_none() {
                    private_key = Some(sk);
                } else {
                    return Err(KeyringError::ParseConfig(
                        "Found too many PrivateKey".into(),
                    ));
                }
            } else if key == "Name" {
                if value.is_empty() {
                    return Err(KeyringError::ParseConfig(
                        "Name must be set to something".into(),
                    ));
                }
                if name.is_empty() {
                    name = value.to_string();
                } else {
                    return Err(KeyringError::ParseConfig("Found too many Name".into()));
                }
            } else {
                return Err(KeyringError::ParseConfig("Found invalid data".into()));
            }
        }

        if name.is_empty() {
            return Err(KeyringError::ParseConfig("Name is required".into()));
        }

        if name.len() > MAX_NAME_SIZE {
            return Err(KeyringError::ParseConfig(
                "Name is too long. Must be < 128 chars".into(),
            ));
        }

        if public_key.is_none() {
            return Err(KeyringError::ParseConfig("PublicKey is required".into()));
        }

        Ok(Key {
            name,
            public_key: public_key.unwrap(),
            private_key,
        })
    }

    fn extract_public_key(&self, value: &str) -> Result<EncodedPk, KeyringError> {
        if value.is_empty() {
            return Err(KeyringError::ParseConfig(
                "PublicKey must be set to something".into(),
            ));
        }
        let pk: EncodedPk = value
            .try_into()
            .map_err(|_| KeyringError::ParseConfig("Malformed public key".into()))?;
        Ok(pk)
    }

    fn extract_private_key(&self, value: &str) -> Result<EncodedSk, KeyringError> {
        if value.is_empty() {
            return Err(KeyringError::ParseConfig(
                "PrivateKey must be set to something".into(),
            ));
        }
        let sk: EncodedSk = value
            .try_into()
            .map_err(|_| KeyringError::ParseConfig("Malformed private key".into()))?;

        Ok(sk)
    }

    fn parse_section_name(&mut self) -> Result<String, KeyringError> {
        let mut done = false;
        let mut name = String::new();
        while !done {
            let ch = self.get_char()?;
            if ch == ']' || ch == CHAR_CR {
                continue;
            } else if ch == CHAR_LF {
                done = true;
            } else {
                name.push(ch)
            }
        }
        Ok(name)
    }

    fn parse_key_value(&mut self) -> Result<(String, String), KeyringError> {
        let mut key = String::new();
        let mut value = String::new();
        let mut done = false;
        while !done {
            let ch = self.get_char()?;
            if ch == CHAR_SPACE || ch == CHAR_TAB || ch == CHAR_CR {
                continue;
            } else if ch == CHAR_LF {
                done = true;
            } else if ch == '#' {
                self.parse_comment()?;
            } else if ch == '=' {
                value = self.parse_value()?;
                done = true;
            } else {
                key.push(ch);
            }
        }

        Ok((key, value))
    }

    fn parse_value(&mut self) -> Result<String, KeyringError> {
        let mut value = String::new();
        let mut done = false;
        while !done {
            let ch = self.get_char()?;
            if ch == CHAR_CR {
                continue;
            } else if ch == CHAR_LF {
                done = true;
            } else {
                value.push(ch);
            }
        }

        // Values can have spaces in them.
        // Only trim leading and trailing whitespace.
        value = value.trim().to_string();

        Ok(value)
    }

    fn parse_comment(&mut self) -> Result<(), KeyringError> {
        let mut done = false;
        while !done {
            let ch = self.get_char()?;
            if ch == CHAR_LF {
                done = true;
            }
        }

        Ok(())
    }

    fn get_char(&mut self) -> Result<char, KeyringError> {
        let ch = self.chars.get(self.idx).ok_or(KeyringError::ParseConfig(
            "invalid configuration file".into(),
        ))?;
        self.idx += 1;
        Ok(*ch)
    }

    fn peek_char(&mut self) -> Result<char, KeyringError> {
        let ch = self.chars.get(self.idx).ok_or(KeyringError::ParseConfig(
            "invalid configuration file".into(),
        ))?;
        Ok(*ch)
    }
}

#[cfg(test)]
mod tests {
    use super::Keyring;
    use super::KeyringParser;
    use super::{EncodedPk, EncodedSk};
    use kestrel_crypto::{PrivateKey, PublicKey};
    use std::convert::TryInto;
    const KEYRING_INI: &str = "
[Key]
# comment lines are fine.
Name = alice
	PublicKey = D7ZZstGYF6okKKEV2rwoUza/tK3iUa8IMY+l5tuirmzzkEog
PrivateKey = ZWdrMPEp09tKN3rAutCDQTshrNqoh0MLPnEERRCm5KFxvXcTo+s/Sf2ze0fKebVsQilImvLzfIHRcJuX8kGetyAQL1VchvzHR28vFhdKeq+NY2KT

[Key]
Name = Bobby Bobertson
    PublicKey = CT/e0R9tbBjTYUhDNnNxltT3LLWZLHwW4DCY/WHxBA8am9vP
";
    #[test]
    fn test_keyring_config() {
        let keyring = Keyring::new(KEYRING_INI).unwrap();
        assert_eq!(keyring.keys.len(), 2);
    }

    #[test]
    fn test_keyring_parser() {
        let mut parser = KeyringParser::new(KEYRING_INI);
        let keys = parser.parse();
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        let alice = &keys[0];
        let bob = &keys[1];
        assert_eq!(2, keys.len());

        assert_eq!("alice", alice.name.as_str());
        assert_eq!(
            "D7ZZstGYF6okKKEV2rwoUza/tK3iUa8IMY+l5tuirmzzkEog",
            alice.public_key.as_str()
        );
        assert!(alice.private_key.is_some());
        assert_eq!("ZWdrMPEp09tKN3rAutCDQTshrNqoh0MLPnEERRCm5KFxvXcTo+s/Sf2ze0fKebVsQilImvLzfIHRcJuX8kGetyAQL1VchvzHR28vFhdKeq+NY2KT", alice.private_key.as_ref().unwrap().as_str());

        assert_eq!("Bobby Bobertson", bob.name.as_str());
        assert_eq!(
            "CT/e0R9tbBjTYUhDNnNxltT3LLWZLHwW4DCY/WHxBA8am9vP",
            bob.public_key.as_str()
        );
        assert!(bob.private_key.is_none());
    }

    #[test]
    fn test_lock_private_key() {
        let sk_bytes =
            hex::decode("42d010ed1797fb3187351423f164caee1ce15eb5a462cf6194457b7a736938f5")
                .unwrap();

        let locked_sk = "ZWdrMHMp/2yenV64rOfAJmMGWRVGbJuUAVhzOeRYRwNPqndu4Pfkg4YXzIna9Eg58JwreHA37o49xCS0x8CWd3yRe+D2ytRXFLb67WNIwxqHJ9Fw";

        let sk = PrivateKey::try_from(sk_bytes.as_slice()).unwrap();

        let password = b"alice";
        let salt = hex::decode("7329ff6c9e9d5eb8ace7c02663065915466c9b9401587339e45847034faa776e")
            .unwrap();
        let salt: [u8; 32] = salt.as_slice().try_into().unwrap();

        let enc_sk = Keyring::lock_private_key(&sk, password, salt);

        assert_eq!(enc_sk.as_str(), locked_sk);
    }

    #[test]
    fn test_unlock_private_key() {
        let sk = "ZWdrMPEp09tKN3rAutCDQTshrNqoh0MLPnEERRCm5KFxvXcTo+s/Sf2ze0fKebVsQilImvLzfIHRcJuX8kGetyAQL1VchvzHR28vFhdKeq+NY2KT";
        let encoded_sk = EncodedSk(String::from(sk));

        assert!(Keyring::unlock_private_key(&encoded_sk, b"alice").is_ok());
        assert!(Keyring::unlock_private_key(&encoded_sk, b"badpass").is_err());

        let bad_sk = "ZWdrMPEtKN3rAutCDQTshrNqoh0MLPnEERRCm5KFxvXcTo+s/Sf2ze0fKebVsQilImvLzfIHRcJuX8kGetyAQL1VchvzHR28vFhdKeq+NY2KT";
        let bad_sk2 = "ZWdrMPEp18tKN3rAutCDQTshrNqoh0MLPnEERRCm5KFxvXcTo+s/Sf2ze0fKebVsQilImvLzfIHRcJuX8kGetyAQL1VchvzHR28vFhdKeq+NY2KT";
        assert!(EncodedSk::try_from(bad_sk).is_err());
        let bad_encoded_sk = bad_sk2.try_into().unwrap();
        assert!(Keyring::unlock_private_key(&bad_encoded_sk, b"alice").is_err());
    }

    #[test]
    fn test_encode_public_key() {
        let pk_bytes =
            hex::decode("3ad53dc25581b18af543a1e8cf4edc2b4e4e483df5a7e0d5ada53e7e4bb86374")
                .unwrap();
        let expected = "OtU9wlWBsYr1Q6Hoz07cK05OSD31p+DVraU+fku4Y3R62CZl";
        let pk = PublicKey::try_from(pk_bytes.as_slice()).unwrap();
        let got = Keyring::encode_public_key(&pk);

        assert_eq!(got.as_str(), expected);
    }

    #[test]
    fn test_decode_public_key() {
        let good_public = "OtU9wlWBsYr1Q6Hoz07cK05OSD31p+DVraU+fku4Y3R62CZl";

        let encoded = EncodedPk(String::from(good_public));
        assert!(Keyring::decode_public_key(&encoded).is_ok());

        let bad_public = "PtU9wlWBsYr1Q6Hoz07cK05OSD31p+DVraU+fku4Y3R62CZl";
        let bad_encoded = EncodedPk(String::from(bad_public));
        assert!(Keyring::decode_public_key(&bad_encoded).is_err());
    }
}
