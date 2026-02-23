// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashMap;

use ct_codecs::{Base64, Decoder, Encoder};
use zeroize::Zeroizing;

use kestrel_crypto::{PrivateKey, PublicKey};

use crate::errors::KeyringError;

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
        let sections = keyring_parser.parse()?;
        let keys = KeyringParser::extract_keys(&sections)?;
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
// section = "[" *utf8 "]" newline *content
// content = *blanks / key-value
// key-value = 1*utf8 *WSP "=" 1*utf8 newline
// key = 1*utf8 ; must exclude "=" and newline
// value = 1*utf8 ; must exclude "=" and newline
// comment = "#"*utf8 newline
// blanks = newline / comment / WSP
// newline = [CR] LF
// utf8 = OCTET ; utf-8 encoded bytes excluding CR and LF
// ; keys in a section must be unique. For non-unique keys, the last key wins.
//
//
// Keys must have a Name and a PublicKey
struct KeyringParser {
    idx: usize,
    chars: Vec<char>,
}

pub(crate) struct Section {
    name: String,
    content: HashMap<String, String>,
}

impl Section {
    fn new(name: String, content: HashMap<String, String>) -> Section {
        Section {
            name: name,
            content: content,
        }
    }
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

    // Parse configuration data
    // The INI format is a list of sections, where each section has 0-N key
    // value pairs
    pub fn parse(&mut self) -> Result<Vec<Section>, KeyringError> {
        self.idx = 0;

        let mut sections = Vec::new();
        loop {
            let ch = match self.get_char() {
                Some(c) => c,
                None => {
                    break;
                }
            };
            if ch == '[' {
                let section = self.parse_section()?;
                sections.push(section);
            } else if ch == '#' {
                self.parse_comment();
            } else if ch == CHAR_CR || ch == CHAR_LF || ch == CHAR_SPACE || ch == CHAR_TAB {
                continue;
            } else {
                return Err(KeyringError::ParseConfig(
                    "Found invalid data in configuration file".to_string(),
                ));
            }
        }

        Ok(sections)
    }

    fn extract_keys(sections: &[Section]) -> Result<Vec<Key>, KeyringError> {
        let mut keys = Vec::new();
        for section in sections {
            if section.name.as_str() != "Key" {
                return Err(KeyringError::ParseConfig(
                    "Invalid section name. Expected 'Key'".to_string(),
                ));
            }

            let name = match section.content.get("Name") {
                Some(n) => n,
                None => {
                    return Err(KeyringError::ParseConfig(
                        "No Name defined for Key".to_string(),
                    ));
                }
            };

            let public_key = match section.content.get("PublicKey") {
                Some(pk) => KeyringParser::extract_public_key(pk.as_str())?,
                None => {
                    return Err(KeyringError::ParseConfig(
                        "No PublicKey defined for Key".to_string(),
                    ));
                }
            };

            let private_key = match section.content.get("PrivateKey") {
                Some(sk) => Some(KeyringParser::extract_private_key(sk.as_str())?),
                None => None,
            };

            keys.push(Key {
                name: name.to_owned(),
                public_key,
                private_key,
            })
        }

        Ok(keys)
    }

    fn parse_section(&mut self) -> Result<Section, KeyringError> {
        let section_name = self.parse_section_name()?;
        let section_content = self.parse_section_content()?;

        Ok(Section::new(section_name, section_content))
    }

    fn parse_section_content(&mut self) -> Result<HashMap<String, String>, KeyringError> {
        let mut content = HashMap::new();
        loop {
            let ch = match self.peek_char() {
                Some(c) => c,
                None => {
                    break;
                }
            };

            if ch == CHAR_CR || ch == CHAR_LF || ch == CHAR_SPACE || ch == CHAR_TAB {
                self.get_char();
                continue;
            } else if ch == '#' {
                self.get_char();
                self.parse_comment();
                continue;
            } else if ch == '[' {
                break;
            }

            let (key, value) = self.parse_key_value()?;
            content.insert(key, value);
        }

        Ok(content)
    }

    fn extract_public_key(value: &str) -> Result<EncodedPk, KeyringError> {
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

    fn extract_private_key(value: &str) -> Result<EncodedSk, KeyringError> {
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
        let mut name = String::new();
        loop {
            let ch = match self.get_char() {
                Some(c) => c,
                None => {
                    return Err(KeyringError::ParseConfig(
                        "Invalid section name".to_string(),
                    ));
                }
            };
            if ch == ']' || ch == CHAR_CR {
                continue;
            } else if ch == CHAR_LF {
                break;
            } else {
                name.push(ch)
            }
        }
        Ok(name)
    }

    fn parse_key_value(&mut self) -> Result<(String, String), KeyringError> {
        let mut key = String::new();
        let mut value = String::new();
        loop {
            let ch = match self.get_char() {
                Some(c) => c,
                None => {
                    return Err(KeyringError::ParseConfig("Invalid key".to_string()));
                }
            };
            if ch == CHAR_SPACE || ch == CHAR_TAB || ch == CHAR_CR {
                continue;
            } else if ch == CHAR_LF {
                break;
            } else if ch == '#' {
                self.parse_comment();
            } else if ch == '=' {
                value = self.parse_value()?;
                break;
            } else {
                key.push(ch);
            }
        }

        Ok((key, value))
    }

    fn parse_value(&mut self) -> Result<String, KeyringError> {
        let mut value = String::new();
        loop {
            let ch = match self.get_char() {
                Some(c) => c,
                None => {
                    return Err(KeyringError::ParseConfig("Invalid value".to_string()));
                }
            };
            if ch == CHAR_CR {
                continue;
            } else if ch == CHAR_LF {
                break;
            } else {
                value.push(ch);
            }
        }

        // Values can have spaces in them.
        // Only trim leading and trailing whitespace.
        value = value.trim().to_string();

        Ok(value)
    }

    fn parse_comment(&mut self) {
        loop {
            let ch = self.get_char();
            if ch.is_none() {
                return;
            }
            let ch = ch.unwrap();
            if ch == CHAR_LF {
                break;
            }
        }
    }

    fn get_char(&mut self) -> Option<char> {
        let ch = self.chars.get(self.idx).copied();
        self.idx += 1;
        ch
    }

    fn peek_char(&mut self) -> Option<char> {
        self.chars.get(self.idx).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::Keyring;
    use super::KeyringParser;
    use super::{EncodedPk, EncodedSk};
    use ct_codecs::{Decoder, Hex};
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
        let sections = parser.parse();
        assert!(sections.is_ok());
        let sections = sections.unwrap();
        assert_eq!(2, sections.len());
        let section_alice = &sections[0];
        let section_bob = &sections[1];

        assert_eq!("Key", section_alice.name.as_str());

        let alice_name = section_alice.content.get("Name");
        assert!(alice_name.is_some());
        assert_eq!("alice", alice_name.unwrap().as_str());

        let alice_pubkey = section_alice.content.get("PublicKey");
        assert!(alice_pubkey.is_some());
        assert_eq!(
            "D7ZZstGYF6okKKEV2rwoUza/tK3iUa8IMY+l5tuirmzzkEog",
            alice_pubkey.unwrap().as_str()
        );

        let alice_privkey = section_alice.content.get("PrivateKey");
        assert!(alice_privkey.is_some());
        assert_eq!(
            "ZWdrMPEp09tKN3rAutCDQTshrNqoh0MLPnEERRCm5KFxvXcTo+s/Sf2ze0fKebVsQilImvLzfIHRcJuX8kGetyAQL1VchvzHR28vFhdKeq+NY2KT",
            alice_privkey.unwrap().as_str()
        );

        assert_eq!("Key", section_bob.name.as_str());

        let bob_name = section_bob.content.get("Name");
        assert!(bob_name.is_some());
        assert_eq!("Bobby Bobertson", bob_name.unwrap().as_str());

        let bob_pubkey = section_bob.content.get("PublicKey");
        assert_eq!(
            "CT/e0R9tbBjTYUhDNnNxltT3LLWZLHwW4DCY/WHxBA8am9vP",
            bob_pubkey.unwrap().as_str()
        );

        assert!(section_bob.content.get("PrivateKey").is_none());
    }

    #[test]
    fn test_lock_private_key() {
        let sk_bytes = Hex::decode_to_vec(
            "42d010ed1797fb3187351423f164caee1ce15eb5a462cf6194457b7a736938f5",
            None,
        )
        .unwrap();

        let locked_sk = "ZWdrMHMp/2yenV64rOfAJmMGWRVGbJuUAVhzOeRYRwNPqndu4Pfkg4YXzIna9Eg58JwreHA37o49xCS0x8CWd3yRe+D2ytRXFLb67WNIwxqHJ9Fw";

        let sk = PrivateKey::try_from(sk_bytes.as_slice()).unwrap();

        let password = b"alice";
        let salt = Hex::decode_to_vec(
            "7329ff6c9e9d5eb8ace7c02663065915466c9b9401587339e45847034faa776e",
            None,
        )
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
        let pk_bytes = Hex::decode_to_vec(
            "3ad53dc25581b18af543a1e8cf4edc2b4e4e483df5a7e0d5ada53e7e4bb86374",
            None,
        )
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
