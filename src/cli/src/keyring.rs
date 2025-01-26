// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

use crate::errors::KeyringError;

use kestrel_crypto::{PrivateKey, PublicKey};

use base64ct::{Base64, Encoding};
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
        match Base64::decode_vec(s) {
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
        Base64::decode_vec(&self.0).expect("Invalid format for encoded Private Key")
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
        match Base64::decode_vec(s) {
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

        let encoded_key = Base64::encode_string(&encoded_bytes);
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

        EncodedPk(Base64::encode_string(&encoded))
    }

    /// Decode a PublicKey
    /// Public keys are base64 encoded with a 4 byte SHA-256 checksum appended
    pub(crate) fn decode_public_key(encoded_pk: &EncodedPk) -> Result<PublicKey, KeyringError> {
        let enc_pk = Base64::decode_vec(encoded_pk.as_str()).expect("Public key decode failed.");
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
        let mut keys = Vec::<Key>::new();

        let mut key_name: Option<String> = None;
        let mut key_public: Option<EncodedPk> = None;
        let mut key_private: Option<EncodedSk> = None;
        let mut key_found = false;

        for line in config.lines() {
            let mut cleaned_line = line.to_string();
            cleaned_line.retain(|c| c != '\t');
            cleaned_line = cleaned_line.trim().to_string();
            if cleaned_line.starts_with("[Key]") {
                if key_found {
                    if key_name.is_none() {
                        return Err(KeyringError::ParseConfig("Key must have a Name".into()));
                    } else if key_public.is_none() {
                        return Err(KeyringError::ParseConfig(
                            "Key must have a PublicKey".into(),
                        ));
                    } else {
                        Keyring::add_key(
                            &mut keys,
                            key_name.as_ref(),
                            key_public.as_ref(),
                            key_private.as_ref(),
                        )?;
                        key_name = None;
                        key_public = None;
                        key_private = None;
                    }
                }
                key_found = true;
                continue;
            } else if cleaned_line.starts_with("Name") {
                if !key_found {
                    return Err(KeyringError::ParseConfig(
                        "Name found outside of [Key] section".into(),
                    ));
                } else if key_name.is_some() {
                    return Err(KeyringError::ParseConfig("Duplicate Name found".into()));
                }

                let name = match cleaned_line.split_once('=') {
                    Some((_, n)) => n.trim(),
                    None => {
                        return Err(KeyringError::ParseConfig(
                            "Name must be set to something".into(),
                        ))
                    }
                };

                if !Keyring::valid_key_name(name) {
                    return Err(KeyringError::ParseConfig("Invalid Name".into()));
                }
                key_name = Some(name.into());
            } else if cleaned_line.starts_with("PublicKey") {
                if !key_found {
                    return Err(KeyringError::ParseConfig(
                        "PublicKey found outside of [Key] section".into(),
                    ));
                } else if key_public.is_some() {
                    return Err(KeyringError::ParseConfig(
                        "Duplicate PublicKey found".into(),
                    ));
                }

                let pubkey = match cleaned_line.split_once('=') {
                    Some((_, pk)) => pk.trim(),
                    None => {
                        return Err(KeyringError::ParseConfig(
                            "PublicKey must be set to something".into(),
                        ))
                    }
                };

                let encoded_pk = pubkey
                    .try_into()
                    .map_err(|_| KeyringError::ParseConfig("Malformed public key".into()))?;
                key_public = Some(encoded_pk);
            } else if cleaned_line.starts_with("PrivateKey") {
                if !key_found {
                    return Err(KeyringError::ParseConfig(
                        "PrivateKey found outside of [Key] section".into(),
                    ));
                } else if key_private.is_some() {
                    return Err(KeyringError::ParseConfig(
                        "Duplicate PrivateKey found".into(),
                    ));
                }

                let seckey = match cleaned_line.split_once('=') {
                    Some((_, sk)) => sk.trim(),
                    None => {
                        return Err(KeyringError::ParseConfig(
                            "PrivateKey must be set to something".into(),
                        ))
                    }
                };

                let encoded_sk = seckey
                    .try_into()
                    .map_err(|_| KeyringError::ParseConfig("Malformed private key".into()))?;
                key_private = Some(encoded_sk);
            } else if cleaned_line.starts_with('#') || cleaned_line.is_empty() {
                // Ignore empty lines and comments lines starting with #
                continue;
            } else {
                return Err(KeyringError::ParseConfig(
                    "Invalid data found in configuration file".into(),
                ));
            }
        }

        if !key_found {
            return Err(KeyringError::ParseConfig(
                "No keys found in configuration file".into(),
            ));
        } else {
            Keyring::add_key(
                &mut keys,
                key_name.as_ref(),
                key_public.as_ref(),
                key_private.as_ref(),
            )?;
        }

        Ok(keys)
    }

    fn add_key(
        keys: &mut Vec<Key>,
        key_name: Option<&String>,
        key_public: Option<&EncodedPk>,
        key_private: Option<&EncodedSk>,
    ) -> Result<(), KeyringError> {
        if key_name.is_none() && key_public.is_some() {
            return Err(KeyringError::ParseConfig("Key must have a Name".into()));
        } else if key_name.is_some() && key_public.is_none() {
            return Err(KeyringError::ParseConfig(
                "Key must have a PublicKey".into(),
            ));
        } else if key_name.is_none() && key_public.is_none() {
            return Err(KeyringError::ParseConfig(
                "Key must have a Name and PublicKey".into(),
            ));
        }

        for k in keys.iter() {
            if &k.name == key_name.unwrap() {
                return Err(KeyringError::ParseConfig(format!(
                    "Found duplicate name: {}",
                    &k.name
                )));
            }

            if k.public_key.as_str() == key_public.unwrap().as_str() {
                return Err(KeyringError::ParseConfig(format!(
                    "Found duplicate public key: {}",
                    k.public_key.as_str()
                )));
            }
        }

        let key = Key {
            name: key_name.unwrap().clone(),
            public_key: key_public.unwrap().clone(),
            private_key: key_private.map(|k| k.to_owned()),
        };

        keys.push(key);

        Ok(())
    }

    pub fn valid_key_name(name: &str) -> bool {
        if name.is_empty() || name.len() > MAX_NAME_SIZE {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::Keyring;
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
