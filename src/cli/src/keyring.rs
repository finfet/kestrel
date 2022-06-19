// Copyright 2021-2022 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

use crate::errors::KeyringError;

use kestrel_crypto::{PrivateKey, PublicKey};
use kestrel_crypto::{SCRYPT_N_V1, SCRYPT_P_V1, SCRYPT_R_V1};

use zeroize::Zeroize;

const PRIVATE_KEY_VERSION: [u8; 2] = [0x00, 0x01];
const MAX_NAME_SIZE: usize = 128;

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
        match base64::decode(s) {
            Ok(s) => {
                if s.len() != 36 {
                    return Err("Inavlid Public Key length");
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
        base64::decode(&self.0).unwrap()
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
        match base64::decode(s) {
            Ok(s) => {
                if s.len() != 66 {
                    return Err("Invalid Private Key length");
                }
            }
            Err(_) => {
                return Err("Invalid Private Key format");
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
        for key in &self.keys {
            if key.name.as_str() == name {
                return Some(key);
            }
        }
        None
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
        salt: [u8; 16],
    ) -> EncodedSk {
        let mut encoded_bytes = Vec::<u8>::new();

        encoded_bytes.extend_from_slice(&PRIVATE_KEY_VERSION);
        encoded_bytes.extend_from_slice(&salt);

        let mut key =
            kestrel_crypto::scrypt(password, &salt, SCRYPT_N_V1, SCRYPT_R_V1, SCRYPT_P_V1, 32);

        let nonce = [0u8; 12];
        let ciphertext = kestrel_crypto::chapoly_encrypt_ietf(
            &key,
            &nonce,
            private_key.as_bytes(),
            &PRIVATE_KEY_VERSION,
        );

        key.zeroize();

        encoded_bytes.extend_from_slice(ciphertext.as_slice());

        let encoded_key = base64::encode(encoded_bytes);
        EncodedSk(encoded_key)
    }

    /// Decrypt a private key.
    pub(crate) fn unlock_private_key(
        locked_sk: &EncodedSk,
        password: &[u8],
    ) -> Result<PrivateKey, KeyringError> {
        let key_bytes = locked_sk.as_bytes();
        let key_bytes = key_bytes.as_slice();
        let version_aad = &key_bytes[..2];
        let salt = &key_bytes[2..18];
        let ciphertext = &key_bytes[18..66];
        let mut key =
            kestrel_crypto::scrypt(password, salt, SCRYPT_N_V1, SCRYPT_R_V1, SCRYPT_P_V1, 32);

        let nonce = [0u8; 12];
        let plaintext = kestrel_crypto::chapoly_decrypt_ietf(&key, &nonce, ciphertext, version_aad)
            .map_err(|_| {
                key.zeroize();
                KeyringError::PrivateKeyDecrypt
            })?;

        key.zeroize();

        Ok(PrivateKey::from(plaintext.as_slice()))
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

        EncodedPk(base64::encode(&encoded))
    }

    pub(crate) fn decode_public_key(encoded_pk: &EncodedPk) -> Result<PublicKey, KeyringError> {
        let enc_pk = base64::decode(encoded_pk.as_str()).expect("Public key hex decode failed.");
        let enc_pk_bytes = enc_pk.as_slice();
        let pk = &enc_pk_bytes[..32];
        let checksum = &enc_pk_bytes[32..];

        let exp_checksum = kestrel_crypto::sha256(pk);
        let exp_checksum: &[u8] = &exp_checksum[..4];

        if checksum != exp_checksum {
            return Err(KeyringError::PublicKeyChecksum);
        }

        Ok(PublicKey::from(pk))
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
PublicKey = Ws+jIx2H5x5UG4ZK+MFiJtq+/0zoujaEsutphJKt+QD7vTmV
PrivateKey = AAGoWKlYNGTcXPf8+hMdVCONSBZ8tk9sWg0E4IFmTCMkrxB1anR2OkYGmkU5p2alGjDjZ+1aJvupjb9vsY2Qk9du

[Key]
Name = Bobby Bobertson
PublicKey = OtU9wlWBsYr1Q6Hoz07cK05OSD31p+DVraU+fku4Y3R62CZl
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

        let locked_sk = "AAHAHs+1SPTMfglwA2Zm9sOpqtg5BaQpJL3U3aa6yjALeWv+lWsiEGFHz9ANwz8u2VALpkqrecl58zQnIrGfeKop";

        let sk = PrivateKey::from(sk_bytes.as_slice());

        let password = b"alice";
        let salt = hex::decode("c01ecfb548f4cc7e0970036666f6c3a9").unwrap();
        let salt: [u8; 16] = salt.as_slice().try_into().unwrap();

        let enc_sk = Keyring::lock_private_key(&sk, password, salt);

        assert_eq!(enc_sk.as_str(), locked_sk);
    }

    #[test]
    fn test_unlock_private_key() {
        let sk = "AAHAHs+1SPTMfglwA2Zm9sOpqtg5BaQpJL3U3aa6yjALeWv+lWsiEGFHz9ANwz8u2VALpkqrecl58zQnIrGfeKop";
        let encoded_sk = EncodedSk(String::from(sk));

        assert!(Keyring::unlock_private_key(&encoded_sk, b"alice").is_ok());
        assert!(Keyring::unlock_private_key(&encoded_sk, b"badpass").is_err());

        let bad_sk = "BAHAHs+1SPTMfglwA2Zm9sOpqtg5BaQpJL3U3aa6yjALeWv+lWsiEGFHz9ANwz8u2VALpkqrecl58zQnIrGfeKop";
        let bad_encoded_sk = EncodedSk(String::from(bad_sk));
        assert!(Keyring::unlock_private_key(&bad_encoded_sk, b"hackme").is_err());
    }

    #[test]
    fn test_encode_public_key() {
        let pk_bytes =
            hex::decode("3ad53dc25581b18af543a1e8cf4edc2b4e4e483df5a7e0d5ada53e7e4bb86374")
                .unwrap();
        let expected = "OtU9wlWBsYr1Q6Hoz07cK05OSD31p+DVraU+fku4Y3R62CZl";
        let pk = PublicKey::from(pk_bytes.as_slice());
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
