use std::convert::TryFrom;
use std::io::Cursor;
use std::io::Write;

use crate::crypto;
use crate::crypto::{PrivateKey, PublicKey};
use crate::errors::KeyringError;

#[derive(Debug, Clone)]
pub struct EncodedPk(String);

#[derive(Debug, Clone)]
pub struct EncodedSk(String);

impl AsRef<str> for EncodedPk {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<&str> for EncodedPk {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match base64::decode_config(s, base64::URL_SAFE_NO_PAD) {
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

impl AsRef<str> for EncodedSk {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<&str> for EncodedSk {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match base64::decode_config(s, base64::URL_SAFE_NO_PAD) {
            Ok(s) => {
                if s.len() != 68 {
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

// WRN in ASCII + file format version (0x20 hex)
pub const KEY_FILE_MAGIC: [u8; 4] = [0x57, 0x52, 0x4e, 0x20];

const MAX_NAME_SIZE: usize = 128;

#[derive(Debug)]
pub struct Key {
    name: String,
    public_key: EncodedPk,
    private_key: Option<EncodedSk>,
}

#[derive(Debug)]
pub struct Keyring {
    keys: Vec<Key>,
}

impl Keyring {
    pub fn new(config: &str) -> Result<Keyring, KeyringError> {
        let keys = Keyring::parse_config(config)?;
        Ok(Keyring { keys })
    }

    /// Encrypt a private key using ChaCha20-Poly1305 with a key derived from
    /// a password using scrypt. The salt MUST be used only once.
    /// Use [gen_salt()](crate::crypto::gen_salt) to get fresh nonces.
    pub fn lock_private_key(
        private_key: &PrivateKey,
        password: &[u8],
        salt: [u8; 16],
    ) -> EncodedSk {
        let mut key_data: Cursor<Vec<u8>> = Cursor::new(Vec::new());

        // We're unwrapping here because writing to a Vec shouldn't fail
        // unless the allocator fails, which will cause a panic anyway.
        key_data.write_all(&KEY_FILE_MAGIC).unwrap();
        key_data.write_all(&salt).unwrap();
        let derived_key = crypto::key_from_pass(password, &salt);
        let sk_ct = crypto::chapoly_encrypt(
            derived_key.as_slice(),
            0,
            &KEY_FILE_MAGIC,
            private_key.as_bytes(),
        );
        key_data.write_all(sk_ct.as_slice()).unwrap();

        let key_data = key_data.into_inner();
        debug_assert_eq!(key_data.len(), 68);

        let b64_string = base64::encode_config(key_data, base64::URL_SAFE_NO_PAD);
        EncodedSk(b64_string)
    }

    /// Decrypt a private key.
    pub fn unlock_private_key(
        locked_sk: &EncodedSk,
        password: &[u8],
    ) -> Result<PrivateKey, KeyringError> {
        let enc_sk = base64::decode_config(locked_sk.as_ref(), base64::URL_SAFE_NO_PAD)
            .expect("Failed to base64 decode private key");
        assert_eq!(enc_sk.len(), 68);

        let header = &enc_sk[..4];
        let salt = &enc_sk[4..20];
        let ct = &enc_sk[20..];

        let key = crypto::key_from_pass(password, salt);

        let pt = match crypto::chapoly_decrypt(&key, 0, header, ct) {
            Ok(pt) => pt,
            Err(_) => return Err(KeyringError::PrivateKeyDecrypt),
        };

        Ok(PrivateKey::from(pt.as_slice()))
    }

    /// Encode a [PublicKey](crate::crypto::PublicKey)
    // Public keys are 32 bytes with a 4 byte SHA-256 checksum
    // appended at the end. Represented as base64 urlsafe no padding.
    pub fn encode_public_key(public_key: &PublicKey) -> EncodedPk {
        let pk = public_key.as_bytes();
        let checksum = crypto::hash(pk);
        let mut encoded = [0u8; 36];
        encoded[..32].copy_from_slice(pk);
        encoded[32..].copy_from_slice(&checksum[..4]);

        EncodedPk(base64::encode_config(&encoded, base64::URL_SAFE_NO_PAD))
    }

    fn decode_public_key(encoded_pk: &EncodedPk) -> Result<PublicKey, KeyringError> {
        let enc_pk = base64::decode_config(encoded_pk.as_ref(), base64::URL_SAFE_NO_PAD)
            .expect("Public key hex decode failed.");
        let enc_pk_bytes = enc_pk.as_slice();
        let pk = &enc_pk_bytes[..32];
        let checksum = &enc_pk_bytes[32..];

        let exp_checksum = crypto::hash(pk);
        let exp_checksum: &[u8] = &exp_checksum[..4];

        if checksum != exp_checksum {
            return Err(KeyringError::PublicKeyChecksum);
        }

        Ok(PublicKey::from(pk))
    }

    /// Write a `[Key]` in the keyring config file format.
    pub fn serialize_key(name: &str, public_key: &EncodedPk, private_key: &EncodedSk) -> String {
        let key_config = format!(
            "[Key]\nName = {}\nPublicKey = {}\nPrivateKey = {}\n",
            name,
            public_key.as_ref(),
            private_key.as_ref()
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
            if line.starts_with("[Key]") {
                if key_found {
                    Keyring::add_key(
                        &mut keys,
                        key_name.as_ref(),
                        key_public.as_ref(),
                        key_private.as_ref(),
                    )?;
                }
                key_found = true;
                continue;
            }
            if !key_found {
                continue;
            }
            if line.trim().starts_with("Name") {
                let name = match line.split_once('=') {
                    Some((_, n)) => n.trim(),
                    None => {
                        return Err(KeyringError::ParseConfig(
                            "Name must be set to something".into(),
                        ))
                    }
                };

                if name.len() > MAX_NAME_SIZE {
                    return Err(KeyringError::ParseConfig("Name is too long.".into()));
                }
                key_name = Some(name.into());
            } else if line.trim().starts_with("PublicKey") {
                let pubkey = match line.split_once('=') {
                    Some((_, pk)) => pk.trim(),
                    None => {
                        return Err(KeyringError::ParseConfig(
                            "PublicKey must be set to something".into(),
                        ))
                    }
                };

                // Public keys are 32 bytes 4 byte SHA256 checksum appended
                // represented as base64 url safe no padding
                if pubkey.len() != 48
                    || base64::decode_config(pubkey.as_bytes(), base64::URL_SAFE_NO_PAD).is_err()
                {
                    return Err(KeyringError::ParseConfig("Malformed public key".into()));
                }

                key_public = Some(EncodedPk(pubkey.into()));
            } else if line.trim().starts_with("PrivateKey") {
                let seckey = match line.split_once('=') {
                    Some((_, sk)) => sk.trim(),
                    None => {
                        return Err(KeyringError::ParseConfig(
                            "PrivateKey must be set to something".into(),
                        ))
                    }
                };

                // Secret keys are 68 bytes of base64 urlsafe nopadding
                // making keys 91 characters long
                if seckey.len() != 91
                    || base64::decode_config(&seckey, base64::URL_SAFE_NO_PAD).is_err()
                {
                    return Err(KeyringError::ParseConfig("Malformed private key".into()));
                }

                key_private = Some(EncodedSk(seckey.into()));
            }
        }

        // Add the final key to the keyring.
        if key_found {
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
        }

        let key = Key {
            name: key_name.unwrap().clone(),
            public_key: key_public.unwrap().clone(),
            private_key: key_private.map(|k| k.to_owned()),
        };

        keys.push(key);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Keyring;
    use super::{EncodedPk, EncodedSk};
    use crate::crypto;
    use crate::crypto::{PrivateKey, PublicKey};
    const KEYRING_INI: &str = "
[Key]
Name = joe
PublicKey = W_9F1DNeow5tX1Nc3eMlWVUnahQ-xfumvUKrV6KjXnWpwEhG
PrivateKey = V1JOIEMJHQLLSNmXUKZby-RezAtxTDHtoq55mKH0freNZQqcx9MeNU4Xz6pQFLzM7P-4MiJcNClgfmAWYddIz6K0v_A

[Key]
Name = Boby Bobertson
PublicKey = Uv-usAsxhFtHIgldsBawk6DG6-60qEC2cpagRJDoKxeEZ5g1
";
    #[test]
    fn test_keyring_config() {
        let keyring = Keyring::new(KEYRING_INI).unwrap();
        assert_eq!(keyring.keys.len(), 2);
    }

    #[test]
    fn test_lock_private_key() {
        let sk_bytes =
            hex::decode("c957097fe549dfcb31b08723f7d963dcd1fe79bfea71abdce1d9c3762e532ab4")
                .unwrap();

        let sk = PrivateKey::from(sk_bytes.as_slice());

        let password = b"hackme";
        let salt = crypto::gen_salt();
        let enc_sk = Keyring::lock_private_key(&sk, password, salt);

        assert_eq!(enc_sk.as_ref().len(), 91);
    }

    #[test]
    fn test_unlock_private_key() {
        let sk = "V1JOIB5AuUCsbeIf8v5ysfOoeSRefgN_zzKKa4L6EN2GHx0zucTxPe2zLQNPJyFPvwh-iXWGKH0ey_2LyzFEiRUchrs";
        let encoded_sk = EncodedSk(String::from(sk));

        assert!(Keyring::unlock_private_key(&encoded_sk, b"hackme").is_ok());
        assert!(Keyring::unlock_private_key(&encoded_sk, b"badpass").is_err());

        let bad_sk = "W1JOIB5AuUCsbeIf8v5ysfOoeSRefgN_zzKKa4L6EN2GHx0zucTxPe2zLQNPJyFPvwh-iXWGKH0ey_2LyzFEiRUchrs";
        let bad_encoded_sk = EncodedSk(String::from(bad_sk));
        assert!(Keyring::unlock_private_key(&bad_encoded_sk, b"hackme").is_err());
    }

    #[test]
    fn test_encode_public_key() {
        let pk_bytes =
            hex::decode("331064acb409776bf3d1fbdf225f61cd71d9281bacaccf82d59e7200144dd164")
                .unwrap();
        let expected = "MxBkrLQJd2vz0fvfIl9hzXHZKBusrM-C1Z5yABRN0WRXjGyY";
        let pk = PublicKey::from(pk_bytes.as_slice());
        let got = Keyring::encode_public_key(&pk);

        assert_eq!(got.as_ref(), expected);
    }

    #[test]
    fn test_decode_public_key() {
        let good_public = "Uv-usAsxhFtHIgldsBawk6DG6-60qEC2cpagRJDoKxeEZ5g1";

        let encoded = EncodedPk(String::from(good_public));
        assert!(Keyring::decode_public_key(&encoded).is_ok());

        let bad_public = "Vv-usAsxhFtHIgldsBawk6DG6-60qEC2cpagRJDoKxeEZ5g1";
        let bad_encoded = EncodedPk(String::from(bad_public));
        assert!(Keyring::decode_public_key(&bad_encoded).is_err());
    }
}
