use std::io::Cursor;
use std::io::Write;

use std::fmt::Write as FmtWrite;

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

impl AsRef<str> for EncodedSk {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

// WRN in ASCII + file format version (0x20 hex)
pub const KEY_FILE_MAGIC: [u8; 4] = [0x57, 0x52, 0x4e, 0x20];

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

    /// Encrypt a private key using ChaCha20Poly1305 with a key derived from
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
        key_data.write(&KEY_FILE_MAGIC).unwrap();
        key_data.write(&salt).unwrap();
        let derived_key = crypto::key_from_pass(password, &salt);
        let sk_ct = crypto::chapoly_encrypt(
            derived_key.as_slice(),
            0,
            &KEY_FILE_MAGIC,
            private_key.as_bytes(),
        );
        key_data.write(sk_ct.as_slice()).unwrap();

        let key_data = key_data.into_inner();
        debug_assert_eq!(key_data.len(), 68);

        let b64_string = base64::encode(key_data);
        EncodedSk(b64_string)
    }

    /// Decrypt a private key.
    fn unlock_private_key(
        locked_sk: &EncodedSk,
        password: &[u8],
    ) -> Result<PrivateKey, KeyringError> {
        let enc_sk =
            base64::decode(locked_sk.as_ref()).expect("Failed to base64 decode private key");
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
    // Public keys are 32 byte hex strings with a 4 byte SHA-256 checksum
    // appended at the end. Total of 36 bytes and 72 characters.
    pub fn encode_public_key(public_key: &PublicKey) -> EncodedPk {
        let pk = public_key.as_bytes();
        let checksum = crypto::hash(pk);
        let mut encoded = [0u8; 36];
        encoded[..32].copy_from_slice(pk);
        encoded[32..].copy_from_slice(&checksum[..4]);

        EncodedPk(hex::encode(&encoded))
    }

    fn decode_public_key(encoded_pk: &EncodedPk) -> Result<PublicKey, KeyringError> {
        let enc_pk = hex::decode(encoded_pk.as_ref()).expect("Public key hex decode failed.");
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
        let mut key_config = String::new();
        // We're unwrapping because write_str shouldn't fail unless the
        // allocator fails, which will casue a panic anyway.
        key_config.write_str("[Key]\n").unwrap();
        key_config
            .write_str(format!("Name = {}\n", name).as_str())
            .unwrap();
        key_config
            .write_str(format!("PublicKey = {}\n", public_key.as_ref()).as_str())
            .unwrap();
        key_config
            .write_str(format!("PrivateKey = {}\n", private_key.as_ref()).as_str())
            .unwrap();

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
                let name = match split_first(line, '=') {
                    Some((_, n)) => n.trim(),
                    None => {
                        return Err(KeyringError::ParseConfig(
                            "Name must be set to something".into(),
                        ))
                    }
                };

                // Restrict name to 128 bytes. Should be a minimum of 32 UTF-8
                // characters.
                if name.len() > 128 {
                    return Err(KeyringError::ParseConfig("Name is too long.".into()));
                }
                key_name = Some(name.into());
            } else if line.trim().starts_with("PublicKey") {
                let pubkey = match split_first(line, '=') {
                    Some((_, pk)) => pk.trim(),
                    None => {
                        return Err(KeyringError::ParseConfig(
                            "PublicKey must be set to something".into(),
                        ))
                    }
                };

                // Public keys are 32 byte hex strings with a
                // 4 byte SHA256 checksum appended
                if pubkey.len() != 72 || hex::decode(pubkey.as_bytes()).is_err() {
                    return Err(KeyringError::ParseConfig("Malformed public key".into()));
                }

                key_public = Some(EncodedPk(pubkey.into()));
            } else if line.trim().starts_with("PrivateKey") {
                let seckey = match split_first(line, '=') {
                    Some((_, sk)) => sk.trim(),
                    None => {
                        return Err(KeyringError::ParseConfig(
                            "PrivateKey must be set to something".into(),
                        ))
                    }
                };

                // Secret keys are 68 bytes of standard base64
                // making keys 92 keys long
                if seckey.len() != 92 || base64::decode(&seckey).is_err() {
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

fn split_first(line: &str, token: char) -> Option<(&str, &str)> {
    let mut idx = -1;
    for (i, c) in line.chars().enumerate() {
        if c == token {
            idx = i as isize;
            break;
        }
    }

    if idx == -1 {
        return None;
    }

    return Some(line.split_at((idx + 1) as usize));
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
PublicKey = 331064acb409776bf3d1fbdf225f61cd71d9281bacaccf82d59e7200144dd164578c6c98
PrivateKey = V1JOIH1TiViOMXGfWeEKgG9iuFiCaOouhnNsQTUJDO6bGWeQ/qnqZqP/8FBMsy4gQZEOB2dqzhv+fa7rj5ursn+OXuI=

[Key]
Name = Bobby Bobertson
PublicKey = e9fa25c3d6d25b640ed7672fe1e4734cc333adb2efa3adf244fbef04765cf72422af720f
";
    #[test]
    fn test_keyring_config() {
        let keyring = Keyring::new(KEYRING_INI).unwrap();
        println!("{:?}", keyring.keys);
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

        println!("private key: {}", enc_sk.as_ref());

        assert_eq!(enc_sk.as_ref().len(), 92);
    }

    #[test]
    fn test_unlock_private_key() {
        let sk = "V1JOIH1TiViOMXGfWeEKgG9iuFiCaOouhnNsQTUJDO6bGWeQ/qnqZqP/8FBMsy4gQZEOB2dqzhv+fa7rj5ursn+OXuI=";
        let encoded_sk = EncodedSk(String::from(sk));

        assert!(Keyring::unlock_private_key(&encoded_sk, b"hackme").is_ok());
        assert!(Keyring::unlock_private_key(&encoded_sk, b"badpass").is_err());

        let bad_sk = "W1JOIH1TiViOMXGfWeEKgG9iuFiCaOouhnNsQTUJDO6bGWeQ/qnqZqP/8FBMsy4gQZEOB2dqzhv+fa7rj5ursn+OXuI=";
        let bad_encoded_sk = EncodedSk(String::from(bad_sk));
        assert!(Keyring::unlock_private_key(&bad_encoded_sk, b"hackme").is_err());
    }

    #[test]
    fn test_encode_public_key() {
        let pk_bytes =
            hex::decode("331064acb409776bf3d1fbdf225f61cd71d9281bacaccf82d59e7200144dd164")
                .unwrap();
        // hash 578c6c98
        let expected = "331064acb409776bf3d1fbdf225f61cd71d9281bacaccf82d59e7200144dd164578c6c98";
        let pk = PublicKey::from(pk_bytes.as_slice());
        let got = Keyring::encode_public_key(&pk);

        println!("public key: {}", got.as_ref());

        assert_eq!(got.as_ref(), expected);
    }

    #[test]
    fn test_decode_public_key() {
        let good_public =
            "e9fa25c3d6d25b640ed7672fe1e4734cc333adb2efa3adf244fbef04765cf72422af720f";

        let encoded = EncodedPk(String::from(good_public));
        assert!(Keyring::decode_public_key(&encoded).is_ok());

        let bad_public = "f9fa25c3d6d25b640ed7672fe1e4734cc333adb2efa3adf244fbef04765cf72422af720f";
        let bad_encoded = EncodedPk(String::from(bad_public));
        assert!(Keyring::decode_public_key(&bad_encoded).is_err());
    }
}
