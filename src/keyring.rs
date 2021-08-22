use crate::errors::KeyringError;

use regex::bytes::Regex;

#[derive(Debug)]
pub struct Key {
    name: String,
    public_key: String,
    private_key: Option<String>,
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

    fn parse_config(config: &str) -> Result<Vec<Key>, KeyringError> {
        let mut keys = Vec::<Key>::new();

        let mut key_name: Option<String> = None;
        let mut key_public: Option<String> = None;
        let mut key_private: Option<String> = None;
        let mut keys_found: usize = 0;

        for line in config.lines() {
            if line.starts_with("[Key]") {
                keys_found += 1;
                if keys_found >= 2 {
                    Keyring::add_key(
                        &mut keys,
                        key_name.as_ref(),
                        key_public.as_ref(),
                        key_private.as_ref(),
                    )?;
                }
                continue;
            }
            if keys_found > 0 {
                if line.starts_with("Name") {
                    // @@Compatibility: The splice_once function requires rustc
                    // 1.52 or later. Consider rewriting to be compatible with
                    // lower versions.
                    let name = match line.split_once("=") {
                        Some((_, n)) => n.trim(),
                        None => {
                            return Err(KeyringError::ParseConfig(
                                "Name must be set to something".into(),
                            ))
                        }
                    };

                    if !Keyring::name_valid(name) {
                        return Err(KeyringError::ParseConfig(
                            "Name must be ASCII and < 40 characters".into(),
                        ));
                    }
                    key_name = Some(name.into());
                } else if line.starts_with("PublicKey") {
                    let pubkey = match line.split_once("=") {
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

                    key_public = Some(pubkey.into());
                } else if line.starts_with("PrivateKey") {
                    let seckey = match line.split_once("=") {
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

                    key_private = Some(seckey.into());
                }
            }
        }

        // Add the final key to the keyring.
        if keys_found > 0 {
            Keyring::add_key(
                &mut keys,
                key_name.as_ref(),
                key_public.as_ref(),
                key_private.as_ref(),
            )?;
        }

        Ok(keys)
    }

    fn name_valid(name: &str) -> bool {
        // Name must be >= 1 && <= 40 of the ascii keyboard characters
        let re = Regex::new(r"^[\x20-\x7E]{1,40}$").unwrap();
        if re.is_match(name.as_bytes()) {
            return true;
        }
        false
    }

    fn add_key(
        keys: &mut Vec<Key>,
        key_name: Option<&String>,
        key_public: Option<&String>,
        key_private: Option<&String>,
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

// Public keys are hex strings with a 4 byte SHA256 checksum
//
// Private keys are pass encrypted base64 strings. Format big endian
// [HEADER] - 20 bytes
// 4 bytes  : WRN in ASCII + Version (0x20 hex) (0x57524E20)
// 16 bytes : salt
//
// [Encrypted Plaintext] - (Overhead of 16)
// 32 bytes : ciphertext of private key
// 16 bytes : ciphertext tag

#[cfg(test)]
mod tests {
    use super::Keyring;
    const KEYRING_INI: &str = "
[Key]
Name = joe
PublicKey = 96f5ecf14bb50935eafed5266bc7da3cfd7f33ad09f8b1948d39b40e8df77ade30731249
PrivateKey = s/0Axe/eJ4KN/yK5qg0jqYNM4P0f9vff1cDtDfL6onGsqThHl4nh9M/TpT/GzhDAocvSKstrBkoSLM74PhDaDpxyHdE=

[Key]
Name = Bobby Bobertson
PublicKey = 449c64b7fbe79b98979a219d7b262daf592a1ee7273ceb4dfb88a6044cac6ae3b83f0dd4
";
    #[test]
    fn test_keyring_config() {
        let keyring = Keyring::new(KEYRING_INI).unwrap();
        println!("{:?}", keyring.keys);
    }
}
