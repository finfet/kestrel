#[derive(Debug)]
pub enum KeyringError {
    ParseConfig(String),
    PubKeyChecksum,
    SecKeyDecrypt,
    KeySerialize,
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KeyringError::ParseConfig(s) => write!(f, "Failed to parse list of keys: {}", s),
            KeyringError::PubKeyChecksum => write!(f, "Public key checksum did not match"),
            KeyringError::SecKeyDecrypt => write!(
                f,
                "Failed to unlock the secret key.\nMake sure the password provided is correct"
            ),
            KeyringError::KeySerialize => write!(f, "Could not write [Key] configuration data"),
        }
    }
}
