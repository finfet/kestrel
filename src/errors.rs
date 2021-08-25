#[derive(Debug)]
pub enum KeyringError {
    ParseConfig(String),
    PublicKeyChecksum,
    PrivateKeyDecrypt,
    KeySerialize,
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KeyringError::ParseConfig(s) => write!(f, "Failed to parse list of keys: {}", s),
            KeyringError::PublicKeyChecksum => write!(f, "Public key checksum did not match"),
            KeyringError::PrivateKeyDecrypt => write!(
                f,
                "Failed to unlock the private key.\nMake sure the password provided is correct"
            ),
            KeyringError::KeySerialize => write!(f, "Could not write [Key] configuration data"),
        }
    }
}
