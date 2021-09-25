use std::error::Error;

#[derive(Debug)]
pub enum KeyringError {
    ParseConfig(String),
    PublicKeyChecksum,
    PrivateKeyDecrypt,
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
        }
    }
}

impl Error for KeyringError {}

#[derive(Debug)]
pub enum EncryptError {
    UnexpectedData,
    WriteLen,
    IOError(std::io::Error),
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EncryptError::UnexpectedData => write!(f, "Expected end of stream. Found extra data."),
            EncryptError::WriteLen => write!(f, "Not enough data written"),
            EncryptError::IOError(e) => e.fmt(f),
        }
    }
}

impl From<std::io::Error> for EncryptError {
    fn from(e: std::io::Error) -> EncryptError {
        EncryptError::IOError(e)
    }
}

impl Error for EncryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EncryptError::UnexpectedData => None,
            EncryptError::WriteLen => None,
            EncryptError::IOError(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub enum DecryptError {
    FileFormat,
    HeaderLen,
    IOError(std::io::Error),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DecryptError::FileFormat => write!(f, "Unsupported file type"),
            DecryptError::HeaderLen => write!(f, "Could not read enough data to get header data"),
            DecryptError::IOError(e) => e.fmt(f),
        }
    }
}

impl From<std::io::Error> for DecryptError {
    fn from(e: std::io::Error) -> DecryptError {
        DecryptError::IOError(e)
    }
}

impl Error for DecryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DecryptError::FileFormat => None,
            DecryptError::HeaderLen => None,
            DecryptError::IOError(e) => Some(e),
        }
    }
}
