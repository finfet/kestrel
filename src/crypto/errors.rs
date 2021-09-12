use std::error::Error;

#[derive(Debug)]
pub struct ChaPolyDecryptError;

impl std::fmt::Display for ChaPolyDecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Decrypt failed")
    }
}

impl Error for ChaPolyDecryptError {}

#[derive(Debug)]
pub enum EncryptError {
    IOError(std::io::Error),
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
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
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EncryptError::IOError(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub struct DecryptError;

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "File decryption failed")
    }
}

impl Error for DecryptError {}

#[derive(Debug)]
pub enum PassEncryptError {
    IOError(std::io::Error),
}

impl std::fmt::Display for PassEncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PassEncryptError::IOError(e) => e.fmt(f),
        }
    }
}

impl From<std::io::Error> for PassEncryptError {
    fn from(e: std::io::Error) -> PassEncryptError {
        PassEncryptError::IOError(e)
    }
}

impl Error for PassEncryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PassEncryptError::IOError(e) => Some(e),
        }
    }
}
