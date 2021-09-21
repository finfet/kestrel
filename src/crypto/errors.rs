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
    UnexpectedData,
    IOError(std::io::Error),
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EncryptError::UnexpectedData => write!(f, "Expected end of stream. Found extra data."),
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
            EncryptError::UnexpectedData => None,
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
