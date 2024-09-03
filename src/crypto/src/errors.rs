// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

//! Library Errors

use std::error::Error;

#[derive(Debug)]
pub struct ChaPolyDecryptError(String);

impl ChaPolyDecryptError {
    pub fn new(msg: &str) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for ChaPolyDecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl Error for ChaPolyDecryptError {}

#[derive(Debug)]
pub enum EncryptError {
    UnexpectedData,
    IORead(std::io::Error),
    IOWrite(std::io::Error),
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EncryptError::UnexpectedData => write!(f, "Expected end of stream. Found extra data."),
            EncryptError::IORead(_) => write!(f, "Plaintext read failed"),
            EncryptError::IOWrite(_) => write!(f, "Ciphertext write failed"),
        }
    }
}

impl Error for EncryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EncryptError::UnexpectedData => None,
            EncryptError::IORead(e) => Some(e),
            EncryptError::IOWrite(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub struct FileFormatError;

impl std::fmt::Display for FileFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Invalid file format.")
    }
}

impl Error for FileFormatError {}

#[derive(Debug)]
pub enum DecryptError {
    ChunkLen,
    ChaPolyDecrypt,
    UnexpectedData,
    IORead(std::io::Error),
    IOWrite(std::io::Error),
    Other(String),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DecryptError::ChunkLen => write!(f, "Chunk length is too large."),
            DecryptError::ChaPolyDecrypt => write!(f, "Decrypt failed."),
            DecryptError::UnexpectedData => write!(f, "Expected end of stream. Found extra data."),
            DecryptError::IORead(_) => write!(f, "Ciphertext read failed"),
            DecryptError::IOWrite(_) => write!(f, "Plaintext write failed"),
            DecryptError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<ChaPolyDecryptError> for DecryptError {
    fn from(_e: ChaPolyDecryptError) -> DecryptError {
        DecryptError::ChaPolyDecrypt
    }
}

impl From<FileFormatError> for DecryptError {
    fn from(e: FileFormatError) -> DecryptError {
        DecryptError::Other(e.to_string())
    }
}

impl Error for DecryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DecryptError::ChunkLen => None,
            DecryptError::ChaPolyDecrypt => None,
            DecryptError::UnexpectedData => None,
            DecryptError::IORead(e) => Some(e),
            DecryptError::IOWrite(e) => Some(e),
            DecryptError::Other(_) => None,
        }
    }
}
