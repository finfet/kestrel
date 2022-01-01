// Copyright 2021-2022 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

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
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EncryptError::UnexpectedData => None,
            EncryptError::IOError(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub enum DecryptError {
    ChunkLen,
    ChaPolyDecrypt,
    UnexpectedData,
    IOError(std::io::Error),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DecryptError::ChunkLen => write!(f, "Chunk length is too large."),
            DecryptError::ChaPolyDecrypt => write!(
                f,
                "Decrypt failed. Check key used. File may have been modified."
            ),
            DecryptError::UnexpectedData => write!(f, "Expected end of stream. Found extra data."),
            DecryptError::IOError(e) => e.fmt(f),
        }
    }
}

impl From<std::io::Error> for DecryptError {
    fn from(e: std::io::Error) -> DecryptError {
        DecryptError::IOError(e)
    }
}

impl From<ChaPolyDecryptError> for DecryptError {
    fn from(_e: ChaPolyDecryptError) -> DecryptError {
        DecryptError::ChaPolyDecrypt
    }
}

impl Error for DecryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DecryptError::ChunkLen => None,
            DecryptError::ChaPolyDecrypt => None,
            DecryptError::UnexpectedData => None,
            DecryptError::IOError(e) => Some(e),
        }
    }
}
