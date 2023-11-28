// Copyright 2021-2023 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

use std::error::Error;

#[derive(Debug)]
pub(crate) enum KeyringError {
    ParseConfig(String),
    PublicKeyChecksum,
    PublicKeyLength,
    PrivateKeyDecrypt,
    PrivateKeyLength,
    PrivateKeyFormat,
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KeyringError::ParseConfig(s) => write!(f, "Failed to parse list of keys: {}", s),
            KeyringError::PublicKeyChecksum => write!(f, "Public key checksum did not match."),
            KeyringError::PublicKeyLength => write!(f, "Invalid public key length."),
            KeyringError::PrivateKeyDecrypt => write!(
                f,
                "Failed to unlock the private key.\nMake sure the password provided is correct."
            ),
            KeyringError::PrivateKeyLength => write!(f, "Invalid private key length."),
            KeyringError::PrivateKeyFormat => write!(f, "Unsupported private key file format."),
        }
    }
}

impl Error for KeyringError {}
