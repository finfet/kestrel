// Copyright 2021-2022 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

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
            KeyringError::PublicKeyChecksum => write!(f, "Public key checksum did not match."),
            KeyringError::PrivateKeyDecrypt => write!(
                f,
                "Failed to unlock the private key.\nMake sure the password provided is correct."
            ),
        }
    }
}

impl Error for KeyringError {}
