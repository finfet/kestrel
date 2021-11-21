/*
Copyright 2021 Kyle Schreiber

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
