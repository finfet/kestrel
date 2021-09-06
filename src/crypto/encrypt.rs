use std::io::{Read, Write};

use crate::crypto::{PrivateKey, PublicKey};

use crate::crypto::errors::EncryptError;

pub fn encrypt<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    sender: &PrivateKey,
    recipient: &PublicKey,
) -> Result<(), EncryptError> {
    todo!()
}
