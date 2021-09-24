use std::io::{Read, Write};

use crate::crypto::errors::DecryptError;
use crate::crypto::{PrivateKey, PublicKey};

pub fn decrypt<T: Read, U: Write>(
    ciphertext: &mut T,
    plaintext: &mut U,
    recipient: &PrivateKey,
) -> Result<PublicKey, DecryptError> {
    todo!()
}
