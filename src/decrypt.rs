use std::convert::TryInto;
use std::io::{Read, Write};

use crate::crypto::{chapoly_decrypt, noise_decrypt, PrivateKey, PublicKey};
use crate::errors::DecryptError;

const PROLOGUE: [u8; 4] = [0x57, 0x52, 0x4e, 0x10];
const CHUNK_SIZE: usize = 65536;
const TAG_SIZE: usize = 16;

pub fn decrypt<T: Read, U: Write>(
    ciphertext: &mut T,
    plaintext: &mut U,
    recipient: &PrivateKey,
) -> Result<PublicKey, DecryptError> {
    let mut prologue = [0u8; 4];
    ciphertext.read_exact(&mut prologue)?;
    if &prologue != &PROLOGUE {
        return Err(DecryptError::FileFormat);
    }

    let mut handshake_message = [0u8; 128];
    ciphertext.read_exact(&mut handshake_message)?;
    let (key, sender_public) = noise_decrypt(recipient, &prologue, &handshake_message)?;

    decrypt_chunks(ciphertext, plaintext, key, None)?;

    Ok(sender_public)
}

pub(crate) fn decrypt_chunks<T: Read, U: Write>(
    ciphertext: &mut T,
    plaintext: &mut U,
    key: [u8; 32],
    aad: Option<&[u8]>,
) -> Result<(), DecryptError> {
    let mut chunk_number: u64 = 0;
    let mut done = false;
    let mut buffer = vec![0; CHUNK_SIZE + TAG_SIZE];
    let mut auth_data = match aad {
        Some(aad) => vec![0; aad.len() + 8],
        None => vec![0; 8],
    };

    loop {
        let mut chunk_header = [0u8; 16];
        ciphertext.read_exact(&mut chunk_header)?;
        let last_chunk_indicator_bytes: [u8; 4] = chunk_header[8..12].try_into().unwrap();
        let ciphertext_length_bytes: [u8; 4] = chunk_header[12..].try_into().unwrap();
        let last_chunk_indicator = u32::from_be_bytes(last_chunk_indicator_bytes);
        let ciphertext_length = u32::from_be_bytes(ciphertext_length_bytes);
        if ciphertext_length > CHUNK_SIZE as u32 {
            return Err(DecryptError::ChunkLen);
        }

        ciphertext.read_exact(&mut buffer[..(ciphertext_length as usize) + TAG_SIZE])?;

        match aad {
            Some(aad) => {
                let aad_len = aad.len();
                auth_data[..aad_len].copy_from_slice(aad);
                auth_data[aad_len..aad_len + 4].copy_from_slice(&last_chunk_indicator_bytes);
                auth_data[aad_len + 4..].copy_from_slice(&ciphertext_length_bytes);
            }
            None => {
                auth_data[..4].copy_from_slice(&last_chunk_indicator_bytes);
                auth_data[4..].copy_from_slice(&ciphertext_length_bytes);
            }
        }

        let ct = &buffer[..(ciphertext_length as usize) + TAG_SIZE];
        let pt_chunk = chapoly_decrypt(&key, chunk_number, auth_data.as_slice(), ct)?;

        // Here we know that our chunk is valid because we have successfully
        // decrypted. We also know that the chunk has not been duplicated or
        // reordered because we used the sequentially increasing chunk_number
        // that we we're expecting the chunk to have.
        if last_chunk_indicator == 1 {
            done = true;
            // Make sure that we're actually at the end of the file.
            // Note that this doesn't have any security implications. If this
            // check wasn't done the plaintext would still be correct. However,
            // the user should know if there is extra data appended to the
            // file.
            let check = ciphertext.read(&mut [0u8; 1])?;
            if check != 0 {
                // We're supposed to be at the end of the file but we found
                // extra data.
                return Err(DecryptError::UnexpectedData);
            }
        }

        plaintext.write_all(pt_chunk.as_slice())?;

        if done {
            break;
        }

        // @@SECURITY: It is extremely important that the chunk number increase
        // sequentially by one here. If it does not chunks can be duplicated
        // and/or reordered.
        chunk_number += 1;
    }

    Ok(())
}
