use std::io::{Read, Write};

use crate::crypto;
use crate::crypto::chapoly_encrypt;
use crate::crypto::noise::HandshakeState;
use crate::crypto::{KeyPair, PrivateKey, PublicKey};

use crate::crypto::errors::{EncryptError, PassEncryptError};

const PROLOGUE: [u8; 4] = [0x57, 0x52, 0x4e, 0x10];

const PASS_FILE_MAGIC: [u8; 4] = [0x57, 0x52, 0x4e, 0x30];

const CHUNK_SIZE: usize = 65536;
const TAG_SIZE: u32 = 16;

/// Encrypt a file. From the sender key to the recipient key.
pub fn encrypt<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    sender: &PrivateKey,
    recipient: &PublicKey,
) -> Result<(), EncryptError> {
    let payload_key = crypto::gen_key();

    encrypt_internal(plaintext, ciphertext, sender, recipient, None, payload_key)?;

    Ok(())
}

fn encrypt_internal<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    sender: &PrivateKey,
    recipient: &PublicKey,
    ephemeral: Option<&PrivateKey>,
    payload_key: [u8; 32],
) -> Result<(), EncryptError> {
    let (file_enc_key, noise_message) = noise_encrypt(sender, recipient, ephemeral, payload_key);

    ciphertext.write(&PROLOGUE)?;
    ciphertext.write(&noise_message)?;

    encrypt_chunks(plaintext, ciphertext, file_enc_key, None)?;

    Ok(())
}

/// Perform a noise handshake message. Pass None to ephemeral to generate a
/// new key pair. This is almost certainly what you want.
/// Returns the channel bound file encryption key and the noise ciphertext.
pub fn noise_encrypt(
    sender: &PrivateKey,
    recipient: &PublicKey,
    ephemeral: Option<&PrivateKey>,
    payload_key: [u8; 32],
) -> ([u8; 32], Vec<u8>) {
    let sender_keypair = sender.into();
    let ephem_keypair = ephemeral.map_or(None, |e| Some(e.into()));
    let mut handshake_state = HandshakeState::initialize(
        true,
        &PROLOGUE,
        Some(sender_keypair),
        ephem_keypair,
        Some(recipient.clone()),
        None,
    );

    // Encrypt the payload key
    let (ciphertext, _) = handshake_state.write_message(&payload_key);

    let handshake_hash = handshake_state.symmetric_state.get_handshake_hash();

    // ikm = payload_key || handshake_hash
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&payload_key);
    ikm[32..].copy_from_slice(&handshake_hash);

    let derived_key = crypto::derive_key(&ikm);

    (derived_key, ciphertext)
}

/// Chunked file encryption
/// Passing aad will include the data as the first aad bytes along with
/// the last chunk indicator and ciphertext length. This aad is used to
/// authenticate the magic header bytes for password dervied encryption
pub(crate) fn encrypt_chunks<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    key: [u8; 32],
    aad: Option<&[u8]>,
) -> Result<(), EncryptError> {
    let mut buff = vec![0; CHUNK_SIZE];
    let mut auth_data = if let Some(aad) = aad {
        // 4 last chunk indicator + 4 ciphertext size
        vec![0; aad.len() + 8]
    } else {
        vec![0; 8]
    };
    let mut done = false;
    let mut chunk_number: u64 = 0;

    let mut prev_read = plaintext.read(&mut buff)?;
    if prev_read == 0 {
        done = true;
    }
    let mut prev = buff.clone();
    loop {
        let num_read = plaintext.read(&mut buff)?;
        if num_read != 0 && done {
            return Err(EncryptError::UnexpectedData);
        } else if num_read == 0 {
            done = true;
        }
        // @@ROBUSTNESS: Confirm this check is needed.
        assert!(prev_read <= prev.len());

        let last_chunk_indicator: u32 = if done { 1 } else { 0 };
        let last_chunk_indicator_bytes = last_chunk_indicator.to_be_bytes();
        let ciphertext_length: u32 = prev_read as u32;
        let ciphertext_length_bytes = ciphertext_length.to_be_bytes();
        if let Some(aad) = aad {
            let aad_len = aad.len();
            auth_data[..aad_len].copy_from_slice(aad);
            auth_data[aad_len..aad_len + 4].copy_from_slice(&last_chunk_indicator_bytes);
            auth_data[aad_len + 4..].copy_from_slice(&ciphertext_length_bytes);
        } else {
            auth_data[..4].copy_from_slice(&last_chunk_indicator_bytes);
            auth_data[4..].copy_from_slice(&ciphertext_length_bytes);
        }

        let ct = if aad.is_some() {
            chapoly_encrypt(&key, chunk_number, &auth_data, &prev[..prev_read])
        } else {
            chapoly_encrypt(&key, chunk_number, &auth_data, &prev[..prev_read])
        };

        ciphertext.write(&chunk_number.to_be_bytes())?;
        ciphertext.write(&last_chunk_indicator_bytes)?;
        ciphertext.write(&ciphertext_length_bytes)?;
        ciphertext.write(ct.as_slice())?;

        if done {
            break;
        }

        prev = buff.clone();
        prev_read = num_read;

        // @@SECURITY: It is extremely important that chunk number increase
        // sequentially by one here. If it does not a nonce could repeat or
        // chunks could be duplicated and/or reordered.
        chunk_number += 1;
    }

    Ok(())
}

/// Encrypt a file with symmetric encryption with a key derived from a password.
pub fn pass_encrypt<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    password: &[u8],
) -> Result<(), PassEncryptError> {
    todo!()
}

#[cfg(test)]
mod test {
    use super::encrypt_internal;
    use super::{PrivateKey, PublicKey};
    use std::convert::TryInto;

    #[test]
    fn test_encrypt() {
        let sender_private =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let recipient_public =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap();
        let ephemeral_private =
            hex::decode("fdbc28d8f4c2a97013e460836cece7a4bdf59df0cb4b3a185146d13615884f38")
                .unwrap();
        let payload_key =
            hex::decode("a9f9ddef54d0432ec067b75aef26c3db5419ade3b016339743ca1812d89188b2")
                .unwrap();

        let sender = PrivateKey::from(sender_private.as_slice());
        let recipient = PublicKey::from(recipient_public.as_slice());
        let ephemeral = PrivateKey::from(ephemeral_private.as_slice());
        let payload_key: [u8; 32] = payload_key.as_slice().try_into().unwrap();

        let plaintext_data = b"Hello, world!";
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(plaintext_data);
        let mut ciphertext = Vec::new();

        encrypt_internal(
            &mut plaintext.as_slice(),
            &mut ciphertext,
            &sender,
            &recipient,
            Some(&ephemeral),
            payload_key,
        )
        .unwrap();
    }
}
