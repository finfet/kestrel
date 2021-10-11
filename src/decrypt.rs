use std::convert::TryInto;
use std::io::{Read, Write};

use crate::crypto;
use crate::crypto::{chapoly_decrypt, noise_decrypt, PrivateKey, PublicKey};
use crate::errors::DecryptError;
use crate::utils::*;

const TAG_SIZE: usize = 16;

pub fn decrypt<T: Read, U: Write>(
    ciphertext: &mut T,
    plaintext: &mut U,
    recipient: &PrivateKey,
) -> Result<PublicKey, DecryptError> {
    let mut prologue = [0u8; 4];
    ciphertext.read_exact(&mut prologue)?;

    let mut handshake_message = [0u8; 128];
    ciphertext.read_exact(&mut handshake_message)?;
    let (payload_key, handshake_hash, sender_public) =
        noise_decrypt(recipient, &prologue, &handshake_message)?;

    // ikm = payload_key || handshake_hash
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&payload_key);
    ikm[32..].copy_from_slice(&handshake_hash);
    let derived_key = crypto::hkdf_extract(Some(&WREN_SALT), &ikm);

    decrypt_chunks(ciphertext, plaintext, derived_key, None)?;

    Ok(sender_public)
}

pub fn pass_decrypt<T: Read, U: Write>(
    ciphertext: &mut T,
    plaintext: &mut U,
    password: &[u8],
) -> Result<(), DecryptError> {
    let mut pass_magic_num = [0u8; 4];
    ciphertext.read_exact(&mut pass_magic_num)?;

    let mut salt = [0u8; 16];
    ciphertext.read_exact(&mut salt)?;

    let key = crypto::scrypt(password, &salt, SCRYPT_N, SCRYPT_R, SCRYPT_P);
    let aad = Some(&pass_magic_num[..]);

    decrypt_chunks(ciphertext, plaintext, key, aad)?;

    Ok(())
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

#[cfg(test)]
mod test {
    use super::{decrypt, pass_decrypt};
    use super::{PrivateKey, PublicKey};
    use crate::crypto::hash;
    use crate::encrypt::test::{
        encrypt_one_chunk, encrypt_small, encrypt_two_chunks, pass_encrypt,
    };

    #[allow(dead_code)]
    struct KeyData {
        alice_private: PrivateKey,
        alice_public: PublicKey,
        bob_private: PrivateKey,
        bob_public: PublicKey,
    }

    #[test]
    fn test_decrypt_small() {
        let expected_plaintext = b"Hello, world!";
        let key_data = get_key_data();
        let expected_sender = key_data.alice_public;
        let recipient = key_data.bob_private;
        let ciphertext = encrypt_small();
        let mut plaintext = Vec::new();
        let sender_public =
            decrypt(&mut ciphertext.as_slice(), &mut plaintext, &recipient).unwrap();

        assert_eq!(&expected_plaintext[..], plaintext.as_slice());
        assert_eq!(expected_sender.as_bytes(), sender_public.as_bytes());
    }

    #[test]
    fn test_decrypt_one_chunk() {
        let expected_hash =
            hex::decode("916b144867c340614f515c7b0e5415c74832d899c05264ded2a277a6e81d81ff")
                .unwrap();
        let key_data = get_key_data();
        let expected_sender = key_data.alice_public;
        let recipient = key_data.bob_private;
        let ciphertext = encrypt_one_chunk();
        let mut plaintext = Vec::new();
        let sender_public =
            decrypt(&mut ciphertext.as_slice(), &mut plaintext, &recipient).unwrap();
        let got_hash = hash(plaintext.as_slice());

        assert_eq!(expected_hash.as_slice(), &got_hash[..]);
        assert_eq!(expected_sender.as_bytes(), sender_public.as_bytes());
    }

    #[test]
    fn test_decrypt_two_chunks() {
        let expected_hash =
            hex::decode("6cb0ccb39028c57dd7db638d27c88fd1acc1794c8582fefe0949c091a2035ac7")
                .unwrap();
        let key_data = get_key_data();
        let expected_sender = key_data.alice_public;
        let recipient = key_data.bob_private;
        let ciphertext = encrypt_two_chunks();
        let mut plaintext = Vec::new();
        let sender_public =
            decrypt(&mut ciphertext.as_slice(), &mut plaintext, &recipient).unwrap();
        let got_hash = hash(plaintext.as_slice());

        assert_eq!(expected_hash.as_slice(), &got_hash[..]);
        assert_eq!(expected_sender.as_bytes(), sender_public.as_bytes());
    }

    #[test]
    fn test_pass_decrypt() {
        let expected_pt = b"Be sure to drink your Ovaltine";
        let pass = b"hackme";

        let ciphertext = pass_encrypt();
        let mut plaintext = Vec::new();
        pass_decrypt(&mut ciphertext.as_slice(), &mut plaintext, pass).unwrap();

        assert_eq!(&expected_pt[..], plaintext.as_slice());
    }

    fn get_key_data() -> KeyData {
        let alice_private =
            hex::decode("46acb4ad2a6ffb9d70245798634ad0d5caf7a9738e5f3b60905dee7a7b973bd5")
                .unwrap();
        let alice_private = PrivateKey::from(alice_private.as_slice());
        let alice_public =
            hex::decode("3cf3637b4dfdc4596544a936b3983fca09324505f39568d4b8537bc01a92cf6d")
                .unwrap();
        let alice_public = PublicKey::from(alice_public.as_slice());

        let bob_private =
            hex::decode("461299525a53333e8597a2b065703ec751356f8462d2704e630c108037567bd4")
                .unwrap();
        let bob_private = PrivateKey::from(bob_private.as_slice());
        let bob_public =
            hex::decode("98459724b39e6b9e90b60d214df2887093e224b163714e07e527a4d37edc2d03")
                .unwrap();
        let bob_public = PublicKey::from(bob_public.as_slice());

        KeyData {
            alice_private,
            alice_public,
            bob_private,
            bob_public,
        }
    }
}
