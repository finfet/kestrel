// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

//! Encryption functions

use crate::errors::EncryptError;

use std::io::{Read, Write};

use crate::{
    chapoly_encrypt_noise, hkdf_sha256, noise_encrypt, scrypt, secure_random, PrivateKey, PublicKey,
};
use crate::{AsymFileFormat, PassFileFormat};
use crate::{CHUNK_SIZE, SCRYPT_N, SCRYPT_P, SCRYPT_R};

const PROLOGUE: [u8; 4] = [0x65, 0x67, 0x6b, 0x10];
const PASS_FILE_MAGIC: [u8; 4] = [0x65, 0x67, 0x6b, 0x20];

/// Encrypt a file from sender key to recipient key.
///
/// Passing None for ephemeral, ephemeral_public, payload_key will generate
/// fresh keys. This is almost certainly what you want. Sender and ephemeral
/// private and public keys must match.
#[allow(clippy::too_many_arguments)]
pub fn key_encrypt<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    sender: &PrivateKey,
    sender_public: &PublicKey,
    recipient: &PublicKey,
    ephemeral: Option<&PrivateKey>,
    ephemeral_public: Option<&PublicKey>,
    payload_key: Option<[u8; 32]>,
    file_format: AsymFileFormat,
) -> Result<(), EncryptError> {
    let _file_format = file_format;
    let payload_key = if let Some(pk) = payload_key {
        pk
    } else {
        secure_random(32).try_into().unwrap()
    };
    let noise_message = noise_encrypt(
        sender,
        sender_public,
        recipient,
        ephemeral,
        ephemeral_public,
        &PROLOGUE,
        &payload_key,
    );

    ciphertext.write_all(&PROLOGUE).map_err(write_err)?;
    ciphertext
        .write_all(&noise_message.ciphertext)
        .map_err(write_err)?;
    ciphertext.flush().map_err(write_err)?;

    let file_encryption_key = hkdf_sha256(&[], &payload_key, &noise_message.handshake_hash, 32);
    let file_encryption_key: [u8; 32] = file_encryption_key.as_slice().try_into().unwrap();

    encrypt_chunks(plaintext, ciphertext, file_encryption_key, &[], CHUNK_SIZE)?;

    Ok(())
}

/// Encrypt a file with symmetric encryption using a key derived from a password.
/// Salt must be a 32 byte nonce.
pub fn pass_encrypt<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    password: &[u8],
    salt: [u8; 32],
    file_format: PassFileFormat,
) -> Result<(), EncryptError> {
    let _file_format = file_format;
    let key = scrypt(password, &salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32);
    let key: [u8; 32] = key.as_slice().try_into().unwrap();
    let aad = &PASS_FILE_MAGIC[..];

    ciphertext.write_all(&PASS_FILE_MAGIC).map_err(write_err)?;
    ciphertext.write_all(&salt).map_err(write_err)?;
    ciphertext.flush().map_err(write_err)?;

    encrypt_chunks(plaintext, ciphertext, key, aad, CHUNK_SIZE)?;

    Ok(())
}

/// Chunked file encryption. Encrypt an (effectively) arbitrary amount of
/// data formatted in chunks of the specified chunk size.
/// The chunk size must be less than (2^32 - 16) bytes on 32bit systems.
/// 64KiB (65536) is a good choice.
///
/// Passing aad will include the data as the first aad bytes. The last 8 bytes
/// of the aad are the last_chunk_indicator (4 bytes) and ciphertext_length
/// (4 bytes).
///
/// Make sure to be aware of canonicalization attacks when adding aad data.
/// This is a "low level" function. You are likely better served by
/// [`key_encrypt`] or [`pass_encrypt`] which
/// use this function internally.
fn encrypt_chunks<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    key: [u8; 32],
    aad: &[u8],
    chunk_size: u32,
) -> Result<(), EncryptError> {
    let chunk_size: usize = chunk_size.try_into().unwrap();
    let mut chunk_number: u64 = 0;
    let mut done = false;
    let mut buff = vec![0; chunk_size];
    let mut auth_data = vec![0u8; aad.len() + 8];

    let mut prev_read = plaintext.read(&mut buff).map_err(read_err)?;
    if prev_read == 0 {
        done = true;
    }
    let mut prev = buff.clone();
    loop {
        let num_read = plaintext.read(&mut buff).map_err(read_err)?;
        if num_read != 0 && done {
            return Err(EncryptError::UnexpectedData);
        } else if num_read == 0 {
            done = true;
        }

        let last_chunk_indicator: u32 = if done { 1 } else { 0 };
        let last_chunk_indicator_bytes = last_chunk_indicator.to_be_bytes();
        let ciphertext_length: u32 = prev_read as u32;
        let ciphertext_length_bytes = ciphertext_length.to_be_bytes();
        let aad_len = aad.len();
        auth_data[..aad_len].copy_from_slice(aad);
        auth_data[aad_len..aad_len + 4].copy_from_slice(&last_chunk_indicator_bytes);
        auth_data[aad_len + 4..].copy_from_slice(&ciphertext_length_bytes);

        let ct = chapoly_encrypt_noise(&key, chunk_number, &auth_data, &prev[..prev_read]);

        let mut chunk_header = [0u8; 16];
        chunk_header[..8].copy_from_slice(&chunk_number.to_be_bytes());
        chunk_header[8..12].copy_from_slice(&last_chunk_indicator_bytes);
        chunk_header[12..].copy_from_slice(&ciphertext_length_bytes);

        ciphertext.write_all(&chunk_header).map_err(write_err)?;
        ciphertext.write_all(ct.as_slice()).map_err(write_err)?;
        ciphertext.flush().map_err(write_err)?;

        if done {
            break;
        }

        prev.clone_from(&buff);
        prev_read = num_read;

        // @@SECURITY: It is extremely important that chunk number increase
        // sequentially by one here. If it does not a nonce could repeat or
        // chunks could be duplicated and/or reordered.
        chunk_number += 1;
    }

    Ok(())
}

fn read_err(err: std::io::Error) -> EncryptError {
    EncryptError::IORead(err)
}

fn write_err(err: std::io::Error) -> EncryptError {
    EncryptError::IOWrite(err)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::CHUNK_SIZE;
    use super::{key_encrypt, pass_encrypt};
    use super::{PrivateKey, PublicKey};
    use crate::sha256;
    use crate::{AsymFileFormat, PassFileFormat};
    use std::convert::TryInto;
    use std::io::Read;

    #[allow(dead_code)]
    struct KeyData {
        alice_private: PrivateKey,
        alice_public: PublicKey,
        bob_private: PrivateKey,
        bob_public: PublicKey,
    }

    #[test]
    fn test_encrypt_small() {
        let ciphertext = encrypt_small();

        let expected_hash =
            hex::decode("3f3b97112e768a8fa7cce7ce90c166b6ea2de51d8868a037dfd57094ea6e77f1")
                .unwrap();
        let got_hash = sha256(ciphertext.as_slice());

        assert_eq!(ciphertext.len(), 177);
        assert_eq!(expected_hash.as_slice(), &got_hash);
    }

    fn encrypt_small() -> Vec<u8> {
        let ephemeral_private =
            hex::decode("fdbc28d8f4c2a97013e460836cece7a4bdf59df0cb4b3a185146d13615884f38")
                .unwrap();
        let payload_key =
            hex::decode("a9f9ddef54d0432ec067b75aef26c3db5419ade3b016339743ca1812d89188b2")
                .unwrap();
        let key_data = get_key_data();

        let sender = PrivateKey::from(key_data.alice_private.as_bytes());
        let sender_public = sender.to_public();
        let recipient = PublicKey::from(key_data.bob_public.as_bytes());
        let ephemeral = PrivateKey::from(ephemeral_private.as_slice());
        let ephemeral_public = ephemeral.to_public();
        let payload_key: [u8; 32] = payload_key.as_slice().try_into().unwrap();

        let plaintext_data = b"Hello, world!";
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(plaintext_data);
        let mut ciphertext = Vec::new();

        key_encrypt(
            &mut plaintext.as_slice(),
            &mut ciphertext,
            &sender,
            &sender_public,
            &recipient,
            Some(&ephemeral),
            Some(&ephemeral_public),
            Some(payload_key),
            AsymFileFormat::V1,
        )
        .unwrap();

        ciphertext
    }

    #[test]
    fn test_encrypt_one_chunk() {
        let ciphertext = encrypt_one_chunk();

        let expected_hash =
            hex::decode("3bce88bcc4d71526cd3f6567213f360a4abb138c3dffa02dc2d6f2c47a339393")
                .unwrap();
        let got_hash = sha256(ciphertext.as_slice());

        assert_eq!(ciphertext.len(), 65700);
        assert_eq!(expected_hash.as_slice(), &got_hash);
    }

    fn encrypt_one_chunk() -> Vec<u8> {
        let ephemeral_private =
            hex::decode("fdf2b46d965e4bb85d856971d657fdd6dc1fe8993f27587980e4f07f6409927f")
                .unwrap();
        let ephemeral_private = PrivateKey::from(ephemeral_private.as_slice());
        let ephemeral_public = ephemeral_private.to_public();
        let payload_key =
            hex::decode("a300f423e416610a5dd87442f4edc21325f2b3211c4c69f0e0c541cf6cf4eca6")
                .unwrap();
        let payload_key: [u8; 32] = payload_key.as_slice().try_into().unwrap();
        let key_data = get_key_data();

        let chunk_size: usize = CHUNK_SIZE.try_into().unwrap();
        let mut plaintext = vec![0; chunk_size];
        std::io::repeat(0x01).read_exact(&mut plaintext).unwrap();
        let mut ciphertext = Vec::new();

        key_encrypt(
            &mut plaintext.as_slice(),
            &mut ciphertext,
            &key_data.alice_private,
            &key_data.alice_public,
            &key_data.bob_public,
            Some(&ephemeral_private),
            Some(&ephemeral_public),
            Some(payload_key),
            AsymFileFormat::V1,
        )
        .unwrap();

        ciphertext
    }

    #[test]
    fn test_encrypt_two_chunks() {
        let ciphertext = encrypt_two_chunks();

        let expected_hash =
            hex::decode("c88c1e5cc207fa2fdbac41c8f748a9072d31e786f6d729a0982f15fb24429079")
                .unwrap();
        let got_hash = sha256(ciphertext.as_slice());

        assert_eq!(ciphertext.len(), 65733);
        assert_eq!(expected_hash.as_slice(), &got_hash);
    }

    fn encrypt_two_chunks() -> Vec<u8> {
        // Plaintext greater than 64k will trigger the need for an extra chunk
        let ephemeral_private =
            hex::decode("90ecf9d1dca6ed1e6997585228513a73d4db36bd7dd7c758acb55a6d333bb2fb")
                .unwrap();
        let ephemeral_private = PrivateKey::from(ephemeral_private.as_slice());
        let ephemeral_public = ephemeral_private.to_public();
        let payload_key =
            hex::decode("d3387376438daeb6f7543e815cbde249810e341c1ccab192025b909b9ea4ebe7")
                .unwrap();
        let payload_key: [u8; 32] = payload_key.as_slice().try_into().unwrap();
        let key_data = get_key_data();

        let chunk_size: usize = CHUNK_SIZE.try_into().unwrap();
        let mut plaintext = vec![0; chunk_size + 1];
        std::io::repeat(0x02).read_exact(&mut plaintext).unwrap();
        let mut ciphertext = Vec::new();

        key_encrypt(
            &mut plaintext.as_slice(),
            &mut ciphertext,
            &key_data.alice_private,
            &key_data.alice_public,
            &key_data.bob_public,
            Some(&ephemeral_private),
            Some(&ephemeral_public),
            Some(payload_key),
            AsymFileFormat::V1,
        )
        .unwrap();

        ciphertext
    }

    #[test]
    fn test_pass_encrypt() {
        let ciphertext = pass_encrypt_util();

        let expected_hash =
            hex::decode("bef8d086931a2be31875839474b455fb6a9bfa0fbb6669dbeb8a86e51be0c9bd")
                .unwrap();
        let got_hash = sha256(ciphertext.as_slice());

        assert_eq!(ciphertext.len(), 98);
        assert_eq!(expected_hash.as_slice(), &got_hash);
    }

    fn pass_encrypt_util() -> Vec<u8> {
        let salt = hex::decode("b3e94eb6bba5bc462aab92fd86eb9d9f939320a60ae46e690907918ef2ee3aec")
            .unwrap();
        let salt: [u8; 32] = salt.try_into().unwrap();
        let pass = b"hackme";
        let plaintext = b"Be sure to drink your Ovaltine";
        let mut pt = Vec::new();
        pt.extend_from_slice(plaintext);
        let mut ciphertext = Vec::new();

        pass_encrypt(
            &mut pt.as_slice(),
            &mut ciphertext,
            pass,
            salt,
            PassFileFormat::V1,
        )
        .unwrap();

        ciphertext
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
