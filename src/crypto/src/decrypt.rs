// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

//! Decryption functions

use crate::errors::{DecryptError, FileFormatError};

use std::io::{Read, Write};

use crate::{chapoly_decrypt_noise, hkdf_sha256, noise_decrypt, scrypt, PrivateKey, PublicKey};
use crate::{AsymFileFormat, FileFormat, PassFileFormat};
use crate::{CHUNK_SIZE, SCRYPT_N, SCRYPT_P, SCRYPT_R};

const TAG_SIZE: usize = 16;

/// Decrypt asymmetric encrypted data from [`key_encrypt`](crate::encrypt::key_encrypt)
pub fn key_decrypt<T: Read, U: Write>(
    ciphertext: &mut T,
    plaintext: &mut U,
    recipient: &PrivateKey,
    recipient_public: &PublicKey,
    file_format: AsymFileFormat,
) -> Result<PublicKey, DecryptError> {
    if file_format != AsymFileFormat::V1 {
        return Err(DecryptError::Other(
            "File format not supported. This may be your plaintext.".into(),
        ));
    }

    let mut prologue = [0u8; 4];
    ciphertext.read_exact(&mut prologue).map_err(read_err)?;
    let file_format = valid_file_format(&prologue)?;
    if file_format == FileFormat::PassV1 {
        return Err(DecryptError::Other(
            "This is a password encrypted file. Try password decrypt instread.".into(),
        ));
    }

    let mut handshake_message = [0u8; 128];
    ciphertext
        .read_exact(&mut handshake_message)
        .map_err(read_err)?;

    let noise_message = noise_decrypt(recipient, recipient_public, &prologue, &handshake_message)?;

    let file_encryption_key = hkdf_sha256(
        &[],
        &noise_message.payload_key,
        &noise_message.handshake_hash,
        32,
    );
    let file_encryption_key: [u8; 32] = file_encryption_key.as_slice().try_into().unwrap();

    decrypt_chunks(ciphertext, plaintext, file_encryption_key, &[], CHUNK_SIZE)?;

    let public_key = noise_message.public_key;

    Ok(public_key)
}

/// Decrypt encrypted data from [`pass_encrypt`](crate::encrypt::pass_encrypt)
pub fn pass_decrypt<T: Read, U: Write>(
    ciphertext: &mut T,
    plaintext: &mut U,
    password: &[u8],
    file_format: PassFileFormat,
) -> Result<(), DecryptError> {
    if file_format != PassFileFormat::V1 {
        return Err(DecryptError::Other(
            "File format not supported. This may be your plaintext.".into(),
        ));
    }

    let mut pass_magic_num = [0u8; 4];
    ciphertext
        .read_exact(&mut pass_magic_num)
        .map_err(read_err)?;
    let file_format = valid_file_format(&pass_magic_num)?;
    if file_format == FileFormat::AsymV1 {
        return Err(DecryptError::Other(
            "This is a key encrypted file. Try decrypt instread.".into(),
        ));
    }

    let mut salt = [0u8; 32];
    ciphertext.read_exact(&mut salt).map_err(read_err)?;

    let key = scrypt(password, &salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32);
    let key: [u8; 32] = key.as_slice().try_into().unwrap();
    let aad = &pass_magic_num[..];

    decrypt_chunks(ciphertext, plaintext, key, aad, CHUNK_SIZE)?;

    Ok(())
}

/// Chunked file decryption of data from [`encrypt_chunks`](crate::encrypt::encrypt_chunks)
/// Chunk size must be less than (2^32 - 16) bytes on 32bit systems.
/// 64KiB is a good choice.
///
/// A file will be created at the specified plaintext path if a path is
/// specified. plaintext_sink and plaintext_path are mutually exclusive. If
/// both are supplied, path is used.
fn decrypt_chunks<T: Read, U: Write>(
    ciphertext: &mut T,
    plaintext: &mut U,
    key: [u8; 32],
    aad: &[u8],
    chunk_size: u32,
) -> Result<(), DecryptError> {
    let mut chunk_number: u64 = 0;
    let mut done = false;
    let cs: usize = chunk_size.try_into().unwrap();
    let mut buffer = vec![0; cs + TAG_SIZE];
    let mut auth_data = vec![0u8; aad.len() + 8];

    loop {
        let mut chunk_header = [0u8; 16];
        ciphertext.read_exact(&mut chunk_header).map_err(read_err)?;
        let last_chunk_indicator_bytes: [u8; 4] = chunk_header[8..12].try_into().unwrap();
        let ciphertext_length_bytes: [u8; 4] = chunk_header[12..].try_into().unwrap();
        let last_chunk_indicator = u32::from_be_bytes(last_chunk_indicator_bytes);
        let ciphertext_length = u32::from_be_bytes(ciphertext_length_bytes);
        if ciphertext_length > chunk_size {
            return Err(DecryptError::ChunkLen);
        }

        let ct_len: usize = ciphertext_length.try_into().unwrap();
        ciphertext
            .read_exact(&mut buffer[..ct_len + TAG_SIZE])
            .map_err(read_err)?;

        let aad_len = aad.len();
        auth_data[..aad_len].copy_from_slice(aad);
        auth_data[aad_len..aad_len + 4].copy_from_slice(&last_chunk_indicator_bytes);
        auth_data[aad_len + 4..].copy_from_slice(&ciphertext_length_bytes);

        let ct = &buffer[..ct_len + TAG_SIZE];
        let pt_chunk = chapoly_decrypt_noise(&key, chunk_number, auth_data.as_slice(), ct)?;

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
            let check = ciphertext.read(&mut [0u8; 1]).map_err(read_err)?;
            if check != 0 {
                // We're supposed to be at the end of the file but we found
                // extra data.
                return Err(DecryptError::UnexpectedData);
            }
        }

        plaintext
            .write_all(pt_chunk.as_slice())
            .map_err(write_err)?;
        plaintext.flush().map_err(write_err)?;

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

/// Check if the given data conforms to one of the [`FileFormat`] types.
pub fn valid_file_format(header: &[u8]) -> Result<FileFormat, FileFormatError> {
    let asym_v1 = [0x65, 0x67, 0x6b, 0x10];
    let pass_v1 = [0x65, 0x67, 0x6b, 0x20];

    if header == asym_v1 {
        return Ok(FileFormat::AsymV1);
    } else if header == pass_v1 {
        return Ok(FileFormat::PassV1);
    }

    Err(FileFormatError)
}

fn read_err(err: std::io::Error) -> DecryptError {
    use std::io::ErrorKind;

    match err.kind() {
        ErrorKind::UnexpectedEof => DecryptError::IORead(std::io::Error::new(
            ErrorKind::Other,
            "Did not read enough data.",
        )),
        _ => DecryptError::IORead(err),
    }
}

fn write_err(err: std::io::Error) -> DecryptError {
    DecryptError::IOWrite(err)
}

#[cfg(test)]
mod tests {
    use super::CHUNK_SIZE;
    use super::{key_decrypt, pass_decrypt};
    use super::{PrivateKey, PublicKey};
    use crate::encrypt::{key_encrypt, pass_encrypt};
    use crate::sha256;
    use crate::{AsymFileFormat, PassFileFormat};
    use std::io::Read;

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
        let recipient_public = key_data.bob_public;
        let ciphertext = encrypt_small_util();
        let mut plaintext = Vec::new();
        let sender_public = key_decrypt(
            &mut ciphertext.as_slice(),
            &mut plaintext,
            &recipient,
            &recipient_public,
            AsymFileFormat::V1,
        )
        .unwrap();

        assert_eq!(&expected_plaintext[..], plaintext.as_slice());
        assert_eq!(expected_sender.as_bytes(), sender_public.as_bytes());
    }

    fn encrypt_small_util() -> Vec<u8> {
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
    fn test_decrypt_one_chunk() {
        let expected_hash =
            hex::decode("916b144867c340614f515c7b0e5415c74832d899c05264ded2a277a6e81d81ff")
                .unwrap();
        let key_data = get_key_data();
        let expected_sender = key_data.alice_public;
        let recipient = key_data.bob_private;
        let recipient_public = key_data.bob_public;
        let ciphertext = encrypt_one_chunk();
        let mut plaintext = Vec::new();
        let sender_public = key_decrypt(
            &mut ciphertext.as_slice(),
            &mut plaintext,
            &recipient,
            &recipient_public,
            AsymFileFormat::V1,
        )
        .unwrap();
        let got_hash = sha256(plaintext.as_slice());

        assert_eq!(expected_hash.as_slice(), &got_hash[..]);
        assert_eq!(expected_sender.as_bytes(), sender_public.as_bytes());
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
    fn test_decrypt_two_chunks() {
        let expected_hash =
            hex::decode("6cb0ccb39028c57dd7db638d27c88fd1acc1794c8582fefe0949c091a2035ac7")
                .unwrap();
        let key_data = get_key_data();
        let expected_sender = key_data.alice_public;
        let recipient = key_data.bob_private;
        let recipient_public = key_data.bob_public;
        let ciphertext = encrypt_two_chunks();
        let mut plaintext = Vec::new();
        let sender_public = key_decrypt(
            &mut ciphertext.as_slice(),
            &mut plaintext,
            &recipient,
            &recipient_public,
            AsymFileFormat::V1,
        )
        .unwrap();
        let got_hash = sha256(plaintext.as_slice());

        assert_eq!(expected_hash.as_slice(), &got_hash[..]);
        assert_eq!(expected_sender.as_bytes(), sender_public.as_bytes());
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
    fn test_pass_decrypt() {
        let expected_pt = b"Be sure to drink your Ovaltine";
        let pass = b"hackme";

        let ciphertext = pass_encrypt_util();
        let mut plaintext = Vec::new();
        pass_decrypt(
            &mut ciphertext.as_slice(),
            &mut plaintext,
            pass,
            PassFileFormat::V1,
        )
        .unwrap();

        assert_eq!(&expected_pt[..], plaintext.as_slice());
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
