use std::io::{Read, Write};

use crate::crypto;
use crate::crypto::chapoly_encrypt;
use crate::crypto::noise::HandshakeState;
use crate::crypto::{PrivateKey, PublicKey};

use crate::crypto::errors::EncryptError;

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
) -> Result<(), EncryptError> {
    let salt = crypto::gen_salt();
    Ok(pass_encrypt_internal(
        plaintext, ciphertext, password, &salt,
    )?)
}

pub(crate) fn pass_encrypt_internal<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    password: &[u8],
    salt: &[u8],
) -> Result<(), EncryptError> {
    let key = crypto::key_from_pass(password, salt);
    let aad = Some(&PASS_FILE_MAGIC[..]);

    ciphertext.write(&PASS_FILE_MAGIC)?;
    ciphertext.write(salt)?;

    Ok(encrypt_chunks(plaintext, ciphertext, key, aad)?)
}

#[cfg(test)]
mod test {
    use super::{encrypt_internal, pass_encrypt_internal};
    use super::{PrivateKey, PublicKey};
    use crate::crypto;
    use crate::crypto::encrypt::CHUNK_SIZE;
    use std::convert::TryInto;
    use std::io::Read;

    struct KeyData {
        alice_private: PrivateKey,
        alice_public: PublicKey,
        bob_private: PrivateKey,
        bob_public: PublicKey,
    }

    #[test]
    fn test_encrypt_small() {
        let ephemeral_private =
            hex::decode("fdbc28d8f4c2a97013e460836cece7a4bdf59df0cb4b3a185146d13615884f38")
                .unwrap();
        let payload_key =
            hex::decode("a9f9ddef54d0432ec067b75aef26c3db5419ade3b016339743ca1812d89188b2")
                .unwrap();
        let key_data = get_key_data();

        let sender = PrivateKey::from(key_data.alice_private.as_bytes());
        let recipient = PublicKey::from(key_data.bob_public.as_bytes());
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

        assert_eq!(ciphertext.len(), 177);
    }

    #[test]
    fn test_encrypt_one_chunk() {
        let ephemeral_private =
            hex::decode("fdf2b46d965e4bb85d856971d657fdd6dc1fe8993f27587980e4f07f6409927f")
                .unwrap();
        let ephemeral_private = PrivateKey::from(ephemeral_private.as_slice());
        let payload_key =
            hex::decode("a300f423e416610a5dd87442f4edc21325f2b3211c4c69f0e0c541cf6cf4eca6")
                .unwrap();
        let payload_key: [u8; 32] = payload_key.as_slice().try_into().unwrap();
        let key_data = get_key_data();

        let mut plaintext = vec![0; CHUNK_SIZE];
        std::io::repeat(0x01).read_exact(&mut plaintext).unwrap();
        let mut ciphertext = Vec::new();

        encrypt_internal(
            &mut plaintext.as_slice(),
            &mut ciphertext,
            &key_data.alice_private,
            &key_data.bob_public,
            Some(&ephemeral_private),
            payload_key,
        )
        .unwrap();

        assert_eq!(ciphertext.len(), 65700);
    }

    #[test]
    fn test_encrypt_two_chuks() {
        // Plaintext greater than 64k will trigger the need for an extra chunk
        let ephemeral_private =
            hex::decode("90ecf9d1dca6ed1e6997585228513a73d4db36bd7dd7c758acb55a6d333bb2fb")
                .unwrap();
        let ephemeral_private = PrivateKey::from(ephemeral_private.as_slice());
        let payload_key =
            hex::decode("d3387376438daeb6f7543e815cbde249810e341c1ccab192025b909b9ea4ebe7")
                .unwrap();
        let payload_key: [u8; 32] = payload_key.as_slice().try_into().unwrap();
        let key_data = get_key_data();

        let mut plaintext = vec![0; CHUNK_SIZE + 1];
        std::io::repeat(0x02).read_exact(&mut plaintext).unwrap();
        let mut ciphertext = Vec::new();

        encrypt_internal(
            &mut plaintext.as_slice(),
            &mut ciphertext,
            &key_data.alice_private,
            &key_data.bob_public,
            Some(&ephemeral_private),
            payload_key,
        )
        .unwrap();

        assert_eq!(ciphertext.len(), 65733);
    }

    #[test]
    fn test_pass_encrypt() {
        let salt = hex::decode("506d95450c0a74f848185ec2105a6770").unwrap();
        let pass = b"hackme";
        let plaintext = b"Be sure to drink your Ovaltine";
        let mut pt = Vec::new();
        pt.extend_from_slice(plaintext);
        let mut ciphertext = Vec::new();

        pass_encrypt_internal(&mut pt.as_slice(), &mut ciphertext, pass, salt.as_slice()).unwrap();

        assert_eq!(ciphertext.len(), 82);
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
