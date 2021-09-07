use std::io::{Read, Write};

use crate::crypto::noise::HandshakeState;
use crate::crypto::{KeyPair, PrivateKey, PublicKey};

use crate::crypto::errors::EncryptError;

const PROLOGUE: [u8; 4] = [0x57, 0x52, 0x4e, 0x10];

pub fn encrypt<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    sender: &PrivateKey,
    recipient: &PublicKey,
) -> Result<(), EncryptError> {
    // call encrypt interal. // encrypt interal used because it is stateless
    // for testing.
    Ok(())
}

pub(crate) fn encrypt_internal<T: Read, U: Write>(
    plaintext: &mut T,
    ciphertext: &mut U,
    sender: &PrivateKey,
    recipient: &PublicKey,
    ephemeral: Option<&PrivateKey>,
    payload_key: [u8; 32],
) -> Result<(), EncryptError> {
    todo!()
}

/// Perform a noise handshake message. Passing None to ephemeral generates a
/// new key pair. This is probably what you want.
/// Returns the channel bound file encryption key and the noise ciphertext.
pub fn noise_encrypt(
    sender: &PrivateKey,
    recipient: &PublicKey,
    ephemeral: Option<&PrivateKey>,
    payload_key: [u8; 32],
) -> ([u8; 32], Vec<u8>) {
    let sender_keypair = sender.into();
    let ephem_keypair = ephemeral.map_or(None, |e| Some(e.into()));
    let handshake_state = HandshakeState::initialize(
        true,
        &PROLOGUE,
        Some(sender_keypair),
        ephem_keypair,
        Some(recipient.clone()),
        None,
    );

    todo!()
}
