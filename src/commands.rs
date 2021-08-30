use std::convert::TryInto;

use crate::crypto;
use crate::crypto::PrivateKey;
use crate::keyring::{EncodedSk, Keyring};

use anyhow::anyhow;

#[derive(Debug)]
pub(crate) struct EncryptOptions {
    pub infile: String,
    pub to: String,
    pub from: String,
    pub outfile: Option<String>,
    pub keyring: Option<String>,
    pub pass: Option<String>,
}

#[derive(Debug)]
pub(crate) struct DecryptOptions {
    pub infile: String,
    pub to: String,
    pub outfile: Option<String>,
    pub keyring: Option<String>,
    pub pass: Option<String>,
}

pub(crate) fn encrypt(opts: EncryptOptions) -> Result<(), anyhow::Error> {
    println!("Encrypting...");
    println!("{:?}", opts);
    Ok(())
}

pub(crate) fn decrypt(opts: DecryptOptions) -> Result<(), anyhow::Error> {
    println!("Decrypting...");
    println!("{:?}", opts);
    Ok(())
}

pub(crate) fn gen_key(name: String) -> Result<(), anyhow::Error> {
    let private_key = PrivateKey::new();
    let public_key = private_key.to_public();
    let salt = crypto::gen_salt();
    let pass = confirm_password_stderr("New Password: ")?;

    let encoded_private_key = Keyring::lock_private_key(&private_key, pass.as_bytes(), salt);
    let encoded_public_key = Keyring::encode_public_key(&public_key);

    let key_config =
        Keyring::serialize_key(name.as_str(), &encoded_public_key, &encoded_private_key);

    println!();
    print!("{}", key_config);

    Ok(())
}

pub(crate) fn change_pass(private_key: String) -> Result<(), anyhow::Error> {
    let old_pass = rpassword::prompt_password_stderr("Old Password: ")?;
    let new_pass = confirm_password_stderr("New Password")?;

    let old_sk: EncodedSk = private_key
        .as_str()
        .try_into()
        .map_err(|e| anyhow!("{}", e))?;
    let sk = Keyring::unlock_private_key(&old_sk, old_pass.as_bytes())?;

    let salt = crypto::gen_salt();
    let new_sk = Keyring::lock_private_key(&sk, new_pass.as_bytes(), salt);

    println!("PrivateKey = {}", new_sk.as_ref());

    Ok(())
}

pub(crate) fn extract_pub(private_key: String) -> Result<(), anyhow::Error> {
    let pass = rpassword::prompt_password_stderr("Password: ")?;

    let esk: EncodedSk = private_key
        .as_str()
        .try_into()
        .map_err(|e| anyhow!("{}", e))?;

    let sk = Keyring::unlock_private_key(&esk, pass.as_bytes())?;

    let pk = sk.to_public();

    let epk = Keyring::encode_public_key(&pk);

    println!("PublicKey = {}", epk.as_ref());

    Ok(())
}

fn confirm_password_stderr(prompt: &str) -> Result<String, anyhow::Error> {
    let password = loop {
        let pass = rpassword::prompt_password_stderr(prompt)?;
        let confirm_pass = rpassword::prompt_password_stderr("Confirm Password: ")?;
        if pass != confirm_pass {
            eprintln!("Passwords do not match");
        } else {
            break pass;
        }
    };

    Ok(password)
}