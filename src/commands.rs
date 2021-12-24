// Copyright 2021 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

use crate::keyring::{EncodedSk, Keyring};

use std::convert::TryInto;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use kestrel_crypto::encrypt::{PASS_FILE_MAGIC, PROLOGUE};
use kestrel_crypto::PrivateKey;
use kestrel_crypto::{decrypt, encrypt};

#[derive(Debug)]
pub(crate) enum KeyCommand {
    Generate(String),
    ChangePass(String),
    ExtractPub(String),
}

pub(crate) enum PasswordCommand {
    Encrypt(PasswordOptions),
    Decrypt(PasswordOptions),
}

#[derive(Debug)]
pub(crate) struct EncryptOptions {
    pub infile: String,
    pub to: String,
    pub from: String,
    pub outfile: Option<String>,
    pub keyring: Option<String>,
}

#[derive(Debug)]
pub(crate) struct DecryptOptions {
    pub infile: String,
    pub to: String,
    pub outfile: Option<String>,
    pub keyring: Option<String>,
}

#[derive(Debug)]
pub(crate) struct PasswordOptions {
    pub infile: String,
    pub outfile: Option<String>,
}

pub(crate) fn encrypt(opts: EncryptOptions) -> Result<(), anyhow::Error> {
    let infile = opts.infile;
    let to = opts.to;
    let from = opts.from;
    let outfile = opts.outfile;
    let keyring = opts.keyring;

    let infile_path = PathBuf::from(infile);
    if !infile_path.exists() {
        return Err(anyhow!(
            "Input file '{}' does not exist",
            extract_filename(infile_path.file_name())
        ));
    }
    let outfile_path = calculate_output_path(
        &infile_path,
        outfile.as_ref(),
        ExtensionAction::AddExtension,
    )?;
    let outfile_path = match outfile_path {
        Some(o) => o,
        None => return Ok(()), // The user didn't want to overwrite the file.
    };

    let keyring = open_keyring(keyring)?;
    let recipient_key = keyring.get_key(&to);
    if recipient_key.is_none() {
        return Err(anyhow!("Recipient key '{}' not found.", &to));
    }
    let recipient_key = recipient_key.unwrap();
    let recipient_public = Keyring::decode_public_key(&recipient_key.public_key)?;

    let sender_key = keyring.get_key(&from);
    if sender_key.is_none() {
        return Err(anyhow!("Sender key '{}' not found.", &from));
    }
    let sender_key = sender_key.unwrap();
    if sender_key.private_key.is_none() {
        return Err(anyhow!("Sender '{}' needs a private key.", &from));
    }
    let sender_key = sender_key.private_key.as_ref().unwrap();
    let unlock_prompt = format!("Unlock '{}' key: ", &from);
    let pass = ask_pass_stderr(&unlock_prompt)?;

    let mut pass = pass;
    let sender_private = loop {
        match Keyring::unlock_private_key(sender_key, pass.as_bytes()) {
            Ok(sk) => break sk,
            Err(_) => {
                eprintln!("Key unlock failed.");
                let p = ask_pass_stderr(&unlock_prompt)?;
                pass = p;
            }
        }
    };

    let mut plaintext = File::open(infile_path).context("Could not open input file.")?;
    let mut ciphertext = File::create(&outfile_path)?;

    eprint!("Encrypting...");

    encrypt::encrypt(
        &mut plaintext,
        &mut ciphertext,
        &sender_private,
        &recipient_public,
        None,
        None,
    )
    .map_err(|e| {
        eprintln!("failed");
        anyhow!(e)
    })?;

    ciphertext.sync_all()?;
    eprintln!("done");

    Ok(())
}

pub(crate) fn decrypt(opts: DecryptOptions) -> Result<(), anyhow::Error> {
    let infile = opts.infile;
    let to = opts.to;
    let outfile = opts.outfile;
    let keyring = opts.keyring;

    let infile_path = PathBuf::from(infile);
    if !infile_path.exists() {
        return Err(anyhow!(
            "Input file '{}' does not exist",
            extract_filename(infile_path.file_name())
        ));
    }

    {
        let mut prologue = [0u8; 4];
        let mut ct_file = File::open(&infile_path).context("Could not open ciphertext file")?;
        ct_file.read_exact(&mut prologue)?;
        if prologue == PASS_FILE_MAGIC {
            return Err(anyhow!(
                "Wrong file type. Try this with the password decrypt command"
            ));
        }
        if prologue != PROLOGUE {
            return Err(anyhow!("Unsupported file type."));
        }
    }

    let outfile_path = calculate_output_path(
        &infile_path,
        outfile.as_ref(),
        ExtensionAction::RemoveExtension,
    )?;
    let outfile_path = match outfile_path {
        Some(o) => o,
        None => return Ok(()), // The user didn't want to overwrite the file.
    };

    let keyring = open_keyring(keyring)?;
    let recipient_key = keyring.get_key(&to);
    let recipient_key = match recipient_key {
        Some(k) => k,
        None => return Err(anyhow!("Key '{}' not found", &to)),
    };
    let recipient_key = match &recipient_key.private_key {
        Some(k) => k,
        None => return Err(anyhow!("Key '{}' needs a private key", &to)),
    };
    let unlock_prompt = format!("Unlock '{}' key: ", &to);
    let pass = ask_pass_stderr(&unlock_prompt)?;

    let mut pass = pass;
    let recipient_private = loop {
        match Keyring::unlock_private_key(recipient_key, pass.as_bytes()) {
            Ok(sk) => break sk,
            Err(_) => {
                eprintln!("Key unlock failed.");
                let p = ask_pass_stderr(&unlock_prompt)?;
                pass = p;
            }
        }
    };

    let mut ciphertext = File::open(&infile_path).context("Could not open input file")?;
    let mut plaintext = File::create(&outfile_path)?;

    eprint!("Decrypting...");
    let sender_public = match decrypt::decrypt(&mut ciphertext, &mut plaintext, &recipient_private)
    {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("failed");
            return Err(anyhow!(e));
        }
    };
    plaintext.sync_all()?;
    eprintln!("done");

    let encoded_public = Keyring::encode_public_key(&sender_public);
    match keyring.get_name_from_key(&encoded_public) {
        Some(name) => println!("Success. File from: {}", name),
        None => {
            println!("Caution. File is from an unknown key.");
            println!("Unknown key: {}", encoded_public.as_str());
        }
    }

    Ok(())
}

pub(crate) fn gen_key(outfile: String) -> Result<(), anyhow::Error> {
    let name = ask_user_stderr("Key name: ")?;
    if !Keyring::valid_key_name(&name) {
        return Err(anyhow!("Name must be at least 1 and 128 characters."));
    }
    let pass = confirm_password_stderr("New password: ")?;
    let private_key = PrivateKey::generate();
    let public_key = private_key.to_public();
    let mut salt = [0u8; 16];
    let tmp_salt = kestrel_crypto::gen_salt();
    salt.copy_from_slice(&tmp_salt[..16]);

    let encoded_private_key = Keyring::lock_private_key(&private_key, pass.as_bytes(), salt);
    let encoded_public_key = Keyring::encode_public_key(&public_key);

    let key_config =
        Keyring::serialize_key(name.as_str(), &encoded_public_key, &encoded_private_key);

    let key_output = format!("\n{}", key_config);

    let mut keyring_file = OpenOptions::new().append(true).create(true).open(outfile)?;

    keyring_file.write_all(key_output.as_bytes())?;
    keyring_file.sync_all()?;

    Ok(())
}

pub(crate) fn change_pass(private_key: String) -> Result<(), anyhow::Error> {
    eprint!("Old password: ");
    let old_pass = passterm::read_password()?;
    eprintln!();
    eprint!("New password: ");
    let new_pass = passterm::read_password()?;
    eprintln!();

    let old_sk: EncodedSk = private_key
        .as_str()
        .try_into()
        .map_err(|e| anyhow!("{}", e))?;
    let sk = Keyring::unlock_private_key(&old_sk, old_pass.as_bytes())?;

    let mut salt = [0u8; 16];
    let tmp_salt = kestrel_crypto::gen_salt();
    salt.copy_from_slice(&tmp_salt[..16]);
    let new_sk = Keyring::lock_private_key(&sk, new_pass.as_bytes(), salt);

    println!("PrivateKey = {}", new_sk.as_str());

    Ok(())
}

pub(crate) fn extract_pub(private_key: String) -> Result<(), anyhow::Error> {
    eprint!("Password: ");
    let pass = passterm::read_password()?;
    eprintln!();

    let esk: EncodedSk = private_key
        .as_str()
        .try_into()
        .map_err(|e| anyhow!("{}", e))?;

    let sk = Keyring::unlock_private_key(&esk, pass.as_bytes())?;

    let pk = sk.to_public();

    let epk = Keyring::encode_public_key(&pk);

    println!("PublicKey = {}", epk.as_str());

    Ok(())
}

pub(crate) fn pass_encrypt(opts: PasswordOptions) -> Result<(), anyhow::Error> {
    let infile = opts.infile;
    let outfile = opts.outfile;

    let infile_path = PathBuf::from(infile);
    if !infile_path.exists() {
        return Err(anyhow!("Input file does not exist"));
    }
    let outfile_path = calculate_output_path(
        &infile_path,
        outfile.as_ref(),
        ExtensionAction::AddExtension,
    )?;
    let outfile_path = match outfile_path {
        Some(o) => o,
        None => return Ok(()), // The user didn't want to overwrite the file.
    };

    let pass = confirm_password_stderr("Use password: ")?;

    let mut plaintext = File::open(infile_path).context("Could not open plaintext file")?;
    let mut ciphertext = File::create(&outfile_path).context("Could not create ciphertext file")?;

    eprint!("Encrypting...");
    let salt = kestrel_crypto::gen_salt();
    encrypt::pass_encrypt(&mut plaintext, &mut ciphertext, pass.as_bytes(), salt).map_err(|e| {
        eprintln!("failed");
        anyhow!(e)
    })?;

    ciphertext.sync_all()?;
    eprintln!("done");

    Ok(())
}

pub(crate) fn pass_decrypt(opts: PasswordOptions) -> Result<(), anyhow::Error> {
    let infile = opts.infile;
    let outfile = opts.outfile;

    let infile_path = PathBuf::from(infile);
    if !infile_path.exists() {
        return Err(anyhow!("Input file does not exist"));
    }

    {
        let mut file_magic_num = [0u8; 4];
        let mut ct_file = File::open(&infile_path).context("Could not open ciphertext file")?;
        ct_file.read_exact(&mut file_magic_num)?;
        if file_magic_num == PROLOGUE {
            return Err(anyhow!(
                "Wrong file type. Try this with the regular decrypt command"
            ));
        }
        if file_magic_num != PASS_FILE_MAGIC {
            return Err(anyhow!("Unsupported file type."));
        }
    }

    let outfile_path = calculate_output_path(
        &infile_path,
        outfile.as_ref(),
        ExtensionAction::RemoveExtension,
    )?;
    let outfile_path = match outfile_path {
        Some(o) => o,
        None => return Ok(()), // The user didn't want to overwrite the file.
    };

    let pass = ask_pass_stderr("Password: ")?;

    let mut ciphertext = File::open(&infile_path).context("Could not open ciphertext file")?;
    let mut plaintext = File::create(&outfile_path).context("Could not create plaintext file")?;

    eprint!("Decrypting...");
    decrypt::pass_decrypt(&mut ciphertext, &mut plaintext, pass.as_bytes()).map_err(|e| {
        eprintln!("failed");
        anyhow!(e)
    })?;

    plaintext.sync_all()?;
    eprintln!("done");

    Ok(())
}

enum ExtensionAction {
    AddExtension,
    RemoveExtension,
}

/// Try to remove or add the file extension to the given path.
/// If the output path already exists, the user will be asked to confirm if
/// they want to overwrite.
/// If the return was Ok but the PathBuf is None, then the user chose not
/// to overwrite the file.
fn calculate_output_path<T: AsRef<Path>, U: Into<PathBuf>>(
    infile: T,
    outfile: Option<U>,
    action: ExtensionAction,
) -> Result<Option<PathBuf>, anyhow::Error> {
    let outfile_path = if let Some(o) = outfile {
        Some(o.into())
    } else {
        let outpath = match action {
            ExtensionAction::AddExtension => {
                Some(add_file_ext(&infile.as_ref().to_path_buf(), "ktl"))
            }
            ExtensionAction::RemoveExtension => {
                remove_file_ext(&infile.as_ref().to_path_buf(), "ktl")
            }
        };

        match outpath {
            Some(op) => {
                if op.exists() {
                    let should_overwrite = confirm_overwrite(&op)?;
                    if !should_overwrite {
                        return Ok(None);
                    } else {
                        Some(op)
                    }
                } else {
                    Some(op)
                }
            }
            None => return Err(anyhow!("Please specify an output filename.")),
        }
    };

    Ok(outfile_path)
}

fn confirm_password_stderr(prompt: &str) -> Result<String, anyhow::Error> {
    let password = loop {
        eprint!("{}", prompt);
        let pass = passterm::read_password()?;
        eprintln!();
        eprint!("Confirm password: ");
        let confirm_pass = passterm::read_password()?;
        eprintln!();

        if pass != confirm_pass {
            eprintln!("Passwords do not match");
        } else {
            break pass;
        }
    };

    Ok(password)
}

fn ask_pass_stderr(prompt: &str) -> Result<String, anyhow::Error> {
    eprint!("{}", prompt);
    let pass = passterm::read_password()?;
    eprintln!();

    Ok(pass)
}

fn confirm_overwrite<T: AsRef<Path>>(path: T) -> Result<bool, anyhow::Error> {
    let filename = extract_filename(path.as_ref().file_name());
    let prompt = format!("File '{}' already exists. Overwrite? (y/n): ", &filename);
    let confirm = ask_user_stderr(&prompt)?;
    if confirm == "y" || confirm == "Y" {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn ask_user_stderr(prompt: &str) -> Result<String, anyhow::Error> {
    let mut line = String::new();
    eprint!("{}", prompt);
    std::io::stderr().flush()?;
    std::io::stdin().read_line(&mut line)?;
    line = line.trim().into();
    Ok(line)
}

// Extract a rust String file name from a std::path::Path::file_name()
fn extract_filename(name: Option<&OsStr>) -> String {
    match name {
        Some(name) => match name.to_str() {
            Some(n) => n.to_string(),
            None => "[Err: Unknown filename]".to_string(),
        },
        None => "[Err: Unknown filename]".to_string(),
    }
}

fn open_keyring(keyring_loc: Option<String>) -> Result<Keyring, anyhow::Error> {
    let path = if let Some(loc) = keyring_loc {
        PathBuf::from(loc)
    } else {
        match std::env::var("KESTREL_KEYRING") {
            Ok(loc) => PathBuf::from(loc),
            Err(e) => match e {
                std::env::VarError::NotPresent => {
                    return Err(anyhow!(
                        "Specify a keyring with -k or set the KESTREL_KEYRING env var"
                    ))
                }
                std::env::VarError::NotUnicode(_) => {
                    return Err(anyhow!("Could not read data from KESTREL_KEYRING env var"));
                }
            },
        }
    };

    let keyring_data = std::fs::read(path)?;
    let keyring_data = String::from_utf8(keyring_data).context("Invalid Keyring encoding")?;

    Ok(Keyring::new(&keyring_data)?)
}

pub fn add_file_ext(path: &Path, extension: impl AsRef<OsStr>) -> PathBuf {
    let mut new_path = path.to_path_buf();
    match path.extension() {
        Some(ext) => {
            let mut ext = ext.to_os_string();
            ext.push(".");
            ext.push(extension);
            new_path.set_extension(ext)
        }
        None => new_path.set_extension(extension),
    };
    new_path
}

fn remove_file_ext<T: AsRef<Path>>(path: T, extension: &str) -> Option<PathBuf> {
    let ext = path.as_ref().extension()?;
    let ext = ext.to_str()?;
    if ext == extension {
        Some(path.as_ref().to_path_buf().with_extension(""))
    } else {
        None
    }
}
