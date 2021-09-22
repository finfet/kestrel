use std::convert::TryInto;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::crypto::PrivateKey;
use crate::keyring::{EncodedSk, Keyring};

use anyhow::{anyhow, Context};

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

#[derive(Debug)]
pub(crate) struct PasswordOptions {
    pub infile: String,
    pub outfile: Option<String>,
    pub pass: Option<String>,
}

pub(crate) fn encrypt(opts: EncryptOptions) -> Result<(), anyhow::Error> {
    let infile = opts.infile;
    let to = opts.to;
    let from = opts.from;
    let outfile = opts.outfile;
    let keyring = opts.keyring;
    let pass = opts.pass;

    let infile_path = PathBuf::from(infile);
    if !infile_path.exists() {
        return Err(anyhow!("Input file does not exist"));
    }
    let outfile_path = match outfile {
        Some(o) => PathBuf::from(o),
        None => {
            let mut outfile = infile_path.clone();
            add_file_ext(&mut outfile, "wrn");
            if outfile.exists() {
                let overwrite = confirm_overwrite(&outfile)?;
                if !overwrite {
                    return Ok(());
                }
            }
            outfile
        }
    };

    let keyring = open_keyring(keyring)?;
    let recipient_key = keyring.get_key(&to);
    if recipient_key.is_none() {
        return Err(anyhow!("Recipient key not found."));
    }
    let recipient_key = recipient_key.unwrap();
    let recipient_public = Keyring::decode_public_key(&recipient_key.public_key)?;

    let sender_key = keyring.get_key(&from);
    if sender_key.is_none() {
        return Err(anyhow!("Sender key not found."));
    }
    let sender_key = sender_key.unwrap();
    if sender_key.private_key.is_none() {
        return Err(anyhow!("Sender needs a private key."));
    }
    let sender_key = sender_key.private_key.as_ref().unwrap();
    let unlock_prompt = format!("Unlock '{}' key: ", &from);
    let pass = match pass {
        Some(p) => p,
        None => ask_pass_stderr(&unlock_prompt)?,
    };

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
    if let Err(e) = crypto::encrypt::encrypt(
        &mut plaintext,
        &mut ciphertext,
        &sender_private,
        &recipient_public,
    ) {
        eprintln!("failed");
        return Err(anyhow!(e));
    }
    eprintln!("done");

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

    if atty::is(atty::Stream::Stdout) {
        println!();
    }
    print!("{}", key_config);

    Ok(())
}

pub(crate) fn change_pass(private_key: String) -> Result<(), anyhow::Error> {
    let old_pass = rpassword::prompt_password_stderr("Old Password: ")?;
    let new_pass = confirm_password_stderr("New Password: ")?;

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

pub(crate) fn pass_encrypt(opts: PasswordOptions) -> Result<(), anyhow::Error> {
    let infile = opts.infile;
    let outfile = opts.outfile;
    let pass = opts.pass;
    let infile_path = PathBuf::from(infile);
    if !infile_path.exists() {
        return Err(anyhow!("Input file does not exist"));
    }
    let outfile_path = match outfile {
        Some(o) => PathBuf::from(o),
        None => {
            let mut outfile = infile_path.clone();
            add_file_ext(&mut outfile, "wrn");
            if outfile.exists() {
                let overwrite = confirm_overwrite(&outfile)?;
                if !overwrite {
                    return Ok(());
                }
            }
            outfile
        }
    };

    let pass = match pass {
        Some(p) => p,
        None => confirm_password_stderr("New password: ")?,
    };

    let mut plaintext = File::open(infile_path).context("Could not open input file")?;
    let mut ciphertext = File::create(&outfile_path)?;

    eprint!("Encrypting...");
    if let Err(e) = crypto::encrypt::pass_encrypt(&mut plaintext, &mut ciphertext, pass.as_bytes())
    {
        eprintln!("failed");
        return Err(anyhow!(e));
    }
    eprintln!("done");

    Ok(())
}

pub(crate) fn pass_decrypt(opts: PasswordOptions) -> Result<(), anyhow::Error> {
    println!("password decrypting");
    println!("{:?}", opts);
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

fn ask_pass_stderr(prompt: &str) -> Result<String, anyhow::Error> {
    let pass = rpassword::prompt_password_stderr(prompt)?;
    Ok(pass)
}

fn confirm_overwrite<T: AsRef<Path>>(path: T) -> Result<bool, anyhow::Error> {
    let filename = extract_filename(path.as_ref().file_name())?;
    let prompt = format!("File '{}' already exists. Overwrite? (y/n): ", &filename);
    let confirm = ask_user(&prompt)?;
    if !(confirm == "y" || confirm == "Y") {
        Ok(false)
    } else {
        Ok(true)
    }
}

fn ask_user(prompt: &str) -> Result<String, anyhow::Error> {
    let mut line = String::new();
    print!("{}", prompt);
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut line)?;
    line = line.trim().into();
    Ok(line)
}

// Extract a rust String file name from a std::path::Path::file_name()
fn extract_filename(name: Option<&OsStr>) -> Result<String, anyhow::Error> {
    match name {
        Some(name) => match name.to_str() {
            Some(n) => Ok(n.to_string()),
            None => Err(anyhow!("Filename has unsupported characters.")),
        },
        None => Err(anyhow!("Filename has unsupported characters.")),
    }
}

fn open_keyring(keyring_loc: Option<String>) -> Result<Keyring, anyhow::Error> {
    let path = if let Some(loc) = keyring_loc {
        PathBuf::from(loc)
    } else {
        match std::env::var("WREN_KEYRING") {
            Ok(loc) => PathBuf::from(loc),
            Err(e) => match e {
                std::env::VarError::NotPresent => {
                    return Err(anyhow!(
                        "Specify a keyring with -k or set the WREN_KEYRING env var"
                    ))
                }
                std::env::VarError::NotUnicode(_) => {
                    return Err(anyhow!("Could not read data from WREN_KEYRING env var"));
                }
            },
        }
    };

    let keyring_data = std::fs::read_to_string(path)?;

    Ok(Keyring::new(&keyring_data)?)
}

pub fn add_file_ext(path: &mut PathBuf, extension: impl AsRef<OsStr>) {
    match path.extension() {
        Some(ext) => {
            let mut ext = ext.to_os_string();
            ext.push(".");
            ext.push(extension);
            path.set_extension(ext)
        }
        None => path.set_extension(extension),
    };
}

fn remove_file_ext<T: AsRef<Path>>(path: T, extension: &str) -> Option<PathBuf> {
    if path.as_ref().extension().is_none() {
        return None;
    }
    let ext = path.as_ref().extension().unwrap();
    if ext.to_str().is_none() {
        return None;
    }
    let ext = ext.to_str().unwrap();
    if ext == extension {
        Some(path.as_ref().to_path_buf().with_extension(""))
    } else {
        None
    }
}
