// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

use crate::keyring::{EncodedSk, Keyring};

use std::convert::TryInto;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use passterm::{isatty, Stream};
use zeroize::{Zeroize, ZeroizeOnDrop};

use kestrel_crypto::errors::DecryptError;
use kestrel_crypto::PrivateKey;
use kestrel_crypto::{decrypt, encrypt};
use kestrel_crypto::{AsymFileFormat, PassFileFormat};

#[derive(Debug)]
pub(crate) struct EncryptOptions {
    pub infile: Option<String>,
    pub to: String,
    pub from: String,
    pub outfile: Option<String>,
    pub keyring: Option<String>,
    pub env_pass: bool,
}

#[derive(Debug)]
pub(crate) struct DecryptOptions {
    pub infile: Option<String>,
    pub to: String,
    pub outfile: Option<String>,
    pub keyring: Option<String>,
    pub env_pass: bool,
}

#[derive(Debug)]
pub(crate) struct PasswordOptions {
    pub infile: Option<String>,
    pub outfile: Option<String>,
    pub env_pass: bool,
}

/// A struct containing a path where the file is created the
/// first time that a read or write is performed.
struct OnDemandFile {
    path: PathBuf,
    handle: Option<File>,
}

impl OnDemandFile {
    fn ensure_created(&mut self) -> std::io::Result<()> {
        if self.handle.is_none() {
            self.handle = Some(File::create(&self.path)?);
        }
        Ok(())
    }

    fn new<T: AsRef<Path>>(p: T) -> Self {
        Self {
            path: p.as_ref().to_path_buf(),
            handle: None,
        }
    }
}

impl Write for OnDemandFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.ensure_created()?;

        let f = self.handle.as_mut().unwrap();
        Ok(f.write(buf)?)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.ensure_created()?;

        let f = self.handle.as_mut().unwrap();
        Ok(f.flush()?)
    }
}

struct SecureString(String);

impl SecureString {
    fn new(s: String) -> Self {
        Self(s)
    }
}

impl Deref for SecureString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Zeroize for SecureString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecureString {}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) fn encrypt(opts: EncryptOptions) -> Result<(), anyhow::Error> {
    let infile = opts.infile;
    let to = opts.to;
    let from = opts.from;
    let outfile = opts.outfile;
    let keyring = opts.keyring;
    let env_pass = opts.env_pass;

    if infile.is_some() && outfile.is_some() {
        let infile = infile.as_deref().unwrap();
        let outfile = outfile.as_deref().unwrap();
        if infile == outfile {
            return Err(anyhow!("Input and output files must be different."));
        }
    }

    let is_text = false;
    // Try to open our plaintext early to not make the user input a keyring
    // password for a plaintext file that doesn't exist.
    let mut plaintext: Box<dyn Read> = open_input(infile.as_deref())?;
    // The ciphertext won't be created until an actuail write() is called.
    let mut ciphertext: Box<dyn Write> = open_output(outfile.as_deref(), is_text)?;

    // Read from the keyring
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
    let sender_public = Keyring::decode_public_key(&sender_key.public_key)?;
    if sender_key.private_key.is_none() {
        return Err(anyhow!("Sender '{}' needs a private key.", &from));
    }
    let sender_key = sender_key.private_key.as_ref().unwrap();
    let unlock_prompt = format!("Unlock '{}' key: ", &from);
    let mut pass = ask_pass(&unlock_prompt, env_pass)?;

    let sender_private = loop {
        match Keyring::unlock_private_key(sender_key, pass.as_bytes()) {
            Ok(sk) => break sk,
            Err(_) => {
                if !passterm::isatty(Stream::Stdin) {
                    return Err(anyhow!("Key unlock failed."));
                } else {
                    eprintln!("Key unlock failed.");
                    let p = ask_pass(&unlock_prompt, env_pass)?;
                    pass = p;
                }
            }
        }
    };

    eprint!("Encrypting...");
    if let Err(e) = encrypt::key_encrypt(
        &mut plaintext,
        &mut ciphertext,
        &sender_private,
        &sender_public,
        &recipient_public,
        None,
        None,
        None,
        AsymFileFormat::V1,
    ) {
        eprintln!("failed.");
        return Err(anyhow!(e));
    }
    eprintln!("done");

    Ok(())
}

pub(crate) fn decrypt(opts: DecryptOptions) -> Result<(), anyhow::Error> {
    let infile = opts.infile;
    let to = opts.to;
    let outfile = opts.outfile;
    let keyring = opts.keyring;
    let env_pass = opts.env_pass;

    // Input and output files must differ. This warns against a common
    // user typo.
    if infile.is_some() && outfile.is_some() {
        let infile = infile.as_deref().unwrap();
        let outfile = outfile.as_deref().unwrap();
        if infile == outfile {
            return Err(anyhow!("Input and output files must be different."));
        }
    }

    let is_text = false;
    // Try to open our ciphertext early to prevent the user from typing in
    // a password for a ciphertext file that doesn't exist.
    let mut ciphertext: Box<dyn Read> = open_input(infile.as_deref())?;
    let mut plaintext: Box<dyn Write> = open_output(outfile.as_deref(), is_text)?;

    let keyring = open_keyring(keyring)?;
    let recipient_key = keyring.get_key(&to);
    let recipient_key = match recipient_key {
        Some(k) => k,
        None => return Err(anyhow!("Key '{}' not found.", &to)),
    };
    let recipient_public = Keyring::decode_public_key(&recipient_key.public_key)?;
    let recipient_key = match &recipient_key.private_key {
        Some(k) => k,
        None => return Err(anyhow!("Key '{}' needs a private key.", &to)),
    };
    let unlock_prompt = format!("Unlock '{}' key: ", &to);
    let mut pass = ask_pass(&unlock_prompt, env_pass)?;

    let recipient_private = loop {
        match Keyring::unlock_private_key(recipient_key, pass.as_bytes()) {
            Ok(sk) => break sk,
            Err(_) => {
                if !passterm::isatty(Stream::Stdin) {
                    return Err(anyhow!("Key unlock failed."));
                } else {
                    eprintln!("Key unlock failed.");
                    let p = ask_pass(&unlock_prompt, env_pass)?;
                    pass = p;
                }
            }
        }
    };

    eprint!("Decrypting...");
    let sender_public = match decrypt::key_decrypt(
        &mut ciphertext,
        &mut plaintext,
        &recipient_private,
        &recipient_public,
        AsymFileFormat::V1,
    ) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("failed.");
            return Err(anyhow!(e));
        }
    };
    eprintln!("done");

    let encoded_public = Keyring::encode_public_key(&sender_public);
    match keyring.get_name_from_key(&encoded_public) {
        Some(name) => eprintln!("Success. File from: {}", name),
        None => {
            eprintln!("Caution. File is from an unknown key.");
            eprintln!("Unknown key: {}", encoded_public.as_str());
        }
    }

    Ok(())
}

pub(crate) fn gen_key(outfile: Option<String>, env_pass: bool) -> Result<(), anyhow::Error> {
    let name = ask_user_stderr("Key name: ")?;
    if !Keyring::valid_key_name(&name) {
        return Err(anyhow!("Name must be between 1 and 128 characters."));
    }

    let pass = confirm_password("New password: ", env_pass)?;

    let private_key = PrivateKey::generate();
    let public_key = private_key.to_public();
    let salt: [u8; 32] = kestrel_crypto::secure_random(32).try_into().unwrap();

    let encoded_private_key = Keyring::lock_private_key(&private_key, pass.as_bytes(), salt);
    let encoded_public_key = Keyring::encode_public_key(&public_key);

    let key_config =
        Keyring::serialize_key(name.as_str(), &encoded_public_key, &encoded_private_key);

    let key_output = if let Some(ref outfile) = outfile {
        // If the file already exists, write additional keys beginning with a newline.
        if Path::new(outfile).exists() {
            format!("\n{}", key_config)
        } else {
            key_config
        }
    } else if isatty(Stream::Stdout) {
        format!("\n{}", key_config)
    } else {
        key_config
    };

    let is_text = true;
    let mut keyring = open_output(outfile.as_deref(), is_text)?;
    keyring.write_all(key_output.as_bytes())?;
    keyring.flush()?;

    Ok(())
}

pub(crate) fn change_pass(private_key: String, env_pass: bool) -> Result<(), anyhow::Error> {
    let old_pass = ask_pass("Old password: ", env_pass)?;
    let new_pass = confirm_new_pass("New password: ", env_pass)?;

    let old_sk: EncodedSk = private_key
        .as_str()
        .try_into()
        .map_err(|e| anyhow!("{}", e))?;
    let sk = Keyring::unlock_private_key(&old_sk, old_pass.as_bytes())?;

    let salt: [u8; 32] = kestrel_crypto::secure_random(32).try_into().unwrap();
    let new_sk = Keyring::lock_private_key(&sk, new_pass.as_bytes(), salt);

    let key_output = if isatty(Stream::Stdout) {
        format!("\nPrivateKey = {}", new_sk.as_str())
    } else {
        format!("PrivateKey = {}", new_sk.as_str())
    };

    println!("{}", key_output);

    Ok(())
}

pub(crate) fn extract_pub(private_key: String, env_pass: bool) -> Result<(), anyhow::Error> {
    let pass = ask_pass("Password: ", env_pass)?;

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
    let env_pass = opts.env_pass;

    if infile.is_some() && outfile.is_some() {
        let infile = infile.as_deref().unwrap();
        let outfile = outfile.as_deref().unwrap();
        if infile == outfile {
            return Err(anyhow!("Input and output files must be different."));
        }
    }

    let is_text = false;
    let mut plaintext: Box<dyn Read> = open_input(infile.as_deref())?;

    // Behind the scenes here we're using an OnDemandFile that doesn't
    // create the file until an actual write is performed. This way if the
    // user backs out before providing a password, we don't clobber their
    // original output file.
    let mut ciphertext: Box<dyn Write> = open_output(outfile.as_deref(), is_text)?;

    let pass = confirm_password("Use password: ", env_pass)?;

    eprint!("Encrypting...");
    let salt: [u8; 32] = kestrel_crypto::secure_random(32).try_into().unwrap();
    if let Err(e) = encrypt::pass_encrypt(
        &mut plaintext,
        &mut ciphertext,
        pass.as_bytes(),
        salt,
        PassFileFormat::V1,
    ) {
        eprintln!("failed.");
        return Err(anyhow!(e));
    }

    eprintln!("done");

    Ok(())
}

pub(crate) fn pass_decrypt(opts: PasswordOptions) -> Result<(), anyhow::Error> {
    fn fmt_err(e: DecryptError) -> anyhow::Error {
        if let DecryptError::ChaPolyDecrypt = e {
            anyhow!("Decrypt failed. Check password used. File may have been modified.")
        } else {
            anyhow!(e)
        }
    }
    let infile = opts.infile;
    let outfile = opts.outfile;
    let env_pass = opts.env_pass;

    if infile.is_some() && outfile.is_some() {
        let infile = infile.as_deref().unwrap();
        let outfile = outfile.as_deref().unwrap();
        if infile == outfile {
            return Err(anyhow!("Input and output files must be different."));
        }
    }

    let is_text = false;
    let mut ciphertext: Box<dyn Read> = open_input(infile.as_deref())?;
    let mut plaintext: Box<dyn Write> = open_output(outfile.as_deref(), is_text)?;

    let pass = ask_pass("Password: ", env_pass)?;

    eprint!("Decrypting...");
    if let Err(e) = decrypt::pass_decrypt(
        &mut ciphertext,
        &mut plaintext,
        pass.as_bytes(),
        PassFileFormat::V1,
    ) {
        eprintln!("failed.");
        return Err(fmt_err(e));
    }
    eprintln!("done");

    Ok(())
}

/// Open a Read input source. Checks for the existence of the file at the
/// given path if specified. If a path is not specified, the source will be
/// stdin, if stdin has been piped in.
fn open_input(path: Option<&str>) -> Result<Box<dyn Read>, anyhow::Error> {
    if let Some(p) = path {
        let infile_path = PathBuf::from(p);
        if !infile_path.exists() {
            return Err(anyhow!(
                "Input file '{}' does not exist.",
                extract_filename(infile_path.file_name())
            ));
        }
        Ok(Box::new(File::open(p).map_err(|e| {
            anyhow!("Could not open input file: {}", e)
        })?))
    } else if isatty(Stream::Stdin) {
        // Stdin must be piped in if we are going to read it
        Err(anyhow!("Please specify an input file."))
    } else {
        Ok(Box::new(std::io::stdin()))
    }
}

/// Open a Write output source. Will use the path if specified, or stdout.
/// Stdout must be redirected to a file for any data that isn't text.
/// The file at the specified path will not be created until an actual write
/// call is performed.
fn open_output(path: Option<&str>, is_text: bool) -> Result<Box<dyn Write>, anyhow::Error> {
    // Require that output be written to a file on windows because windows
    // can't write non utf-8 byte sequences in a console
    // https://doc.rust-lang.org/stable/std/io/fn.stdout.html#note-windows-portability-considerations
    if cfg!(target_os = "windows") && path.is_none() {
        return Err(anyhow!("Please specify an output file."));
    }

    if let Some(p) = path {
        Ok(Box::new(OnDemandFile::new(p)))
    } else if isatty(Stream::Stdout) && !is_text {
        // Refuse to output to the terminal unless it is redirected to
        // a file or another program.
        Err(anyhow!("Please specify an output file."))
    } else {
        Ok(Box::new(std::io::stdout()))
    }
}

fn confirm_password(prompt: &str, env_pass: bool) -> Result<SecureString, anyhow::Error> {
    if env_pass {
        return read_env_pass();
    }

    let password = confirm_loop(prompt)?;

    Ok(password)
}

fn confirm_loop(prompt: &str) -> Result<SecureString, anyhow::Error> {
    let password = loop {
        let pass = ask_pass(prompt, false)?;
        let confirm_pass = ask_pass("Confirm password: ", false)?;

        if *pass != *confirm_pass {
            // Don't loop if we're not in an interactive prompt.
            if !passterm::isatty(Stream::Stdin) {
                return Err(anyhow!("Passwords do not match"));
            } else {
                eprintln!("Passwords do not match");
            }
        } else {
            break pass;
        }
    };

    Ok(password)
}

fn ask_pass(prompt: &str, env_pass: bool) -> Result<SecureString, anyhow::Error> {
    if env_pass {
        return read_env_pass();
    }

    let pass = match passterm::prompt_password_tty(Some(prompt)) {
        Ok(p) => p,
        Err(e) => {
            if passterm::isatty(Stream::Stdin) {
                passterm::prompt_password_stdin(Some(prompt), Stream::Stderr)?
            } else {
                return Err(anyhow!(e));
            }
        }
    };

    Ok(SecureString::new(pass))
}

fn confirm_new_pass(prompt: &str, env_pass: bool) -> Result<SecureString, anyhow::Error> {
    if env_pass {
        return read_env_new_pass();
    }

    let password = confirm_loop(prompt)?;

    Ok(password)
}

/// Read the password from the KESTREL_PASSWORD environment variable
fn read_env_pass() -> Result<SecureString, anyhow::Error> {
    match std::env::var("KESTREL_PASSWORD") {
        Ok(p) => Ok(SecureString::new(p)),
        Err(e) => match e {
            std::env::VarError::NotPresent => Err(anyhow!(
                "--env-pass requires setting the KESTREL_PASSWORD environment variable"
            )),
            std::env::VarError::NotUnicode(_) => Err(anyhow!(
                "Could not read data from KESTREL_PASSWORD environment variable"
            )),
        },
    }
}

/// Read the password from the KESTREL_NEW_PASSWORD environment variable
fn read_env_new_pass() -> Result<SecureString, anyhow::Error> {
    match std::env::var("KESTREL_NEW_PASSWORD") {
        Ok(p) => Ok(SecureString::new(p)),
        Err(e) => match e {
            std::env::VarError::NotPresent => {
                Err(anyhow!("--env-pass with change-pass requires setting the KESTREL_NEW_PASSWORD environment variable"))
            }
            std::env::VarError::NotUnicode(_) => {
                Err(anyhow!("Could not read data from KESTREL_NEW_PASSWORD environment variable"))
            }
        }
    }
}

fn ask_user_stderr(prompt: &str) -> Result<String, anyhow::Error> {
    let mut line = String::new();
    eprint!("{}", prompt);
    std::io::stderr().flush()?;
    std::io::stdin().read_line(&mut line)?;
    line = line.trim().into();
    if !passterm::isatty(Stream::Stdin) {
        eprintln!();
    }
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

    let keyring_data = std::fs::read(path).map_err(|e| anyhow!("Could not open keyring: {}", e))?;
    let keyring_data = String::from_utf8(keyring_data)
        .map_err(|_| anyhow!("Invalid keyinrg encoding. Expected UTF-8"))?;

    Ok(Keyring::new(&keyring_data)?)
}
