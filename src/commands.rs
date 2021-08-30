use crate::crypto;
use crate::crypto::PrivateKey;
use crate::keyring::Keyring;

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

pub(crate) fn gen_key(name: String, password: Option<String>) -> Result<(), anyhow::Error> {
    let private_key = PrivateKey::new();
    let public_key = private_key.to_public();
    let salt = crypto::gen_salt();
    let pass = match password {
        Some(p) => p,
        None => confirm_password_stderr()?,
    };

    let encoded_private_key = Keyring::lock_private_key(&private_key, pass.as_bytes(), salt);
    let encoded_public_key = Keyring::encode_public_key(&public_key);

    let key_config =
        Keyring::serialize_key(name.as_str(), &encoded_public_key, &encoded_private_key);

    println!();
    print!("{}", key_config);

    Ok(())
}

fn confirm_password_stderr() -> Result<String, anyhow::Error> {
    let password = loop {
        let pass = rpassword::prompt_password_stderr("Password: ")?;
        let confirm_pass = rpassword::prompt_password_stderr("Confirm Password: ")?;
        if pass != confirm_pass {
            eprintln!("Passwords do not match");
        } else {
            break pass;
        }
    };

    Ok(password)
}

pub(crate) fn change_pass(
    private_key: String,
    password: Option<String>,
) -> Result<(), anyhow::Error> {
    println!("Changing password...");
    println!("Provided private key: {}", private_key);
    println!("Provided pass: {:?}", password);
    Ok(())
}

pub(crate) fn extract_pub(
    private_key: String,
    password: Option<String>,
) -> Result<(), anyhow::Error> {
    println!("Extracting public key...");
    println!("Provided private key: {}", private_key);
    println!("Provided pass: {:?}", password);
    Ok(())
}
