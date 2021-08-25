use crate::crypto::PrivateKey;

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
    println!("Generating key for: {}", name);
    let private_key = PrivateKey::new();
    println!("Private key: {:02x?}", private_key.as_bytes());
    let public_key = private_key.to_public();
    println!("Public key: {:02x?}", public_key.as_bytes());
    Ok(())
}

pub(crate) fn change_pass(opts: (String, Option<String>)) -> Result<(), anyhow::Error> {
    println!("Changing password...");
    println!("Provided private key: {}", opts.0);
    println!("Provided pass: {:?}", opts.1);
    Ok(())
}

pub(crate) fn extract_pub(opts: (String, Option<String>)) -> Result<(), anyhow::Error> {
    println!("Extracting public key...");
    println!("Provided private key: {}", opts.0);
    println!("Provided pass: {:?}", opts.1);
    Ok(())
}
