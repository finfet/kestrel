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

// Infile, Opt<Outfile>, Opt<Pass>
pub(crate) type PassOptions = (String, Option<String>, Option<String>);

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

pub(crate) fn pass_enc(opts: PassOptions) -> Result<(), anyhow::Error> {
    println!("Symmetric encryption");
    println!("infile: {}", opts.0);
    println!("outfile: {:?}", opts.1);
    println!("pass: {:?}", opts.2);

    Ok(())
}

pub(crate) fn pass_dec(opts: PassOptions) -> Result<(), anyhow::Error> {
    println!("Symmetric decryption");
    println!("infile: {}", opts.0);
    println!("outfile: {:?}", opts.1);
    println!("pass: {:?}", opts.2);

    Ok(())
}
