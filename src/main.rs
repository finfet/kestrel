mod commands;
mod crypto;
mod errors;
mod keyring;

use anyhow::anyhow;
use getopts::Options;

use commands::{DecryptOptions, EncryptOptions};

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

const USAGE: &str = "USAGE:
    wren encrypt FILE -t NAME -f NAME [-o FILE] [-k KEYRING] [-p PASS]
    wren decrypt FILE -t NAME [-o FILE] [-k KEYRING] [-p PASS]
    wren gen-key NAME
    wren change-pass PRIVATE-KEY [-p PASS]
    wren extract-pub PRIVATE-KEY [-p PASS]

    Aliases enc and dec can be used for encrypt and decrypt.
    Option -k is required unless WREN_KEYRING env var is set.

OPTIONS:
    -t, --to        Recipient key name. Decrypt requires a private key.
    -f, --from      Sender key name. Must be a private key.
    -o, --output    Output file name.
    -k, --keyring   Location of a keyring file.
    -p, --password  Password of private key. Prefer interactive prompt.
    -h, --help      Print help information.
    -v, --version   Print version information.";

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();

    if args.len() <= 1 {
        return Err(anyhow!("{}", USAGE));
    }

    if args[1] == "-v" || args[1] == "--version" {
        print_version();
        return Ok(());
    }

    if args[1] == "-h" || args[1] == "--help" {
        print_help();
        return Ok(());
    }

    match args[1] {
        "enc" | "encrypt" => match parse_encrypt(args.as_slice()) {
            Ok(opts) => commands::encrypt(opts)?,
            Err(e) => print_usage(e)?,
        },
        "dec" | "decrypt" => match parse_decrypt(args.as_slice()) {
            Ok(opts) => commands::decrypt(opts)?,
            Err(e) => print_usage(e)?,
        },
        "gen-key" => match parse_gen_key(args.as_slice()) {
            Ok(name) => commands::gen_key(name)?,
            Err(e) => print_usage(e)?,
        },
        "change-pass" => match parse_change_pass(args.as_slice()) {
            Ok(opts) => commands::change_pass(opts)?,
            Err(e) => print_usage(e)?,
        },
        "extract-pub" => match parse_extract_pub(args.as_slice()) {
            Ok(opts) => commands::extract_pub(opts)?,
            Err(e) => print_usage(e)?,
        },
        _ => {
            return Err(anyhow!("{}", USAGE));
        }
    }

    Ok(())
}

fn print_help() {
    println!("{}", USAGE);
}

fn print_version() {
    println!("v{}", VERSION.unwrap_or("0.0.1"));
}

fn print_usage(msg: Option<String>) -> Result<(), anyhow::Error> {
    if let Some(msg) = msg {
        return Err(anyhow!("{}\n\nError: {}", USAGE, msg));
    } else {
        return Err(anyhow!("{}", USAGE));
    }
}

fn parse_encrypt(args: &[&str]) -> Result<EncryptOptions, Option<String>> {
    let mut encrypt_opts = Options::new();
    encrypt_opts.reqopt("t", "to", "Recipient key name", "NAME");
    encrypt_opts.reqopt("f", "from", "Sender key name", "NAME");
    encrypt_opts.optopt("o", "output", "Output file", "FILE");
    encrypt_opts.optopt("k", "keyring", "Keyring file", "FILE");
    encrypt_opts.optopt("p", "password", "Key password", "PASS");

    let matches = match encrypt_opts.parse(&args[2..]) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Specify an input file to encrypt".to_string()));
    }

    let infile = matches.free[0].clone();
    let to = matches.opt_str("t").unwrap();
    let from = matches.opt_str("f").unwrap();
    let outfile = matches.opt_str("o");
    let keyring = matches.opt_str("k");
    let pass = matches.opt_str("p");

    Ok(EncryptOptions {
        infile,
        to,
        from,
        outfile,
        keyring,
        pass,
    })
}

fn parse_decrypt(args: &[&str]) -> Result<DecryptOptions, Option<String>> {
    let mut decrypt_opts = Options::new();
    decrypt_opts.reqopt("t", "to", "Recipient key name", "NAME");
    decrypt_opts.optopt("o", "output", "Output file", "FILE");
    decrypt_opts.optopt("k", "keyring", "Keyring file", "FILE");
    decrypt_opts.optopt("p", "password", "Key password", "PASS");

    let matches = match decrypt_opts.parse(&args[2..]) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Specify an input file to decrypt".to_string()));
    }

    let infile = matches.free[0].clone();
    let to = matches.opt_str("t").unwrap();
    let outfile = matches.opt_str("o");
    let keyring = matches.opt_str("k");
    let pass = matches.opt_str("p");

    Ok(DecryptOptions {
        infile,
        to,
        outfile,
        keyring,
        pass,
    })
}

fn parse_gen_key(args: &[&str]) -> Result<String, Option<String>> {
    let gen_key_opts = Options::new();
    let matches = match gen_key_opts.parse(&args[2..]) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some(
            "Give the key a name like Alice or Mallory".to_string(),
        ));
    }

    Ok(matches.free[0].clone())
}

fn parse_change_pass(args: &[&str]) -> Result<(String, Option<String>), Option<String>> {
    let mut change_pass_opts = Options::new();
    change_pass_opts.optopt("p", "password", "Key password", "PASS");

    let matches = match change_pass_opts.parse(&args[2..]) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Provide the private key string".to_string()));
    }

    let priv_key = matches.free[0].clone();
    let pass = matches.opt_str("p");

    Ok((priv_key, pass))
}

fn parse_extract_pub(args: &[&str]) -> Result<(String, Option<String>), Option<String>> {
    let mut extract_pub_opts = Options::new();
    extract_pub_opts.optopt("p", "password", "Key password", "PASS");

    let matches = match extract_pub_opts.parse(&args[2..]) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Provide the private key string".to_string()));
    }

    let priv_key = matches.free[0].clone();
    let pass = matches.opt_str("p");

    Ok((priv_key, pass))
}
