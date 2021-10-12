mod commands;
mod decrypt;
mod encrypt;
mod errors;
mod keyring;
mod utils;

use commands::{DecryptOptions, EncryptOptions, KeyCommand, PasswordCommand, PasswordOptions};

use anyhow::anyhow;
use getopts::Options;

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

const USAGE: &str = "USAGE:
    wren encrypt FILE -t NAME -f NAME [-o FILE] [-k KEYRING]
    wren decrypt FILE -t NAME [-o FILE] [-k KEYRING]
    wren key generate
    wren key change-pass PRIVATE-KEY
    wren key extract-pub PRIVATE-KEY
    wren password encrypt|decrypt FILE [-o FILE]

    Aliases enc, dec, pass, and gen can be used as encrypt, decrypt,
    password, and generate respectively.
    Option -k is required unless WREN_KEYRING env var is set.

OPTIONS:
    -t, --to        Recipient key name. Decrypt requires a private key.
    -f, --from      Sender key name. Must be a private key.
    -o, --output    Output file name.
    -k, --keyring   Location of a keyring file.
    -h, --help      Print help information.
    -v, --version   Print version information.";

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();

    if args.len() <= 1 {
        print_help();
        return Ok(());
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
        "key" => match parse_key(args.as_slice()) {
            Ok(key_command) => match key_command {
                KeyCommand::Generate => commands::gen_key()?,
                KeyCommand::ChangePass(priv_key) => commands::change_pass(priv_key)?,
                KeyCommand::ExtractPub(priv_key) => commands::extract_pub(priv_key)?,
            },
            Err(e) => print_usage(e)?,
        },
        "pass" | "password" => match parse_password(args.as_slice()) {
            Ok(pass_command) => match pass_command {
                PasswordCommand::Encrypt(pass_opts) => commands::pass_encrypt(pass_opts)?,
                PasswordCommand::Decrypt(pass_opts) => commands::pass_decrypt(pass_opts)?,
            },
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
    if args.len() < 3 {
        return Err(Some("Not enough arguments".to_string()));
    }

    let mut encrypt_opts = Options::new();
    encrypt_opts.reqopt("t", "to", "Recipient key name", "NAME");
    encrypt_opts.reqopt("f", "from", "Sender key name", "NAME");
    encrypt_opts.optopt("o", "output", "Output file", "FILE");
    encrypt_opts.optopt("k", "keyring", "Keyring file", "FILE");

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

    Ok(EncryptOptions {
        infile,
        to,
        from,
        outfile,
        keyring,
    })
}

fn parse_decrypt(args: &[&str]) -> Result<DecryptOptions, Option<String>> {
    if args.len() < 3 {
        return Err(Some("Not enough arguments".to_string()));
    }

    let mut decrypt_opts = Options::new();
    decrypt_opts.reqopt("t", "to", "Recipient key name", "NAME");
    decrypt_opts.optopt("o", "output", "Output file", "FILE");
    decrypt_opts.optopt("k", "keyring", "Keyring file", "FILE");

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

    Ok(DecryptOptions {
        infile,
        to,
        outfile,
        keyring,
    })
}

fn parse_key(args: &[&str]) -> Result<KeyCommand, Option<String>> {
    match args[2] {
        "gen" | "generate" => {
            if args.len() == 3 {
                Ok(KeyCommand::Generate)
            } else {
                Err(None)
            }
        }
        "change-pass" => {
            if args.len() == 4 {
                let priv_key = args[3].to_string();
                Ok(KeyCommand::ChangePass(priv_key))
            } else {
                Err(Some("Provide a private key".to_string()))
            }
        }
        "extract-pub" => {
            if args.len() == 4 {
                let priv_key = args[3].to_string();
                Ok(KeyCommand::ExtractPub(priv_key))
            } else {
                Err(Some("Provide a private key".to_string()))
            }
        }
        _ => Err(None),
    }
}

fn parse_password(args: &[&str]) -> Result<PasswordCommand, Option<String>> {
    if args.len() < 4 {
        return Err(Some("Not enough arguments".to_string()));
    }

    match args[2] {
        "encrypt" | "enc" => match parse_pass_encrypt(&args[3..]) {
            Ok(pass_opts) => Ok(PasswordCommand::Encrypt(pass_opts)),
            Err(e) => Err(e),
        },
        "decrypt" | "dec" => match parse_pass_decrypt(&args[3..]) {
            Ok(pass_opts) => Ok(PasswordCommand::Decrypt(pass_opts)),
            Err(e) => Err(e),
        },
        _ => Err(None),
    }
}

fn parse_pass_encrypt(args: &[&str]) -> Result<PasswordOptions, Option<String>> {
    let mut pass_encrypt_opts = Options::new();
    pass_encrypt_opts.optopt("o", "output", "Output file", "FILE");

    let matches = match pass_encrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Specify an input file to encrypt".to_string()));
    }

    let infile = matches.free[0].clone();
    let outfile = matches.opt_str("o");

    Ok(PasswordOptions { infile, outfile })
}

fn parse_pass_decrypt(args: &[&str]) -> Result<PasswordOptions, Option<String>> {
    let mut pass_decrypt_opts = Options::new();
    pass_decrypt_opts.optopt("o", "output", "Output file", "FILE");

    let matches = match pass_decrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Specify an input file to decrypt".to_string()));
    }

    let infile = matches.free[0].clone();
    let outfile = matches.opt_str("o");

    Ok(PasswordOptions { infile, outfile })
}
