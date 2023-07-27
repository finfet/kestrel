// Copyright 2021-2023 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

mod commands;
mod errors;
mod keyring;

use commands::{DecryptOptions, EncryptOptions, KeyCommand, PasswordCommand, PasswordOptions};

use anyhow::anyhow;
use getopts::Options;

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

const USAGE: &str = "USAGE:
    kestrel encrypt FILE -t NAME -f NAME [-o FILE] [-k KEYRING]
    kestrel decrypt FILE -t NAME [-o FILE] [-k KEYRING]
    kestrel key generate -o FILE
    kestrel key change-pass PRIVATE-KEY
    kestrel key extract-pub PRIVATE-KEY
    kestrel password encrypt|decrypt FILE [-o FILE]

    Aliases enc, dec, pass, and gen can be used as encrypt, decrypt,
    password, and generate respectively.
    Option -k is required unless KESTREL_KEYRING env var is set.

OPTIONS:
    -t, --to      NAME    Recipient key name. Decrypt requires a private key.
    -f, --from    NAME    Sender key name. Must be a private key.
    -o, --output  FILE    Output file name.
    -k, --keyring KEYRING Location of a keyring file.
    -h, --help            Print help information.
    -v, --version         Print version information.";

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();

    if args.len() <= 1 {
        print_help();

        return Ok(());
    }

    for arg in &args {
        let arg = *arg;
        if arg == "-h" || arg == "--help" {
            print_help();
            return Ok(());
        } else if arg == "-v" || arg == "--version" {
            print_version();
            return Ok(());
        }
    }

    match args[1] {
        "enc" | "encrypt" => match parse_encrypt(args.as_slice()) {
            Ok(opts) => commands::encrypt(opts)?,
            Err(e) => print_error(&e)?,
        },
        "dec" | "decrypt" => match parse_decrypt(args.as_slice()) {
            Ok(opts) => commands::decrypt(opts)?,
            Err(e) => print_error(&e)?,
        },
        "key" => match parse_key(args.as_slice()) {
            Ok(key_command) => match key_command {
                KeyCommand::Generate(outfile) => commands::gen_key(outfile)?,
                KeyCommand::ChangePass(priv_key) => commands::change_pass(priv_key)?,
                KeyCommand::ExtractPub(priv_key) => commands::extract_pub(priv_key)?,
            },
            Err(e) => print_error(&e)?,
        },
        "pass" | "password" => match parse_password(args.as_slice()) {
            Ok(pass_command) => match pass_command {
                PasswordCommand::Encrypt(pass_opts) => commands::pass_encrypt(pass_opts)?,
                PasswordCommand::Decrypt(pass_opts) => commands::pass_decrypt(pass_opts)?,
            },
            Err(e) => print_error(&e)?,
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

fn print_error(msg: &str) -> Result<(), anyhow::Error> {
    Err(anyhow!("{}\n{}", msg, "For more info use '--help'"))
}

fn parse_encrypt(args: &[&str]) -> Result<EncryptOptions, String> {
    if args.len() < 3 {
        return Err("Not enough arguments".to_string());
    }

    let mut encrypt_opts = Options::new();
    encrypt_opts.long_only(true);
    encrypt_opts.reqopt("t", "to", "Recipient key name", "NAME");
    encrypt_opts.reqopt("f", "from", "Sender key name", "NAME");
    encrypt_opts.optopt("o", "output", "Output file", "FILE");
    encrypt_opts.optopt("k", "keyring", "Keyring file", "FILE");

    let matches = match encrypt_opts.parse(&args[2..]) {
        Ok(m) => m,
        Err(e) => return Err(e.to_string()),
    };

    if matches.free.len() != 1 {
        return Err("Specify an input file to encrypt".to_string());
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

fn parse_decrypt(args: &[&str]) -> Result<DecryptOptions, String> {
    if args.len() < 3 {
        return Err("Not enough arguments".to_string());
    }

    let mut decrypt_opts = Options::new();
    decrypt_opts.long_only(true);
    decrypt_opts.reqopt("t", "to", "Recipient key name", "NAME");
    decrypt_opts.optopt("o", "output", "Output file", "FILE");
    decrypt_opts.optopt("k", "keyring", "Keyring file", "FILE");

    let matches = match decrypt_opts.parse(&args[2..]) {
        Ok(m) => m,
        Err(e) => return Err(e.to_string()),
    };

    if matches.free.len() != 1 {
        return Err("Specify an input file to decrypt".to_string());
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

fn parse_key(args: &[&str]) -> Result<KeyCommand, String> {
    if args.len() < 4 {
        return Err("Not enough arguments".to_string());
    }

    match args[2] {
        "gen" | "generate" => {
            let mut gen_opts = Options::new();
            gen_opts.reqopt("o", "output", "Output file", "FILE");
            gen_opts.long_only(true);
            let matches = match gen_opts.parse(&args[3..]) {
                Ok(m) => m,
                Err(e) => return Err(e.to_string()),
            };

            let outfile = matches.opt_str("o").unwrap();

            Ok(KeyCommand::Generate(outfile))
        }
        "change-pass" => {
            if args.len() == 4 {
                let priv_key = args[3].to_string();
                Ok(KeyCommand::ChangePass(priv_key))
            } else {
                Err("Provide a private key".to_string())
            }
        }
        "extract-pub" => {
            if args.len() == 4 {
                let priv_key = args[3].to_string();
                Ok(KeyCommand::ExtractPub(priv_key))
            } else {
                Err("Provide a private key".to_string())
            }
        }
        _ => Err("Incorrect usage".to_string()),
    }
}

fn parse_password(args: &[&str]) -> Result<PasswordCommand, String> {
    if args.len() < 4 {
        return Err("Not enough arguments".to_string());
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
        _ => Err("Incorrect usage".to_string()),
    }
}

fn parse_pass_encrypt(args: &[&str]) -> Result<PasswordOptions, String> {
    let mut pass_encrypt_opts = Options::new();
    pass_encrypt_opts.long_only(true);
    pass_encrypt_opts.optopt("o", "output", "Output file", "FILE");

    let matches = match pass_encrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(e.to_string()),
    };

    if matches.free.len() != 1 {
        return Err("Specify an input file to encrypt".to_string());
    }

    let infile = matches.free[0].clone();
    let outfile = matches.opt_str("o");

    Ok(PasswordOptions { infile, outfile })
}

fn parse_pass_decrypt(args: &[&str]) -> Result<PasswordOptions, String> {
    let mut pass_decrypt_opts = Options::new();
    pass_decrypt_opts.long_only(true);
    pass_decrypt_opts.optopt("o", "output", "Output file", "FILE");

    let matches = match pass_decrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(e.to_string()),
    };

    if matches.free.len() != 1 {
        return Err("Specify an input file to decrypt".to_string());
    }

    let infile = matches.free[0].clone();
    let outfile = matches.opt_str("o");

    Ok(PasswordOptions { infile, outfile })
}
