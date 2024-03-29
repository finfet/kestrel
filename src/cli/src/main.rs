// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

mod commands;
mod errors;
mod keyring;

use commands::{DecryptOptions, EncryptOptions, PasswordOptions};

use anyhow::anyhow;
use getopts::Options;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "USAGE:
    kestrel encrypt [FILE] -t NAME -f NAME [-o FILE] [-k KEYRING]
    kestrel decrypt [FILE] -t NAME [-o FILE] [-k KEYRING]
    kestrel key generate [-o FILE]
    kestrel key change-pass PRIVATE-KEY
    kestrel key extract-pub PRIVATE-KEY
    kestrel password encrypt|decrypt [FILE] [-o FILE]

    Aliases enc, dec, pass, and gen can be used as encrypt, decrypt,
    password, and generate respectively.
    Option -k is required unless KESTREL_KEYRING env var is set.

OPTIONS:
    -t, --to      NAME    Recipient key name. Decrypt requires a private key.
    -f, --from    NAME    Sender key name. Must be a private key.
    -o, --output  FILE    Output file name.
    -k, --keyring KEYRING Location of a keyring file.
    -h, --help            Print help information.
    -v, --version         Print version information.
    --env-pass            Read password from KESTREL_PASSWORD env var";

#[derive(Debug)]
pub(crate) enum KeyCommand {
    Generate(Option<String>, bool),
    ChangePass(String, bool),
    ExtractPub(String, bool),
}

#[derive(Debug)]
pub(crate) enum PasswordCommand {
    Encrypt(PasswordOptions),
    Decrypt(PasswordOptions),
}

fn main() {
    if let Err(e) = try_main() {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let args = convert_args(args.as_slice())?;
    let args: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();

    if args.len() <= 1 || args.contains(&"--help") || args.contains(&"-h") {
        print_help();

        return Ok(());
    }

    match args[1] {
        "-h" | "--help" => {
            print_help();
            return Ok(());
        }
        "-v" | "--version" => {
            print_version();
            return Ok(());
        }
        "enc" | "encrypt" => {
            let args = slice_args(&args, 2);
            match parse_encrypt(args) {
                Ok(opts) => commands::encrypt(opts)?,
                Err(e) => print_usage_error(&e)?,
            }
        }
        "dec" | "decrypt" => {
            let args = slice_args(&args, 2);
            match parse_decrypt(args) {
                Ok(opts) => commands::decrypt(opts)?,
                Err(e) => print_usage_error(&e)?,
            }
        }
        "key" => {
            let args = slice_args(&args, 2);
            match parse_key(args) {
                Ok(key_command) => match key_command {
                    KeyCommand::Generate(outfile, env_pass) => {
                        commands::gen_key(outfile, env_pass)?
                    }
                    KeyCommand::ChangePass(priv_key, env_pass) => {
                        commands::change_pass(priv_key, env_pass)?
                    }
                    KeyCommand::ExtractPub(priv_key, env_pass) => {
                        commands::extract_pub(priv_key, env_pass)?
                    }
                },
                Err(e) => print_usage_error(&e)?,
            }
        }
        "pass" | "password" => {
            let args = slice_args(&args, 2);
            match parse_password(args) {
                Ok(pass_command) => match pass_command {
                    PasswordCommand::Encrypt(pass_opts) => commands::pass_encrypt(pass_opts)?,
                    PasswordCommand::Decrypt(pass_opts) => commands::pass_decrypt(pass_opts)?,
                },
                Err(e) => print_usage_error(&e)?,
            }
        }
        _ => {
            print_usage_error("Invalid command")?;
        }
    }

    Ok(())
}

fn convert_args<T: AsRef<std::ffi::OsStr>>(args: &[T]) -> Result<Vec<String>, anyhow::Error> {
    let mut converted = Vec::<String>::new();
    for arg in args.iter() {
        let a = arg
            .as_ref()
            .to_str()
            .ok_or_else(|| anyhow!("Arguments must be valid UTF-8"))?
            .to_string();
        converted.push(a);
    }

    Ok(converted)
}

/// Return the remainder of the slice after the given index or the empty slice otherwise
fn slice_args<'a>(args: &'a [&'a str], idx: usize) -> &'a [&'a str] {
    let args: &'a [&'a str] = if args.len() > idx { &args[idx..] } else { &[] };

    args
}

fn print_help() {
    println!("{}", USAGE);
}

fn print_version() {
    println!("v{}", VERSION);
}

fn print_usage_error(msg: &str) -> Result<(), anyhow::Error> {
    Err(anyhow!("{}\n{}", msg, "For more info use '--help'"))
}

fn parse_encrypt(args: &[&str]) -> Result<EncryptOptions, String> {
    let mut encrypt_opts = Options::new();
    encrypt_opts.long_only(true);
    encrypt_opts.reqopt("t", "to", "Recipient key name", "NAME");
    encrypt_opts.reqopt("f", "from", "Sender key name", "NAME");
    encrypt_opts.optopt("o", "output", "Output file", "FILE");
    encrypt_opts.optopt("k", "keyring", "Keyring file", "FILE");
    encrypt_opts.optflag("", "env-pass", "read KESTREL_PASSWORD env var");

    let matches = match encrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(e.to_string()),
    };

    if matches.free.len() > 1 {
        return Err("Invalid usage".to_string());
    }

    let infile = if matches.free.len() == 1 {
        Some(matches.free[0].clone())
    } else {
        None
    };

    let to = matches.opt_str("t").unwrap();
    let from = matches.opt_str("f").unwrap();
    let outfile = matches.opt_str("o");
    let keyring = matches.opt_str("k");
    let env_pass = matches.opt_present("env-pass");

    Ok(EncryptOptions {
        infile,
        to,
        from,
        outfile,
        keyring,
        env_pass,
    })
}

fn parse_decrypt(args: &[&str]) -> Result<DecryptOptions, String> {
    let mut decrypt_opts = Options::new();
    decrypt_opts.long_only(true);
    decrypt_opts.reqopt("t", "to", "Recipient key name", "NAME");
    decrypt_opts.optopt("o", "output", "Output file", "FILE");
    decrypt_opts.optopt("k", "keyring", "Keyring file", "FILE");
    decrypt_opts.optflag("", "env-pass", "read KESTREL_PASSWORD env var");

    let matches = match decrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(format_parse_decrypt_error(e)),
    };

    if matches.free.len() > 1 {
        return Err("Invalid usage".to_string());
    }

    let infile = if matches.free.len() == 1 {
        Some(matches.free[0].clone())
    } else {
        None
    };

    let to = matches.opt_str("t").unwrap();
    let outfile = matches.opt_str("o");
    let keyring = matches.opt_str("k");
    let env_pass = matches.opt_present("env-pass");

    Ok(DecryptOptions {
        infile,
        to,
        outfile,
        keyring,
        env_pass,
    })
}

fn format_parse_decrypt_error(err: getopts::Fail) -> String {
    match err {
        getopts::Fail::UnrecognizedOption(ref o) => {
            // Tell users that the --from option isn't required while
            // decrypting.
            if o.as_str() == "f" || o.as_str() == "from" {
                format!("{}. '--from' is not required for decryption.", err)
            } else {
                err.to_string()
            }
        }
        _ => err.to_string(),
    }
}

fn parse_key(args: &[&str]) -> Result<KeyCommand, String> {
    if args.is_empty() {
        return Err("Invalid usage".to_string());
    }

    match args[0] {
        "gen" | "generate" => {
            let mut gen_opts = Options::new();
            gen_opts.long_only(true);
            gen_opts.optopt("o", "output", "Output file", "FILE");
            gen_opts.optflag("", "env-pass", "read KESTREL_PASSWORD env var");

            let args = slice_args(args, 1);

            let matches = match gen_opts.parse(args) {
                Ok(m) => m,
                Err(e) => return Err(e.to_string()),
            };

            let outfile = matches.opt_str("o");
            let env_pass = matches.opt_present("env-pass");

            Ok(KeyCommand::Generate(outfile, env_pass))
        }
        "change-pass" => {
            let mut change_opts = Options::new();
            change_opts.long_only(true);
            change_opts.optflag("", "env-pass", "read KESTREL_PASSWORD env var");

            let args = slice_args(args, 1);

            let matches = match change_opts.parse(args) {
                Ok(m) => m,
                Err(e) => return Err(e.to_string()),
            };

            let env_pass = matches.opt_present("env-pass");

            if matches.free.len() != 1 {
                return Err("Provide a private key".to_string());
            }

            let private_key = matches.free[0].clone();

            Ok(KeyCommand::ChangePass(private_key, env_pass))
        }
        "extract-pub" => {
            let mut extract_opts = Options::new();
            extract_opts.long_only(true);
            extract_opts.optflag("", "env-pass", "read KESTREL_PASSWORD env var");

            let args = slice_args(args, 1);

            let matches = match extract_opts.parse(args) {
                Ok(m) => m,
                Err(e) => return Err(e.to_string()),
            };

            let env_pass = matches.opt_present("env-pass");

            if matches.free.len() != 1 {
                return Err("Provide a private key".to_string());
            }

            let private_key = matches.free[0].clone();

            Ok(KeyCommand::ExtractPub(private_key, env_pass))
        }
        _ => Err("Invalid command".to_string()),
    }
}

fn parse_password(args: &[&str]) -> Result<PasswordCommand, String> {
    if args.is_empty() {
        return Err("Invalid usage".to_string());
    }

    match args[0] {
        "encrypt" | "enc" => {
            let args = slice_args(args, 1);
            match parse_pass_encrypt(args) {
                Ok(pass_opts) => Ok(PasswordCommand::Encrypt(pass_opts)),
                Err(e) => Err(e),
            }
        }
        "decrypt" | "dec" => {
            let args = slice_args(args, 1);
            match parse_pass_decrypt(args) {
                Ok(pass_opts) => Ok(PasswordCommand::Decrypt(pass_opts)),
                Err(e) => Err(e),
            }
        }
        _ => Err("Invalid command".to_string()),
    }
}

fn parse_pass_encrypt(args: &[&str]) -> Result<PasswordOptions, String> {
    let mut pass_encrypt_opts = Options::new();
    pass_encrypt_opts.long_only(true);
    pass_encrypt_opts.optopt("o", "output", "Output file", "FILE");
    pass_encrypt_opts.optflag("", "env-pass", "read KESTREL_PASSWORD env var");

    let matches = match pass_encrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(e.to_string()),
    };

    if matches.free.len() > 1 {
        return Err("Invalid usage".to_string());
    }

    let infile = if matches.free.len() == 1 {
        Some(matches.free[0].clone())
    } else {
        None
    };

    let outfile = matches.opt_str("o");
    let env_pass = matches.opt_present("env-pass");

    Ok(PasswordOptions {
        infile,
        outfile,
        env_pass,
    })
}

fn parse_pass_decrypt(args: &[&str]) -> Result<PasswordOptions, String> {
    let mut pass_decrypt_opts = Options::new();
    pass_decrypt_opts.long_only(true);
    pass_decrypt_opts.optopt("o", "output", "Output file", "FILE");
    pass_decrypt_opts.optflag("", "env-pass", "read KESTREL_PASSWORD env var");

    let matches = match pass_decrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(e.to_string()),
    };

    if matches.free.len() > 1 {
        return Err("Invalid usage".to_string());
    }

    let infile = if matches.free.len() == 1 {
        Some(matches.free[0].clone())
    } else {
        None
    };

    let outfile = matches.opt_str("o");
    let env_pass = matches.opt_present("env-pass");

    Ok(PasswordOptions {
        infile,
        outfile,
        env_pass,
    })
}
