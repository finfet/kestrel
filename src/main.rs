mod commands;
mod crypto;
mod decrypt;
mod encrypt;
mod errors;
mod keyring;

use anyhow::anyhow;
use getopts::Options;

use commands::{DecryptOptions, EncryptOptions, KeyCommand, PasswordCommand, PasswordOptions};

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

const USAGE: &str = "USAGE:
    wren encrypt FILE -t NAME -f NAME [-o FILE] [-k KEYRING] [-p PASS]
    wren decrypt FILE -t NAME [-o FILE] [-k KEYRING] [-p PASS]
    wren key generate NAME
    wren key change-pass PRIVATE-KEY
    wren key extract-pub PRIVATE-KEY
    wren password encrypt|decrypt FILE [-o FILE] [-p PASS]

    Aliases enc, dec, and pass can be used as encrypt, decrypt, and password.
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
        "key" => match parse_key(args.as_slice()) {
            Ok(key_command) => match key_command {
                KeyCommand::Generate(key_name) => commands::gen_key(key_name)?,
                KeyCommand::ChangePass(priv_key) => commands::change_pass(priv_key)?,
                KeyCommand::ExtractPub(priv_key) => commands::extract_pub(priv_key)?,
            },
            Err(e) => print_usage(e)?,
        },
        "password" | "pass" => match parse_password(args.as_slice()) {
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
    if args.len() < 3 {
        return Err(Some("Not enough arguments".to_string()));
    }

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

fn parse_key(args: &[&str]) -> Result<KeyCommand, Option<String>> {
    if args.len() < 4 {
        return Err(Some("Not enough arguments".to_string()));
    }

    match args[2] {
        "generate" => match parse_gen_key(&args[3..]) {
            Ok(key_name) => Ok(KeyCommand::Generate(key_name)),
            Err(e) => Err(e),
        },
        "change-pass" => match parse_change_pass(&args[3..]) {
            Ok(priv_key) => Ok(KeyCommand::ChangePass(priv_key)),
            Err(e) => Err(e),
        },
        "extract-pub" => match parse_extract_pub(&args[3..]) {
            Ok(priv_key) => Ok(KeyCommand::ExtractPub(priv_key)),
            Err(e) => Err(e),
        },
        _ => {
            return Err(None);
        }
    }
}

fn parse_gen_key(args: &[&str]) -> Result<String, Option<String>> {
    let gen_key_opts = Options::new();

    let matches = match gen_key_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some(
            "Give the key a name like Alice or Mallory".to_string(),
        ));
    }

    let key_name = matches.free[0].clone();

    Ok(key_name)
}

fn parse_change_pass(args: &[&str]) -> Result<String, Option<String>> {
    let change_pass_opts = Options::new();

    let matches = match change_pass_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Provide the private key string".to_string()));
    }

    let priv_key = matches.free[0].clone();

    Ok(priv_key)
}

fn parse_extract_pub(args: &[&str]) -> Result<String, Option<String>> {
    let extract_pub_opts = Options::new();

    let matches = match extract_pub_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Provide the private key string".to_string()));
    }

    let priv_key = matches.free[0].clone();

    Ok(priv_key)
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
    pass_encrypt_opts.optopt("p", "password", "Password", "PASS");

    let matches = match pass_encrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Specify an input file to encrypt".to_string()));
    }

    let infile = matches.free[0].clone();
    let outfile = matches.opt_str("o");
    let pass = matches.opt_str("p");

    Ok(PasswordOptions {
        infile,
        outfile,
        pass,
    })
}

fn parse_pass_decrypt(args: &[&str]) -> Result<PasswordOptions, Option<String>> {
    let mut pass_decrypt_opts = Options::new();
    pass_decrypt_opts.optopt("o", "output", "Output file", "FILE");
    pass_decrypt_opts.optopt("p", "password", "Password", "PASS");

    let matches = match pass_decrypt_opts.parse(args) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string())),
    };

    if matches.free.len() != 1 {
        return Err(Some("Specify an input file to decrypt".to_string()));
    }

    let infile = matches.free[0].clone();
    let outfile = matches.opt_str("o");
    let pass = matches.opt_str("p");

    Ok(PasswordOptions {
        infile,
        outfile,
        pass,
    })
}
