use std::error::Error;
use std::process::exit;
use getopts::Options;

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

const USAGE: &str = "USAGE:
    wren encrypt FILE -t NAME -f NAME [-o FILE] [-k KEYRING] [-p PASS]
    wren decrypt FILE -t NAME [-o FILE] [-k KEYRING] [-p PASS]
    wren gen-key NAME
    wren change-pass PRIVATE-KEY [-p PASS]
    wren extract-pub PRIVATE-KEY [-p PASS]
    wren pass-enc FILE [-o FILE] [-p PASS]
    wren pass-dec FILE [-o FILE] [-p PASS]

    Aliases enc and dec can be used for encrypt and decrypt.
    Option -k is required unless the WREN_KEYRING environment variable
    points to a keyring file.

OPTIONS:
    -t, --to        Recipient key name. Decrypt requires a private key.
    -f, --from      Sender key name. Must be a private key.
    -o, --output    Output file name.
    -k, --keyring   Location of a keyring file.
    -p, --password  Password of private key. Prefer interactive prompt.
    -h, --help      Print help information.
    -v, --version   Print version information.
";

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 1 {
        print_usage();
        exit(1);
    }

    match parse_prog_flags(&args[1..]) {
        Ok(_) => return Ok(()),
        Err(e) => {
            match e {
                Some(e) => eprintln!("{}\nError: {}", USAGE, e),
                None => print_usage()
            }
            exit(1);
        }
    }
}

// Prints -v and -h options
fn parse_prog_flags(args: &[String]) -> Result<(), Option<String>> {
    if args[0] == "-v" || args[0] == "--version" {
        print_version();
        return Ok(());
    }

    if args[0] == "-h" || args[0] == "--help" {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        "gen-key" => {
            let gen_key_opts = Options::new();
            let matches = match gen_key_opts.parse(&args[1..]) {
                Ok(m) => m,
                Err(e) => return Err(Some(e.to_string()))
            };

            if matches.free.len() != 1 {
                return Err(Some("Give the key a name like Alice or Mallory".to_string()));
            }

            let key_name = matches.free[0].clone();
            println!("Generating key for: {}", key_name);
        }
        _ => {
            return Err(None);
        }
    }

    Ok(())
}

fn print_help() {
    println!("{}", USAGE);
}

fn print_usage() {
    eprintln!("{}", USAGE);
}

fn print_version() {
    println!("v{}", VERSION.unwrap_or("0.0.1"));
}