use getopts::Options;
use anyhow::anyhow;

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
        "gen-key" => {
            match parse_gen_key(args.as_slice()) {
                Ok(name) => run_gen_key(name)?,
                Err(e) => print_usage(e)?
            }
        }
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

fn parse_gen_key(args: &[&str]) -> Result<String, Option<String>> {
    let gen_key_opts = Options::new();
    let matches = match gen_key_opts.parse(&args[2..]) {
        Ok(m) => m,
        Err(e) => return Err(Some(e.to_string()))
    };

    if matches.free.len() != 1 {
        return Err(Some("Give the key a name like Alice or Mallory".to_string()));
    }

    Ok(matches.free[0].clone())
}

fn run_gen_key(name: String) -> Result<(), anyhow::Error> {
    println!("Generating key for: {}", name);
    Ok(())
}
