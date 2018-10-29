extern crate clap;
extern crate rpassword;
extern crate ring;
extern crate clipboard;

use clap::{Arg, App};
use ring::{digest, pbkdf2};

use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA512;
static DEFAULT_ALPHABET: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-%$#.!@^&*()";

fn generate_password(master_password: &str, _salt: &str, _version: u32, length: usize, _alphabet: &str, _purpose: &str) -> String {
    let alphabet = _alphabet.chars().collect::<Vec<char>>();
    let salt =_salt.as_bytes();
    let version = _version.to_string();

    let iterations = 800000;

    let mut hashable = _purpose.to_string();
    hashable.push_str(&version);
    hashable.push_str(&master_password);

    let mut to_store = vec![0u8; length];
    pbkdf2::derive(DIGEST_ALG, iterations, salt, hashable.as_bytes(), &mut to_store);

    to_store.iter()
        .map(|i| alphabet[((*i as f64 / 256.0) * alphabet.len() as f64) as usize])
        .collect::<String>()
}

fn main() {
    let matches = App::new("sinkless")
        .version("0.0.1")
        .author("kybernetikos <me@kybernetikos.com>")
        .about("A password generator that does away with syncing.  Soon with added emojis.")
        .arg(Arg::with_name("purpose")
            .required(true)
            .takes_value(true)
            .index(1)
            .help("The purpose for which we want a password, e.g. firefox or for a webpage https://accounts.google.com."))
        .arg(Arg::with_name("revision")
            .takes_value(true)
            .index(2)
            .default_value("0")
            .help("The version of the password to generate."))
        .arg(Arg::with_name("length")
            .takes_value(true)
            .index(3)
            .default_value("40")
            .help("How long a password should be generated."))
        .arg(Arg::with_name("salt")
            .takes_value(true)
            .index(4)
            .default_value("salt")
            .help("A salt.  Should be user specific."))
        .arg(Arg::with_name("alphabet")
            .takes_value(true)
            .index(5)
            .default_value(DEFAULT_ALPHABET)
            .help("The alphabet to use for the generated password."))
        .arg(Arg::with_name("password")
            .takes_value(true)
            .index(6)
            .help("The master password. If not provided, this will be prompted for at the command line."))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .help("Output to stdout"))
        .arg(Arg::with_name("clipboard")
            .short("c")
            .long("clipboard")
            .help("Output to clipboard. Will do this by default if output to stdout isn't configured."))
        .get_matches();

    let purpose = matches.value_of("purpose").unwrap();
    let password = match matches.value_of("password") {
        Some(pass) => pass.to_string(),
        None => rpassword::prompt_password_stderr("Password: ").unwrap()
    };
    let should_output = matches.is_present("output");
    let alphabet = matches.value_of("alphabet").unwrap();
    let salt = matches.value_of("salt").unwrap();
    let version = matches.value_of("revision").unwrap().parse().unwrap();
    let length = matches.value_of("length").unwrap().parse().unwrap();

    let result = generate_password(&password, salt, version, length, alphabet, purpose);

    if should_output {
        println!("{}", result);
    }

    if !should_output || matches.is_present("clipboard") {
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(result).unwrap();
        eprintln!("Stored to clipboard");
    }
}