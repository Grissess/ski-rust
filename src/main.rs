extern crate base64;
extern crate crypto;
#[macro_use]
extern crate clap;
extern crate rand;
extern crate rpassword;
extern crate argon2rs;

use std::io::{self, Write};
use std::fs;
use std::ffi::OsStr;

pub mod error;
pub mod coding;
pub mod key;
pub mod sym;
pub mod csrng;
pub mod kdf;
pub mod data;

use coding::{Encodable, Decodable, CodedObject};

fn get_input(filename: Option<&OsStr>) -> io::Result<Box<dyn io::Read>> {
    match filename {
        None => Ok(Box::new(io::stdin())),
        Some(name) => fs::File::open(name).map(|file| Box::new(file) as Box<dyn io::Read>),
    }
}

fn main() {
    let arg_config = load_yaml!("args.yml");
    let matches = clap::App::from_yaml(arg_config).get_matches();

    std::process::exit(match matches.subcommand() {
        ("encode", Some(args)) => {
            let mut input = get_input(args.value_of_os("FILE")).unwrap();
            let mut buffer: Vec<u8> = Vec::new();
            input.read_to_end(&mut buffer).unwrap();
            io::stdout().write_all(coding::encode(buffer).as_bytes()).unwrap();
            0
        },

        ("decode", Some(args)) => {
            let mut input = get_input(args.value_of_os("FILE")).unwrap();
            let mut buffer: Vec<u8> = Vec::new();
            input.read_to_end(&mut buffer).unwrap();
            io::stdout().write_all(&coding::decode(buffer).unwrap()).unwrap();
            0
        },

        ("key", Some(args)) => {
            match args.subcommand() {
                ("gen", Some(_args)) => {
                    println!("{}", key::Key::new().encode().as_uri());
                    0
                },

                ("pub", Some(args)) => {
                    let key = key::Key::decode(
                        &CodedObject::from_uri(args.value_of("KEY").unwrap()).unwrap()
                    ).unwrap();

                    println!("{}", key.public().encode().as_uri());
                    0
                },

                ("shared", Some(args)) => {
                    let privkey = key::Key::decode(
                        &CodedObject::from_uri(args.value_of("PRIVKEY").unwrap()).unwrap()
                    ).unwrap();
                    let pubkey = key::PubKey::decode(
                        &CodedObject::from_uri(args.value_of("PUBKEY").unwrap()).unwrap()
                    ).unwrap();

                    let shkey = privkey.shared_key(&pubkey);

                    println!("{}", shkey.encode().as_uri());
                    0
                },

                ("encrypt", Some(args)) => {
                    let privkey = key::Key::decode(
                        &CodedObject::from_uri(args.value_of("PRIVKEY").unwrap()).unwrap()
                    ).unwrap();
                    let pubkey = key::PubKey::decode(
                        &CodedObject::from_uri(args.value_of("PUBKEY").unwrap()).unwrap()
                    ).unwrap();

                    let mut buffer: Vec<u8> = Vec::new();
                    let mut input = get_input(args.value_of_os("FILE")).unwrap();
                    input.read_to_end(&mut buffer).unwrap();

                    let session = data::Session::from_keys(&privkey, &pubkey);
                    let ciphertext = session.encrypt(&buffer);

                    let output = if args.is_present("ascii") {
                        ciphertext.encode().as_uri().into_bytes()
                    } else {
                        ciphertext.encode().as_binary().unwrap()
                    };
                    io::stdout().write_all(&output).unwrap();
                    0
                },

                ("decrypt", Some(args)) => {
                    let privkey = key::Key::decode(
                        &CodedObject::from_uri(args.value_of("PRIVKEY").unwrap()).unwrap()
                    ).unwrap();
                    let pubkey = key::PubKey::decode(
                        &CodedObject::from_uri(args.value_of("PUBKEY").unwrap()).unwrap()
                    ).unwrap();

                    let mut buffer: Vec<u8> = Vec::new();
                    let mut input = get_input(args.value_of_os("FILE")).unwrap();
                    input.read_to_end(&mut buffer).unwrap();

                    let session = data::Session::from_keys(&privkey, &pubkey);
                    let cipher = if args.is_present("ascii") {
                        CodedObject::from_uri(std::str::from_utf8(&buffer).unwrap()).unwrap()
                    } else {
                        CodedObject::from_binary(&buffer).unwrap()
                    };
                    let cipher = data::EncryptedData::decode(&cipher).unwrap();

                    io::stdout().write_all(&session.decrypt(&cipher)).unwrap();
                    0
                },

                _ => {
                    eprintln!("{}", args.usage());
                    1
                },
            }
        },

        ("sym", Some(args)) => {
            match args.subcommand() {
                ("gen", Some(_args)) => {
                    println!("{}", sym::Key::new().encode().as_uri());
                    0
                },

                ("derive", Some(_args)) => {
                    let pass = rpassword::prompt_password_stderr("Password: ").unwrap();
                    let hasher = kdf::KeyDerivation::new();
                    let mut output = [0u8; sym::Key::SIZE];
                    hasher.hash(pass.as_bytes(), &mut output);
                    println!("{}", (sym::Key { bytes: output }).encode().as_uri());
                    0
                },

                ("encrypt", Some(args)) => {
                    let key = sym::Key::decode(
                        &CodedObject::from_uri(args.value_of("KEY").unwrap()).unwrap()
                    ).unwrap();
                    let mut input = get_input(args.value_of_os("FILE")).unwrap();
                    let mut buffer: Vec<u8> = Vec::new();
                    input.read_to_end(&mut buffer).unwrap();
                    let cipher = key.cipher();
                    let data = cipher.encipher(&buffer);
                    let output = if args.is_present("ascii") {
                        data.encode().as_uri().into_bytes()
                    } else {
                        data.encode().as_binary().unwrap()
                    };
                    io::stdout().write_all(&output).unwrap();
                    0
                },

                ("decrypt", Some(args)) => {
                    let key = sym::Key::decode(
                        &CodedObject::from_uri(args.value_of("KEY").unwrap()).unwrap()
                    ).unwrap();
                    let mut input = get_input(args.value_of_os("FILE")).unwrap();
                    let mut buffer: Vec<u8> = Vec::new();
                    input.read_to_end(&mut buffer).unwrap();
                    let data = {
                        let co = if args.is_present("ascii") {
                            CodedObject::from_uri(std::str::from_utf8(&buffer).unwrap()).unwrap()
                        } else {
                            CodedObject::from_binary(&buffer).unwrap()
                        };

                        sym::EncipheredData::decode(&co).unwrap()
                    };
                    let cipher = key.cipher_for_data(&data);
                    let plain = cipher.decipher(&data);
                    io::stdout().write_all(&plain).unwrap();
                    0
                },

                _ => {
                    eprintln!("{}", args.usage());
                    1
                },
            }
        },

        _ => {
            eprintln!("{}", matches.usage());
            1
        },
    })
}
