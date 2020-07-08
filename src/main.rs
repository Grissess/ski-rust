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
pub mod sig;

use coding::{Encodable, Decodable, CodedObject};

fn get_input(filename: Option<&OsStr>) -> io::Result<Box<dyn io::Read>> {
    match filename {
        None => Ok(Box::new(io::stdin())),
        Some(name) => fs::File::open(name).map(|file| Box::new(file) as Box<dyn io::Read>),
    }
}

fn read_all_input(filename: Option<&OsStr>) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut input = get_input(filename)?;
    input.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn from_arg<T: Decodable, S: AsRef<str> + Clone>(args: &clap::ArgMatches, name: S) -> error::Result<T> where String: From<S> {
    T::decode(
        &CodedObject::from_uri(
            args
                .value_of(name.clone())
                .ok_or_else(|| error::Error::MissingArgument(String::from(name)))?
        )?
    )
}

fn main() {
    let arg_config = load_yaml!("args.yml");
    let matches = clap::App::from_yaml(arg_config).get_matches();

    std::process::exit(match matches.subcommand() {
        ("encode", Some(args)) => {
            let buffer = read_all_input(args.value_of_os("FILE")).unwrap();
            io::stdout().write_all(coding::encode(buffer).as_bytes()).unwrap();
            0
        },

        ("decode", Some(args)) => {
            let buffer = read_all_input(args.value_of_os("FILE")).unwrap();
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
                    let key: key::Key = from_arg(args, "KEY").unwrap();

                    println!("{}", key.public().encode().as_uri());
                    0
                },

                ("shared", Some(args)) => {
                    let privkey: key::Key = from_arg(args, "PRIVKEY").unwrap();
                    let pubkey: key::PubKey = from_arg(args, "PUBKEY").unwrap();

                    let shkey = privkey.shared_key(&pubkey);

                    println!("{}", shkey.encode().as_uri());
                    0
                },

                ("encrypt", Some(args)) => {
                    let privkey: key::Key = from_arg(args, "PRIVKEY").unwrap();
                    let pubkey: key::PubKey = from_arg(args, "PUBKEY").unwrap();

                    let buffer = read_all_input(args.value_of_os("FILE")).unwrap();

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
                    let privkey: key::Key = from_arg(args, "PRIVKEY").unwrap();
                    let pubkey: key::PubKey = from_arg(args, "PUBKEY").unwrap();

                    let buffer = read_all_input(args.value_of_os("FILE")).unwrap();

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

                ("sign", Some(args)) => {
                    let privkey: key::Key = from_arg(args, "PRIVKEY").unwrap();

                    let buffer = read_all_input(args.value_of_os("FILE")).unwrap();

                    let sig = sig::Signature::sign(&privkey, &buffer);

                    if args.is_present("why") {
                        eprintln!("{:?}", sig.hash().as_ref().unwrap());
                    }

                    println!("{}", sig.encode().as_uri());
                    0
                },

                ("verify", Some(args)) => {
                    let pubkey: key::PubKey = from_arg(args, "PUBKEY").unwrap();
                    let sig: sig::Signature = from_arg(args, "SIGNATURE").unwrap();

                    let buffer = read_all_input(args.value_of_os("FILE")).unwrap();

                    if args.is_present("why") {
                        let reason = sig.verify_reason(&pubkey, &buffer);
                        if let Some(err) = reason {
                            println!("failed: {:?}", err);
                            1
                        } else {
                            println!("success");
                            0
                        }
                    } else {
                        if sig.verify(&pubkey, &buffer) {
                            println!("success");
                            0
                        } else {
                            println!("failed");
                            1
                        }
                    }
                },

                _ => {
                    eprintln!("{}", args.usage());
                    2
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
                    let key: sym::Key = from_arg(args, "KEY").unwrap();

                    let buffer = read_all_input(args.value_of_os("FILE")).unwrap();

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
                    let key: sym::Key = from_arg(args, "KEY").unwrap();

                    let buffer = read_all_input(args.value_of_os("FILE")).unwrap();

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
                    2
                },
            }
        },

        _ => {
            eprintln!("{}", matches.usage());
            2
        },
    })
}
