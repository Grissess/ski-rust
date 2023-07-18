extern crate ski;

#[macro_use]
extern crate clap;

use std::io::{self, Write};
use std::fs;
use std::ffi::OsStr;

use ski::*;
use ski::coding::{Encodable, Decodable, CodedObject};

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
        &CodedObject::from_urn(
            args
                .value_of(name.clone())
                .ok_or_else(|| error::Error::MissingArgument(String::from(name)))?
        )?
    )
}

fn from_args<T: Decodable, S: AsRef<str> + Clone>(args: &clap::ArgMatches, name: S) -> error::Result<Vec<T>> where String: From<S> {
    match args.values_of(name.clone()) {
        None => Ok(vec![]),
        Some(values) => {
            let mut result = Vec::new();
            for v in values {
                result.push(T::decode(&CodedObject::from_urn(v)?)?);
            }
            Ok(result)
        },
    }
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

        ("rand", Some(args)) => {
            let bytes: usize = args.value_of("AMOUNT").unwrap().parse().unwrap();
            let mut result: Vec<u8> = Vec::with_capacity(bytes);
            result.extend(std::iter::repeat(0u8).take(bytes));
            csrng::fill_random(&mut result[..]);
            io::stdout().write_all(&result[..]).unwrap();
            0
        }

        ("key", Some(args)) => {
            match args.subcommand() {
                ("gen", Some(_args)) => {
                    println!("{}", key::Key::new().encode().as_urn());
                    0
                },

                ("pub", Some(args)) => {
                    let key: key::Key = from_arg(args, "KEY").unwrap();

                    println!("{}", key.public().encode().as_urn());
                    0
                },

                ("shared", Some(args)) => {
                    let privkey: key::Key = from_arg(args, "PRIVKEY").unwrap();
                    let pubkey: key::PubKey = from_arg(args, "PUBKEY").unwrap();

                    let shkey = privkey.shared_key(&pubkey);

                    println!("{}", shkey.encode().as_urn());
                    0
                },

                ("encrypt", Some(args)) => {
                    let privkey: key::Key = from_arg(args, "PRIVKEY").unwrap();
                    let pubkeys: Vec<key::PubKey> = from_args(args, "PUBKEY").unwrap();

                    let buffer = read_all_input(args.value_of_os("file")).unwrap();

                    let session = data::Session::from_keys_multiway(&privkey, &pubkeys);
                    let ciphertext = session.encrypt(&buffer);

                    let object = if args.is_present("multiway") {
                        data::encode_multiway(&ciphertext)
                    } else {
                        ciphertext.encode()
                    };

                    let output = if args.is_present("ascii") {
                        object.as_urn().into_bytes()
                    } else {
                        object.as_binary().unwrap()
                    };
                    io::stdout().write_all(&output).unwrap();
                    0
                },

                ("decrypt", Some(args)) => {
                    let privkey: key::Key = from_arg(args, "PRIVKEY").unwrap();
                    let pubkeys: Vec<key::PubKey> = from_args(args, "PUBKEY").unwrap();

                    let buffer = read_all_input(args.value_of_os("file")).unwrap();

                    let session = data::Session::from_keys_multiway(&privkey, &pubkeys);
                    let cipher = if args.is_present("ascii") {
                        CodedObject::from_urn(std::str::from_utf8(&buffer).unwrap()).unwrap()
                    } else {
                        CodedObject::from_binary(&buffer).unwrap()
                    };
                    let cipher = data::EncryptedData::decode(&cipher).unwrap();

                    let data = if args.is_present("index") {
                        let index: usize = args.value_of("index").unwrap().parse().unwrap();
                        let len = session.len_of(&cipher);
                        if index >= len {
                            Err::<(), _>(error::Error::IndexOutOfRange(index, len)).unwrap();
                        }
                        session.decrypt_index(&cipher, index).expect("no shared key found")
                    } else {
                        session.decrypt(&cipher).expect("no shared key found")
                    };

                    io::stdout().write_all(&data).unwrap();
                    0
                },

                ("sign", Some(args)) => {
                    let privkey: key::Key = from_arg(args, "PRIVKEY").unwrap();

                    let buffer = read_all_input(args.value_of_os("FILE")).unwrap();

                    let sig = if args.is_present("random") {
                        sig::Signature::sign_random(&privkey, &buffer)
                    } else {
                        sig::Signature::sign_deterministic(&privkey, &buffer)
                    };

                    if args.is_present("why") {
                        eprintln!("{:?}", sig.hash().as_ref().unwrap());
                    }

                    println!("{}", sig.encode().as_urn());
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
                    println!("{}", sym::Key::new().encode().as_urn());
                    0
                },

                ("derive", Some(_args)) => {
                    let pass = rpassword::prompt_password_stderr("Password: ").unwrap();
                    let hasher = kdf::KeyDerivation::new();
                    let mut output = [0u8; sym::Key::SIZE];
                    hasher.hash(pass.as_bytes(), &mut output);
                    println!("{}", (sym::Key { bytes: output }).encode().as_urn());
                    0
                },

                ("encrypt", Some(args)) => {
                    let key: sym::Key = from_arg(args, "KEY").unwrap();

                    let buffer = read_all_input(args.value_of_os("FILE")).unwrap();

                    let cipher = key.cipher();
                    let data = cipher.encipher(&buffer);
                    let output = if args.is_present("ascii") {
                        data.encode().as_urn().into_bytes()
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
                            CodedObject::from_urn(std::str::from_utf8(&buffer).unwrap()).unwrap()
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

                ("rand", Some(args)) => {
                    let input = read_all_input(args.value_of_os("file")).unwrap();
                    let needed_bytes = sym::Key::SIZE + sym::Key::NONCE;
                    if input.len() < needed_bytes {
                        panic!("need at least {} bytes of previous state", needed_bytes);
                    }
                    let iv: Vec<u8> = if args.is_present("iv") {
                        args.value_of("iv").unwrap().as_bytes().into()
                    } else {
                        std::iter::repeat(0x5au8).take(input.len()).collect()
                    };
                    let mut key = sym::Key { bytes: [0u8; sym::Key::SIZE] };
                    key.bytes.copy_from_slice(&input[.. sym::Key::SIZE]);
                    let mut nonce = [0u8; sym::Key::NONCE];
                    nonce.copy_from_slice(&input[sym::Key::SIZE .. needed_bytes]);
                    let cipher = key.cipher_with_nonce(nonce);
                    let state = cipher.encipher(&iv);
                    io::stdout().write_all(&state.data).unwrap();
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
