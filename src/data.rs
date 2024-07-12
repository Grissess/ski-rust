use crate::error;
use crate::coding::{Encodable, Decodable, CodedObject};
use crate::key::{self, PubKey, SharedKey};
use crate::sym::{self, EncipheredData};
use crate::sig::{SignatureHash, SIG_HASH_SIZE};

use std::convert::TryFrom;

use crypto::util::fixed_time_eq;
use crypto::digest::Digest;

#[derive(Debug, Clone)]
pub struct Session {
    keys: Vec<SharedKey>,
}

#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub session_keys: Vec<EncipheredData>,
    pub data: EncipheredData,
    pub hash: Option<EncipheredData>,
}

impl From<SharedKey> for sym::Key {
    fn from(key: SharedKey) -> sym::Key {
        sym::Key { bytes: key.bytes }
    }
}

impl Session {
    pub fn from_keys(private: &key::Key, public: &PubKey) -> Session {
        Session {
            keys: vec![private.shared_key(public)],
        }
    }

    pub fn from_keys_multiway(private: &key::Key, publics: &[PubKey]) -> Session {
        Session {
            keys: publics.iter().map(|pk| private.shared_key(pk)).collect(),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> EncryptedData {
        let session_key = sym::Key::new();
        let mut hash = [0u8; SIG_HASH_SIZE];
        let mut hasher = SignatureHash::new();
        hasher.input(data);
        hasher.result(&mut hash);
        let cipherdata = session_key.cipher().encipher(data);
        let ciphered_keys: Vec<_> = self.keys.iter().map(|sk| {
            sym::Key::from(sk.clone()).cipher().encipher(&session_key.bytes)
        }).collect();

        EncryptedData {
            session_keys: ciphered_keys,
            data: cipherdata,
            hash: Some(session_key.cipher().encipher(&hash)),
        }
    }

    pub fn decrypt_index(&self, data: &EncryptedData, index: usize) -> Option<Vec<u8>> {
        for key in &self.keys {
            let cipher = sym::Key::from(key.clone()).cipher_for_data(&data.session_keys[index]);
            let session_key = sym::Key {
                bytes: {
                    let mut bytes = [0u8; sym::Key::SIZE];
                    bytes.copy_from_slice(&cipher.decipher(&data.session_keys[index]));
                    bytes
                },
            };
            let cipher = session_key.cipher_for_data(&data.data);
            let plain = cipher.decipher(&data.data);
            if let Some(hash_data) = &data.hash {
                let mut hasher = SignatureHash::new();
                let mut hash = [0u8; SIG_HASH_SIZE];
                hasher.input(&plain);
                hasher.result(&mut hash);
                let hash_result = session_key.cipher_for_data(&hash_data).decipher(&hash_data);
                if fixed_time_eq(&hash, &hash_result) {
                    return Some(plain);
                }
            } else {
                return Some(plain);
            }
        }
        None
    }

    pub fn decrypt(&self, data: &EncryptedData) -> Option<Vec<u8>> {
        for index in 0 .. self.len_of(data) {
            if let Some(data) = self.decrypt_index(data, index) {
                return Some(data);
            }
        }
        None
    }

    pub fn len_of(&self, data: &EncryptedData) -> usize { data.session_keys.len() }
}

impl From<&SharedKey> for Session {
    fn from(key: &SharedKey) -> Session {
        Session { keys: vec![key.clone()] }
    }
}

impl From<SharedKey> for Session {
    fn from(key: SharedKey) -> Session {
        Session { keys: vec![key] }
    }
}

pub const ENCRYPTED_DATA_SCHEME: &'static str = "ski:encr";
pub const MULTIWAY_ENCRYPTED_DATA_SCHEME: &'static str = "ski:enmw";

pub fn encode_multiway(ec: &EncryptedData) -> CodedObject {
    let mut data = Vec::new();
    data.push(u8::try_from(ec.session_keys.len()).unwrap());
    for sk in &ec.session_keys {
        let co = sk.encode();
        data.push(u8::try_from(co.bytes.len()).unwrap());
        data.extend(&co.bytes);
    }
    let hash = ec.hash.as_ref().unwrap().encode();
    data.push(u8::try_from(hash.bytes.len()).unwrap());
    data.extend(&hash.bytes);
    data.extend(&ec.data.encode().bytes);
    CodedObject {
        scheme: MULTIWAY_ENCRYPTED_DATA_SCHEME.into(),
        bytes: data,
    }
}

impl Encodable for EncryptedData {
    fn encode(&self) -> CodedObject {
        if self.session_keys.len() == 1 {
            let co = self.session_keys[0].encode();
            let mut data = Vec::new();
            data.push(u8::try_from(co.bytes.len()).unwrap());
            data.extend(&co.bytes);
            data.extend(&self.data.encode().bytes);
            CodedObject {
                scheme: ENCRYPTED_DATA_SCHEME.into(),
                bytes: data,
            }
        } else {
            encode_multiway(self)
        }
    }
}

impl Decodable for EncryptedData {
    fn decode(input: &CodedObject) -> error::Result<Self> {
        if let Ok(_) = input.expect_scheme(ENCRYPTED_DATA_SCHEME) {
            let session_len = input.bytes[0] as usize;
            let session_key = EncipheredData::decode(
                &CodedObject {
                    scheme: crate::sym::SYMMETRICALLY_ENCRYPTED_DATA_SCHEME.into(),
                    bytes: input.bytes[1 .. session_len + 1].into(),
                },
            )?;
            let data = EncipheredData::decode(
                &CodedObject {
                    scheme: crate::sym::SYMMETRICALLY_ENCRYPTED_DATA_SCHEME.into(),
                    bytes: input.bytes[session_len + 1 ..].into(),
                },
            )?;
            Ok(EncryptedData {
                session_keys: vec![session_key], data, hash: None
            })
        } else {
            input.expect_scheme(MULTIWAY_ENCRYPTED_DATA_SCHEME)?;
            let num_keys = input.bytes[0] as usize;
            let mut session_keys = Vec::new();
            let mut byte_offset = 1usize;
            for _ in 0 .. num_keys {
                let key_len = input.bytes[byte_offset] as usize;
                byte_offset += 1;
                session_keys.push(EncipheredData::decode(
                    &CodedObject {
                        scheme: crate::sym::SYMMETRICALLY_ENCRYPTED_DATA_SCHEME.into(),
                        bytes: input.bytes[byte_offset .. byte_offset + key_len].into(),
                    },
                )?);
                byte_offset += key_len;
            }
            let hash_len = input.bytes[byte_offset] as usize;
            byte_offset += 1;
            let hash = EncipheredData::decode(&CodedObject {
                scheme: crate::sym::SYMMETRICALLY_ENCRYPTED_DATA_SCHEME.into(),
                bytes: input.bytes[byte_offset .. byte_offset + hash_len].into(),
            })?;
            byte_offset += hash_len;
            let data = EncipheredData::decode(
                &CodedObject {
                    scheme: crate::sym::SYMMETRICALLY_ENCRYPTED_DATA_SCHEME.into(),
                    bytes: input.bytes[byte_offset ..].into(),
                },
            )?;
            Ok(EncryptedData {
                session_keys, data, hash: Some(hash),
            })
        }
    }
}
