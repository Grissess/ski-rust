use crate::error;
use crate::coding::{Encodable, Decodable, CodedObject};
use crate::key::{self, PubKey, SharedKey};
use crate::sym::{self, EncipheredData};

use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct Session {
    key: SharedKey,
}

#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub session_key: EncipheredData,
    pub data: EncipheredData,
}

impl From<SharedKey> for sym::Key {
    fn from(key: SharedKey) -> sym::Key {
        sym::Key { bytes: key.bytes }
    }
}

impl Session {
    pub fn from_keys(private: &key::Key, public: &PubKey) -> Session {
        Session {
            key: private.shared_key(public),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> EncryptedData {
        let session_key = sym::Key::new();
        let cipherdata = session_key.cipher().encipher(data);
        let cipherkey = sym::Key::from(self.key.clone()).cipher().encipher(&session_key.bytes);
        EncryptedData {
            session_key: cipherkey,
            data: cipherdata,
        }
    }

    pub fn decrypt(&self, data: &EncryptedData) -> Vec<u8> {
        let cipher = sym::Key::from(self.key.clone()).cipher_for_data(&data.session_key);
        let session_key = sym::Key {
            bytes: {
                let mut bytes = [0u8; sym::Key::SIZE];
                bytes.copy_from_slice(&cipher.decipher(&data.session_key));
                bytes
            },
        };
        let cipher = session_key.cipher_for_data(&data.data);
        cipher.decipher(&data.data)
    }
}

impl From<&SharedKey> for Session {
    fn from(key: &SharedKey) -> Session {
        Session { key: key.clone() }
    }
}

impl From<SharedKey> for Session {
    fn from(key: SharedKey) -> Session {
        Session { key }
    }
}

pub const ENCRYPTED_DATA_SCHEME: &'static str = "ski-encr";

impl Encodable for EncryptedData {
    fn encode(&self) -> CodedObject {
        let co = self.session_key.encode();
        let mut data = Vec::new();
        data.push(u8::try_from(co.bytes.len()).unwrap());
        data.extend(&co.bytes);
        data.extend(&self.data.encode().bytes);
        CodedObject {
            scheme: ENCRYPTED_DATA_SCHEME.into(),
            bytes: data,
        }
    }
}

impl Decodable for EncryptedData {
    fn decode(input: &CodedObject) -> error::Result<Self> {
        input.expect_scheme(ENCRYPTED_DATA_SCHEME)?;
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
            session_key, data,
        })
    }
}
