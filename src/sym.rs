use crate::error;
use crate::coding::{Encodable, Decodable, CodedObject};
use crate::csrng::fill_random;

use crypto::chacha20::ChaCha20;
use crypto::symmetriccipher::SynchronousStreamCipher;

#[derive(Debug, Clone)]
pub struct Key {
    pub bytes: [u8; 32],
}

pub struct Cipher {
    nonce: [u8; 24],
    state: ChaCha20,
}

#[derive(Debug, Clone)]
pub struct EncipheredData {
    pub nonce: [u8; 24],
    pub data: Vec<u8>,
}


impl Key {
    pub const SIZE: usize = 32;
    pub const NONCE: usize = 24;

    pub fn new() -> Key {
        let mut bytes = [0u8; 32];
        fill_random(&mut bytes);
        Key { bytes }
    }

    pub fn cipher_with_nonce(&self, nonce: [u8; 24]) -> Cipher {
        Cipher {
            nonce,
            state: ChaCha20::new_xchacha20(&self.bytes, &nonce),
        }
    }

    pub fn cipher(&self) -> Cipher {
        let mut nonce = [0u8; 24];
        fill_random(&mut nonce);
        self.cipher_with_nonce(nonce)
    }

    pub fn cipher_for_data(&self, enciphered_data: &EncipheredData) -> Cipher {
        self.cipher_with_nonce(enciphered_data.nonce.clone())
    }
}

impl Cipher {
    pub fn encipher(mut self, input: &[u8]) -> EncipheredData {
        let mut output: Vec<u8> = Vec::with_capacity(input.len());
        output.extend(std::iter::repeat(0).take(input.len()));
        self.state.process(input, &mut output);
        EncipheredData {
            nonce: self.nonce,
            data: output,
        }
    }

    pub fn decipher(mut self, input: &EncipheredData) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::with_capacity(input.data.len());
        output.extend(std::iter::repeat(0).take(input.data.len()));
        self.state.process(&input.data, &mut output);
        output
    }
}

pub const SYMMETRIC_KEY_SCHEME: &'static str = "ski:symk";
pub const SYMMETRICALLY_ENCRYPTED_DATA_SCHEME: &'static str = "ski:syed";

impl Encodable for Key {
    fn encode(&self) -> CodedObject {
        CodedObject {
            scheme: SYMMETRIC_KEY_SCHEME.into(),
            bytes: self.bytes.into(),
        }
    }
}

impl Decodable for Key {
    fn decode(input: &CodedObject) -> error::Result<Self> {
        input.expect_scheme(SYMMETRIC_KEY_SCHEME)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&input.bytes);
        Ok(Key { bytes })
    }
}

impl Encodable for EncipheredData {
    fn encode(&self) -> CodedObject {
        let mut bytes = Vec::with_capacity(self.data.len() + self.nonce.len());
        bytes.extend(&self.nonce);
        bytes.extend(&self.data);
        CodedObject {
            scheme: SYMMETRICALLY_ENCRYPTED_DATA_SCHEME.into(),
            bytes,
        }
    }
}

impl Decodable for EncipheredData {
    fn decode(input: &CodedObject) -> error::Result<Self> {
        input.expect_scheme(SYMMETRICALLY_ENCRYPTED_DATA_SCHEME)?;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&input.bytes[..24]);
        Ok(EncipheredData {
            nonce,
            data: (&input.bytes[24..]).into(),
        })
    }
}
