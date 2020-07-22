use crate::error::{self, Error};
use crate::coding::{Encodable, Decodable, CodedObject};
use crate::csrng::fill_random;

use crypto::curve25519::{ge_scalarmult_base, curve25519, Fe};

#[derive(Debug, Clone)]
pub struct PubKey {
    pub bytes: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Key {
    pub bytes: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SharedKey {
    pub bytes: [u8; 32],
}

impl From<&Key> for PubKey {
    fn from(key: &Key) -> PubKey {
        PubKey {
            bytes: ge_scalarmult_base(&key.bytes).to_bytes(),
        }
    }
}

impl PubKey {
    pub fn montgomery_field(&self) -> Fe {
        let this = Fe::from_bytes(&self.bytes);
        let z = Fe([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let x = z + this;
        let z = (z - this).invert();
        x * z
    }
}

impl Key {
    pub fn from_bytes(bytes: &[u8]) -> error::Result<Key> {
        let blen = bytes.len();
        if blen != 32 {
            return Err(Error::InvalidLength(blen));
        }

        let mut key: [u8; 32] = [0; 32];  // FIXME: Can be uninitialized
        key.copy_from_slice(bytes);
        key[0] &= 248;
        key[31] &= 63;
        key[31] |= 64;

        Ok(Key {
            bytes: key,
        })
    }

    pub fn new() -> Key {
        let mut key = [0u8; 32];
        fill_random(&mut key);
        Key::from_bytes(&key).unwrap()
    }

    pub fn public(&self) -> PubKey { self.into() }

    pub fn shared_key(&self, other: &PubKey) -> SharedKey {
        SharedKey {
            bytes: curve25519(&self.bytes, &other.montgomery_field().to_bytes())
        }
    }
}

pub const PRIVATE_KEY_SCHEME: &'static str = "ski:prvk";
pub const PUBLIC_KEY_SCHEME: &'static str = "ski:pubk";
pub const SHARED_KEY_SCHEME: &'static str = "ski:shak";

impl Encodable for Key {
    fn encode(&self) -> CodedObject {
        CodedObject {
            scheme: PRIVATE_KEY_SCHEME.into(),
            bytes: self.bytes.into(),
        }
    }
}

impl Decodable for Key {
    fn decode(input: &CodedObject) -> error::Result<Self> {
        input.expect_scheme(PRIVATE_KEY_SCHEME)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&input.bytes);
        Ok(Key {
            bytes: key,
        })
    }
}

impl Encodable for PubKey {
    fn encode(&self) -> CodedObject {
        CodedObject {
            scheme: PUBLIC_KEY_SCHEME.into(),
            bytes: self.bytes.into(),
        }
    }
}

impl Decodable for PubKey {
    fn decode(input: &CodedObject) -> error::Result<Self> {
        input.expect_scheme(PUBLIC_KEY_SCHEME)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&input.bytes);
        Ok(PubKey {
            bytes: key,
        })
    }
}

impl Encodable for SharedKey {
    fn encode(&self) -> CodedObject {
        CodedObject {
            scheme: SHARED_KEY_SCHEME.into(),
            bytes: self.bytes.into(),
        }
    }
}

impl Decodable for SharedKey {
    fn decode(input: &CodedObject) -> error::Result<Self> {
        input.expect_scheme(SHARED_KEY_SCHEME)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&input.bytes);
        Ok(SharedKey {
            bytes: key,
        })
    }
}
