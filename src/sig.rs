use crate::error;
use crate::coding::{Encodable, Decodable, CodedObject};
use crate::key::{Key, PubKey};
use crate::csrng::fill_random;

use crypto::curve25519::{ge_scalarmult_base, sc_reduce, sc_muladd, GeP3, GeP2};
use crypto::sha2::Sha512;
use crypto::digest::Digest;
use crypto::util::fixed_time_eq;

/* The following code is stolen from the private (non-exported) parts of crypto::ed25519. */
pub const L: [u8; 32] =
      [ 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
        0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed ];

pub fn check_s_lt_l(s: &[u8]) -> bool
{
    let mut c: u8 = 0;
    let mut n: u8 = 1;

    let mut i = 31;
    loop {
        c |= ((((s[i] as i32) - (L[i] as i32)) >> 8) as u8) & n;
        n &= (((((s[i] ^ L[i]) as i32)) - 1) >> 8) as u8;
        if i == 0 {
            break;
        } else {
            i -= 1;
        }
    }

    c == 0
}
/* End of imports. */

pub fn ct_zero(data: &[u8]) -> bool {
    let mut b = 0u8;
    for v in data {
        b |= v;
    }
    b == 0
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub nonce_pt: [u8; 32],
    pub signature: [u8; 32],
}

pub type SignatureHash = Sha512;
pub const SIG_HASH_SIZE: usize = 64;

impl Signature {
    pub fn sign_with_nonce(key: &Key, data: &[u8], nonce: [u8; 32]) -> Signature {
        let nonce_pt = ge_scalarmult_base(&nonce).to_bytes();
        let mut hasher = SignatureHash::new();
        let pubkey = key.public();
        hasher.input(&nonce_pt);
        hasher.input(&pubkey.bytes);
        hasher.input(data);
        let mut digest = [0u8; SIG_HASH_SIZE];
        hasher.result(&mut digest);
        sc_reduce(&mut digest);

        let mut signature = [0u8; 32];
        sc_muladd(&mut signature, &digest[0..32], &key.bytes, &nonce);
        Signature {
            nonce_pt, signature
        }
    }

    pub fn sign(key: &Key, data: &[u8]) -> Signature {
        let mut nonce = [0u8; 32];
        fill_random(&mut nonce);
        Signature::sign_with_nonce(key, data, nonce)
    }

    pub fn verify(&self, key: &PubKey, data: &[u8]) -> bool {
        if check_s_lt_l(&self.signature) { return false; }

        let gp = match GeP3::from_bytes_negate_vartime(&key.bytes) {
            Some(g) => g,
            None => return false,
        };

        if ct_zero(&key.bytes) { return false; }

        let mut hasher = SignatureHash::new();
        hasher.input(&self.nonce_pt);
        hasher.input(&key.bytes);
        hasher.input(data);
        let mut digest = [0u8; SIG_HASH_SIZE];
        hasher.result(&mut digest);
        sc_reduce(&mut digest);

        let r = GeP2::double_scalarmult_vartime(&digest[0..32], gp, &self.signature);
        fixed_time_eq(r.to_bytes().as_ref(), &self.nonce_pt)
    }
}

pub const SIGNATURE_SCHEME: &'static str = "ski-sign";

impl Encodable for Signature {
    fn encode(&self) -> CodedObject {
        let mut data = Vec::with_capacity(64);
        data.extend(&self.nonce_pt);
        data.extend(&self.signature);
        CodedObject {
            scheme: SIGNATURE_SCHEME.into(),
            bytes: data,
        }
    }
}

impl Decodable for Signature {
    fn decode(input: &CodedObject) -> error::Result<Self> {
        input.expect_scheme(SIGNATURE_SCHEME)?;
        let mut nonce_pt = [0u8; 32];
        let mut signature = [0u8; 32];
        nonce_pt.copy_from_slice(&input.bytes[0..32]);
        signature.copy_from_slice(&input.bytes[32..64]);
        Ok(Signature { nonce_pt, signature })
    }
}
