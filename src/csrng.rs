use rand::{RngCore, rngs::OsRng};

pub fn fill_random(bytes: &mut [u8]) {
    OsRng.fill_bytes(bytes);
}
