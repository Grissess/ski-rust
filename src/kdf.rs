use argon2rs::{Argon2, Variant};

pub struct KeyDerivation {
    hasher: Argon2,
}

pub const WELL_KNOWN_SALT: [u8; 8] = [0; 8];

impl KeyDerivation {
    pub fn new() -> Self {
        KeyDerivation {
            hasher: Argon2::new(1, 1, 8, Variant::Argon2i).unwrap(),
        }
    }

    pub fn hash(&self, input: &[u8], output: &mut [u8]) {
        self.hasher.hash(output, input, &WELL_KNOWN_SALT, &[], &[]);
    }
}
