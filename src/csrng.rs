use rand::RngCore;

pub fn fill_random(bytes: &mut [u8]) {
    let mut rng = rand::rngs::EntropyRng::new();
    rng.fill_bytes(bytes);
}
