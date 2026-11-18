pub fn fill_bytes(bytes: &mut [u8]) {
    crate::sys::pal::symbian::secure_random(bytes)
}
