use blake3::Hasher as Blake3;
use sha3::{Digest, Sha3_256, Sha3_512};

#[inline]
pub fn sha3_256_domain(domain: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"EEZO:");
    h.update(domain);
    h.update(b":");
    h.update(msg);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[inline]
pub fn sha3_512_domain(domain: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(b"EEZO:");
    h.update(domain);
    h.update(b":");
    h.update(msg);
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

#[inline]
pub fn blake3_domain(domain: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut h = Blake3::new();
    h.update(b"EEZO:");
    h.update(domain);
    h.update(b":");
    h.update(msg);
    h.finalize().into()
}
