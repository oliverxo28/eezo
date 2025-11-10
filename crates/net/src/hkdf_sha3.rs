//! HKDF over HMAC(SHA3-256) per RFC5869 pattern.
//! Output length (L) arbitrary; SHA3-256 block = 32 bytes.

use hmac::{Hmac, Mac};
use sha3::Sha3_256;

pub const SHA3_256_LEN: usize = 32;

type HmacSha3 = Hmac<Sha3_256>;

/// HKDF-Extract(salt, ikm) -> prk (32 bytes)
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA3_256_LEN] {
    let mut mac = HmacSha3::new_from_slice(salt).expect("HMAC key size");
    mac.update(ikm);
    let tag = mac.finalize().into_bytes();
    let mut prk = [0u8; SHA3_256_LEN];
    prk.copy_from_slice(&tag[..SHA3_256_LEN]);
    prk
}

/// HKDF-Expand(prk, info, L) -> okm (L bytes)
pub fn expand(prk: &[u8; SHA3_256_LEN], info: &[u8], okm_len: usize) -> Vec<u8> {
    let mut t = Vec::new();
    let mut okm = Vec::with_capacity(okm_len);
    let mut counter: u8 = 1;

    while okm.len() < okm_len {
        let mut mac = HmacSha3::new_from_slice(prk).expect("HMAC key size");
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        let take = (okm_len - okm.len()).min(SHA3_256_LEN);
        okm.extend_from_slice(&block[..take]);
        t = block.to_vec();
        counter = counter.checked_add(1).expect("HKDF counter overflow");
    }
    okm
}
/// HKDF-Expand into a caller-provided buffer (no extra allocations).
pub fn expand_into(prk: &[u8; SHA3_256_LEN], info: &[u8], out: &mut [u8]) {
    let mut t: Vec<u8> = Vec::new();
    let mut filled = 0usize;
    let mut counter: u8 = 1;
    while filled < out.len() {
        let mut mac = HmacSha3::new_from_slice(prk).expect("HMAC key size");
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        let take = (out.len() - filled).min(SHA3_256_LEN);
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;
        t = block.to_vec();
        counter = counter.checked_add(1).expect("HKDF counter overflow");
    }
}

/// HKDF-Expand with a fixed-size output array (handy for 3B session_id, 32B keys, etc.).
pub fn expand_fixed<const N: usize>(prk: &[u8; SHA3_256_LEN], info: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    expand_into(prk, info, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hkdf_lengths() {
        let prk = extract(b"salt", b"ikm");
        for l in [1usize, 16, 32, 64, 80, 97] {
            assert_eq!(expand(&prk, b"info", l).len(), l);
        }
    }
    #[test]
    fn expand_fixed_matches_expand() {
        let prk = extract(b"salt", b"ikm");
        let a: [u8; 3] = expand_fixed(&prk, b"sid");
        let b = expand(&prk, b"sid", 3);
        assert_eq!(a.to_vec(), b);

        let c: [u8; 32] = expand_fixed(&prk, b"k");
        let d = expand(&prk, b"k", 32);
        assert_eq!(c.to_vec(), d);
    }
}
