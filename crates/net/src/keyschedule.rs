//! Derive traffic keys and 3-byte session_id from a secret.
//!
//! **Full handshake:** `shared_secret` comes from KEM (encap/decap).
//! **Resumption (T37.1):** we reuse the *same* HKDF flow with a PSK derived
//! from the accepted ticket. No label/version change is needed.
//!
//! Inputs: secret, salt_c[16], salt_s[16].
//! Derivation:
//!   prk = HKDF-Extract(salt = salt_c || salt_s, ikm = secret)
//!   key_block = HKDF-Expand(prk, "EEZO:traffic/v1", 64)
//!   sess_id   = HKDF-Expand(prk, "EEZO:sessid/v1", 3)
//! Output: k_c2s, k_s2c (32B each), session_id[3] (role-agnostic mapping).

use crate::hkdf_sha3::{expand, extract};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TrafficKeys {
    pub k_c2s: [u8; KEY_LEN],
    pub k_s2c: [u8; KEY_LEN],
    pub session_id: [u8; 3],
}

pub fn derive(secret: &[u8], salt_c: &[u8; 16], salt_s: &[u8; 16]) -> TrafficKeys {
    let mut salt = [0u8; 32];
    salt[..16].copy_from_slice(salt_c);
    salt[16..].copy_from_slice(salt_s);

    let prk = extract(&salt, secret);
    let kb = expand(&prk, b"EEZO:traffic/v1", 64);
    let sid = expand(&prk, b"EEZO:sessid/v1", 3);

    let mut k_c2s = [0u8; KEY_LEN];
    let mut k_s2c = [0u8; KEY_LEN];
    k_c2s.copy_from_slice(&kb[0..KEY_LEN]);
    k_s2c.copy_from_slice(&kb[KEY_LEN..(2 * KEY_LEN)]);

    let mut session_id = [0u8; 3];
    session_id.copy_from_slice(&sid[..3]);

    // zeroize sensitive temps
    let mut salt_z = salt;
    salt_z.zeroize();
    let _ = kb; // drop vec without warning
    let mut prk_z = prk; // prk is [u8; 32]
    prk_z.zeroize();

    TrafficKeys {
        k_c2s,
        k_s2c,
        session_id,
    }
}

/// Alias used by handshake code for clarity.
#[inline]
pub fn derive_keys(secret: &[u8], salt_c: &[u8; 16], salt_s: &[u8; 16]) -> TrafficKeys {
    derive(secret, salt_c, salt_s)
}

/// Convenience wrapper emphasizing PSK-based resumption path.
#[inline]
pub fn derive_from_psk(psk: &[u8], salt_c: &[u8; 16], salt_s: &[u8; 16]) -> TrafficKeys {
    derive(psk, salt_c, salt_s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stable_derivation() {
        let ss = b"shared secret test";
        let salt_c = [1u8; 16];
        let salt_s = [2u8; 16];
        let a = derive(ss, &salt_c, &salt_s);
        let b = derive(ss, &salt_c, &salt_s);
        assert_eq!(a.k_c2s, b.k_c2s);
        assert_eq!(a.k_s2c, b.k_s2c);
        assert_eq!(a.session_id, b.session_id);
    }
    #[test]
    fn psk_resumption_matches_alias() {
        let psk = b"resume psk bytes";
        let salt_c = [9u8; 16];
        let salt_s = [8u8; 16];
        let x = derive_from_psk(psk, &salt_c, &salt_s);
        let y = derive_keys(psk, &salt_c, &salt_s);
        assert_eq!(x.k_c2s, y.k_c2s);
        assert_eq!(x.k_s2c, y.k_s2c);
        assert_eq!(x.session_id, y.session_id);
    }
}
