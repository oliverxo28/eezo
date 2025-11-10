//! EEZO keystore file format (v0)
//! --------------------------------
//! **Purpose:** store a secret key (e.g., ML-DSA-44 SK) encrypted at rest.
//!
//! **Primitives**
//! - KDF: **Argon2id v1.3** with tunable params (time/memory/lanes).
//! - AEAD: **XChaCha20-Poly1305 (IETF)** with 24-byte nonce.
//! - AAD: domain-separated header binding `algo_id`, `kdf_salt`, and `nonce`.
//!
//! **On disk (JSON fields)**
//! - `algo_id` (u16): scheme id (e.g., `0x0144` for ML-DSA-44).
//! - `pubkey` (optional bytes): cleartext pubkey (helps export/verify).
//! - `kdf_salt` (bytes, ≥16): Argon2id salt.
//! - `kdf_time` (u32), `kdf_mem_kib` (u32), `kdf_lanes` (u32): Argon2id params.
//! - `nonce` (24 bytes): XChaCha20-Poly1305 nonce.
//! - `ciphertext` (bytes): AEAD(ciphertext || tag) of the secret key.
//! - `note` (string): human note / version tag.
//!
//! **Security notes**
//! - The password is **never** stored. It is used via Argon2id to derive a 32-byte AEAD key.
//! - We zeroize in-memory secrets (`PlainSecret`, derived AEAD key) on drop.
//! - `validate()` enforces conservative bounds to reject malformed files.
//! - AAD binds metadata so tampering with `algo_id/salt/nonce` invalidates decryption.
//!
//! **Interoperability**
//! - The layout is self-describing; future versions can bump the `note` string and/or
//!   extend AAD (bump the internal AAD format version byte in `derive_aad()`).
//! - `pubkey` is optional; when present we enforce scheme-specific length (e.g., 1312 for ML-DSA-44).

use anyhow::anyhow;
use chacha20poly1305::{aead::{Aead, Payload}, XChaCha20Poly1305};
use chacha20poly1305::KeyInit;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use argon2::{self, Argon2};
use zeroize::Zeroize;

// ---- KDF & AEAD hardening constants ---------------------------------------
const SALT_LEN: usize  = 16;   // Argon2 salt size
const NONCE_LEN: usize = 24;   // XChaCha20-Poly1305 nonce
// Stronger default Argon2id params for new keystores:
const KDF_TIME_DEFAULT: u32    = 3;       // iterations
const KDF_MEM_KIB_DEFAULT: u32 = 262_144; // 256 MiB
const KDF_LANES_DEFAULT: u32   = 1;       // lanes (parallelism)

#[derive(Serialize, Deserialize)]
pub struct Keystore {
    algo_id: u16,
    /// Optional unencrypted public key (scheme-dependent length).
    /// Kept in clear; helps verification/export without decrypting.
    #[serde(default)]
    pubkey: Option<Vec<u8>>,
    kdf_salt: Vec<u8>,
    kdf_time: u32,
    kdf_mem_kib: u32,
    kdf_lanes: u32,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    pub note: String,
}

impl Keystore {
    /// Public accessor for the algorithm identifier (e.g., ML-DSA-44 code).
    pub fn algo_id(&self) -> u16 {
        self.algo_id
    }

    /// Public accessor for the KDF salt bytes.
    pub fn kdf_salt(&self) -> &[u8] {
        &self.kdf_salt
    }

    /// Public accessor for the XChaCha20-Poly1305 nonce (24 bytes).
    pub fn nonce(&self) -> [u8; 24] {
        self.nonce
    }

    /// Public accessor for the (unencrypted) public key bytes (if present).
    pub fn pubkey(&self) -> Option<&[u8]> {
        self.pubkey.as_deref()
    }

    /// Validate internal invariants before (de)cryption or IO.
    pub fn validate(&self) -> Result<(), &'static str> {
        // Nonce: XChaCha20-Poly1305 requires 24 bytes
        if self.nonce.len() != NONCE_LEN {
            return Err("invalid nonce length");
        }
        // KDF salt sanity (>= 16 bytes is standard)
        if self.kdf_salt.len() < SALT_LEN {
            return Err("kdf_salt too short");
        }
        // Ciphertext must include at least the tag (16B) + 1 byte of data
        if self.ciphertext.len() < 17 {
            return Err("ciphertext too short");
        }
        // If ML-DSA-44 (0x0144) and a pubkey is present, enforce pk length = 1312.
        if self.algo_id == 0x0144 {
            if let Some(pk) = &self.pubkey {
                if pk.len() != 1312 {
                    return Err("pubkey length mismatch for ML-DSA-44");
                }
            }
        }
        // Conservative Argon2 bounds (t_cost 1..=6, m_cost 64MB..=1GB)
        let (t, m_kib, p) = (self.kdf_time, self.kdf_mem_kib, self.kdf_lanes);
        if !(1..=6).contains(&t) { return Err("argon2 time cost out of bounds"); }
        if !(65536..=1048576).contains(&m_kib) { return Err("argon2 memory out of bounds"); }
        if !(1..=8).contains(&p) { return Err("argon2 lanes out of bounds"); }
        Ok(())
    }
}

#[cfg(any(test, feature = "testing"))]
impl Keystore {
    /// Flip the first byte of ciphertext (simulates storage tamper).
    pub fn test_tamper_ciphertext(&mut self) {
        if let Some(b) = self.ciphertext.get_mut(0) {
            *b ^= 0x80;
        }
    }

    /// Flip the first byte of the nonce (simulates metadata tamper).
    pub fn test_tamper_nonce(&mut self) {
        if !self.nonce.is_empty() {
            self.nonce[0] ^= 0x01;
        }
    }

    /// Make KDF salt too short to pass validation (simulates malformed keystore).
    pub fn test_shorten_kdf_salt(&mut self) {
        if self.kdf_salt.len() > 4 {
            self.kdf_salt.truncate(4);
        } else {
            // fall back to empty, still invalid
            self.kdf_salt.clear();
        }
    }
}

pub struct PlainSecret (pub Vec<u8>);
impl Drop for PlainSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn derive_key(password: &str, salt: &[u8], t: u32, m: u32, p: u32) -> [u8; 32] {
    let params = argon2::Params::new(m, t, p, None).unwrap();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .unwrap();
    out
}

fn derive_aad(algo_id: u16, kdf_salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    // A small domain-separated header; stable across versions
    // | "EEZO" | ver=1 | algo_id (LE) | salt_len (LE) | salt | nonce |
    let mut aad = Vec::with_capacity(4 + 1 + 2 + 2 + kdf_salt.len() + nonce.len());
    aad.extend_from_slice(b"EEZO");
    aad.push(1); // format version for AAD
    aad.extend_from_slice(&algo_id.to_le_bytes());
    aad.extend_from_slice(&(kdf_salt.len() as u16).to_le_bytes());
    aad.extend_from_slice(kdf_salt);
    aad.extend_from_slice(nonce);
    aad
}

pub fn encrypt_secret(password: &str, algo_id: u16, secret: &[u8]) -> Keystore {
    encrypt_secret_with_params(
        password,
        algo_id,
        secret,
        None,
        KDF_TIME_DEFAULT,
        KDF_MEM_KIB_DEFAULT,
        KDF_LANES_DEFAULT,
    )
}

/// Same as `encrypt_secret` but allows explicit Argon2 parameters.
pub fn encrypt_secret_with_params(
    password: &str,
    algo_id: u16,
    secret: &[u8],
    pubkey: Option<&[u8]>,
    kdf_time: u32,
    kdf_mem_kib: u32,
    kdf_lanes: u32,
) -> Keystore {
    let mut kdf_salt = vec![0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut kdf_salt);

    let mut key = derive_key(password, &kdf_salt, kdf_time, kdf_mem_kib, kdf_lanes);

    let aead = XChaCha20Poly1305::new_from_slice(&key).expect("bad AEAD key length");
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let aad = derive_aad(algo_id, &kdf_salt, &nonce);
    let n = chacha20poly1305::XNonce::from_slice(&nonce);
    let ct = aead
        .encrypt(n, Payload { msg: secret, aad: &aad })
        .expect("encryption failed");

    let ks = Keystore {
        algo_id,
        pubkey: pubkey.map(|b| b.to_vec()),
        kdf_salt,
        kdf_time,
        kdf_mem_kib,
        kdf_lanes,
        nonce,
        ciphertext: ct,
        note: "EEZO KS v0".into(),
    };
    ks.validate().expect("fresh keystore failed self-validate");
    key.zeroize();
    ks
}

pub fn decrypt_secret(password: &str, ks: &Keystore) -> Result<PlainSecret, anyhow::Error> {
    ks.validate().map_err(|e| anyhow!(e))?;

    let mut key = derive_key(password, &ks.kdf_salt, ks.kdf_time, ks.kdf_mem_kib, ks.kdf_lanes);
    let aead = XChaCha20Poly1305::new_from_slice(&key).expect("bad AEAD key length");
    let aad = derive_aad(ks.algo_id, &ks.kdf_salt, &ks.nonce);
    let n = chacha20poly1305::XNonce::from_slice(&ks.nonce);
    let pt = aead
        .decrypt(n, Payload { msg: &ks.ciphertext, aad: &aad })
        .map_err(|_| anyhow::anyhow!("decryption failed"))?;

    key.zeroize();
    Ok(PlainSecret(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let pw = "correct horse battery staple";
        let secret = b"super-secret-sk-bytes";
        let ks = encrypt_secret_with_params(
            pw,
            0x0144,               // ML-DSA-44
            secret,
            None,                 // no pubkey
            2,                    // lighter params for test speed
            64 * 1024,            // 64 MiB in KiB
            1,
        );
        ks.validate().unwrap();
        let pt = decrypt_secret(pw, &ks).expect("decrypt");
        assert_eq!(&pt.0, secret);
    }
}