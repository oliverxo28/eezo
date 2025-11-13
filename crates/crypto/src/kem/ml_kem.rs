//! ML-KEM (Kyber768) helper routines.
//!
//! This module is compiled only when the PQ runtime is enabled.
//! Note: the AlgoId wiring for KEM lives in your enum (e.g. `AlgoId::MlKem768`)
//! and should map to `0x0344`. This file just uses the concrete algorithm.

// === Public ML-KEM API for eezo-net tests ===
// Export primitives required by handshake tests.
#[cfg(feature = "mlkem")]
pub use pqcrypto_mlkem::mlkem768::{
    keypair, encapsulate, decapsulate, PublicKey, SecretKey, Ciphertext,
};

// Some tests expect `keygen` instead of `keypair`.
#[cfg(feature = "mlkem")]
pub use pqcrypto_mlkem::mlkem768::keypair as keygen;

// Bring kem traits into scope so `.as_bytes()` is available on both types.
use pqcrypto_traits::kem::{
    SharedSecret as _,
};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use hkdf::Hkdf;
use sha3::Sha3_256;

pub struct InitiatorHello {
    pub enc: Ciphertext,
    pub eph_pk: PublicKey, // For explicitness; mlkem768 encaps takes recipient pk; here we demo pattern
}

pub struct ResponderReply {
    pub aead_key: [u8; 32],
    pub decaps_ok: bool,
}

/// Derive an AEAD key from shared secret via HKDF(SHA3-256).
fn kdf(ss: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(None, ss);
    let mut okm = [0u8; 32];
    hk.expand(b"EEZO:KDF:ML-KEM->AEAD", &mut okm).unwrap();
    okm
}

/// Responder side: decapsulate and produce AEAD key.
pub fn responder_decaps(sk: &SecretKey, ct: &Ciphertext) -> ResponderReply {
    let ss = decapsulate(ct, sk); // returns SharedSecret (not a Result)
    ResponderReply { aead_key: kdf(ss.as_bytes()), decaps_ok: true }
}

/// Initiator side: encapsulate to responder pk, yielding ciphertext + AEAD key locally.
pub fn initiator_encaps(pk: &PublicKey) -> (Ciphertext, [u8; 32]) {
    // In pqcrypto-mlkem, `encapsulate` returns (SharedSecret, Ciphertext)
    let (ss, ct) = encapsulate(pk);
    (ct, kdf(ss.as_bytes()))
}

/// Helper: construct an AEAD from derived key.
#[allow(deprecated)]
pub fn aead_from_key(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

