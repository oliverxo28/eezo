// crates/crypto/src/sig/mod.rs

// -----------------------------------------------------------------------------
// T77.SAFE-2: Compile-time safety check for skip-sig-verify
// -----------------------------------------------------------------------------
// Ensure skip-sig-verify cannot be enabled without dev-unsafe.
// This is enforced via feature dependencies in Cargo.toml, but we add a
// compile-time assertion here as defense-in-depth.
#[cfg(all(feature = "skip-sig-verify", not(feature = "dev-unsafe")))]
compile_error!(
    "skip-sig-verify feature requires dev-unsafe feature. \
     NEVER enable these features in production/testnet/mainnet builds!"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgoId {
    // FIPS 204: ML-DSA level 2 (mldsa44)
    MlDsa44,

    // FIPS 205: SLH-DSA 128f (SPHINCS+)
    SlhDsa128f,
}

#[derive(Clone, Debug)]
pub struct PkBytes(pub Vec<u8>);
#[derive(Clone, Debug)]
pub struct SkBytes(pub Vec<u8>);
#[derive(Clone, Debug)]
pub struct SigBytes(pub Vec<u8>);

pub trait SignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;

    const ALGO_ID: AlgoId;
    const PK_LEN: usize;
    const SK_LEN: usize;
    const SIG_MAX_LEN: usize;

    fn keypair() -> (Self::PublicKey, Self::SecretKey);
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;

    fn pk_as_bytes(pk: &Self::PublicKey) -> &[u8];
    fn sk_as_bytes(sk: &Self::SecretKey) -> &[u8];
}

// -----------------------------------------------------------------------------
// Submodules (feature-gated)
// -----------------------------------------------------------------------------

#[cfg(feature = "mldsa")]
pub mod ml_dsa;

#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;

// Optional hybrid helper (disabled in EEZO builds).
// pub mod hybrid;

// -----------------------------------------------------------------------------
// Public registry module (feature-gated)
// -----------------------------------------------------------------------------
#[cfg(any(feature = "mldsa", feature = "slh-dsa"))]
pub mod registry;

#[cfg(feature = "mldsa")]
pub use registry::verify_anchor_mldsa_44;

// -----------------------------------------------------------------------------
// Unified verification entry point
// -----------------------------------------------------------------------------

/// Verify a signature over the exact message bytes (no re-hash).
/// Active schemes are controlled by features: `mldsa`, `slh-dsa`, or `skip-sig-verify`.
///
/// Dev/test bypass: accept all signatures.
#[cfg(feature = "skip-sig-verify")]
pub fn verify_sig(_pubkey: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
    true
}


/// Real verification path (one or both schemes enabled), only when not skipping.
#[cfg(all(not(feature = "skip-sig-verify"), any(feature = "mldsa", feature = "slh-dsa")))]
pub fn verify_sig(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    registry::verify(pubkey, msg, sig)
}

/// Fallback: if no signature scheme (and not skipping) is enabled, verification is unavailable.
/// Return false so the crate still compiles under `--no-default-features`.
#[cfg(not(any(feature = "mldsa", feature = "slh-dsa", feature = "skip-sig-verify")))]
pub fn verify_sig(_pubkey: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
    false
}

// Keep older import path working for tests and external users,
// but only when the registry exists.
#[cfg(any(feature = "mldsa", feature = "slh-dsa"))]
pub use crate::sig::registry::RotationState;

// Back-compat alias: `sig::mldsa::*` now points to `sig::ml_dsa::*` when available.
#[cfg(feature = "mldsa")]
pub mod mldsa {
    // Also re-export the trait so `sig::mldsa::SignatureScheme` keeps working.
    pub use super::SignatureScheme;
    pub use super::ml_dsa::*;
}