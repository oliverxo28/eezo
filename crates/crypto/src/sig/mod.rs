// crates/crypto/src/sig/mod.rs

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
// If you ever add a real feature for it, re-enable with a proper cfg.
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

/// Verify a signature over the **exact message bytes** (no re-hash).
/// Active schemes are controlled by features: `mldsa`, `slh-dsa`, or `skip-sig-verify`.

// If neither real scheme nor skip flag is enabled, hard fail at compile time.
#[cfg(not(any(feature = "mldsa", feature = "slh-dsa", feature = "skip-sig-verify")))]
compile_error!("eezo-crypto: no signature scheme enabled; enable mldsa or slh-dsa (prod) or skip-sig-verify (dev/tests).");

// Dev/test bypass: accept all signatures.
#[cfg(feature = "skip-sig-verify")]
pub fn verify_sig(_pubkey: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
    true
}

// Real verification path (one or both schemes enabled), only when not skipping.
#[cfg(all(not(feature = "skip-sig-verify"), any(feature = "mldsa", feature = "slh-dsa")))]
pub fn verify_sig(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    registry::verify(pubkey, msg, sig)
}
