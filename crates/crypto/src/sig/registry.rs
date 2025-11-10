//! Signature scheme registry and dispatch.
//! Aligns with the PQC algorithm IDs:
//! - ML-DSA-44  => AlgoId::MlDsa44 (0x0144)
//! - SLH-DSA-128f (optional) => AlgoId::SlhDsa128f (0x0244)
use super::{AlgoId, SignatureScheme};

// Concrete schemes behind the features (match the crypto crate features).
#[cfg(feature = "mldsa")]
use super::ml_dsa::{
    pk_from_bytes as mldsa_pk_from_bytes, sig_from_bytes as mldsa_sig_from_bytes, MlDsa44,
};
#[cfg(feature = "slh-dsa")]
use super::slh_dsa::SlhDsa128f;

// A simple factory/registry mapping AlgoId -> concrete scheme.
pub enum SignatureRegistry {
    #[cfg(feature = "mldsa")]
    MlDsa44,

    #[cfg(feature = "slh-dsa")]
    SlhDsa128f,
}

impl SignatureRegistry {
    pub fn from_algo(id: AlgoId) -> Option<Self> {
        match id {
            #[cfg(feature = "mldsa")]
            AlgoId::MlDsa44 => Some(SignatureRegistry::MlDsa44),

            #[cfg(feature = "slh-dsa")]
            AlgoId::SlhDsa128f => Some(SignatureRegistry::SlhDsa128f),

            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    pub fn pk_len(&self) -> usize {
        match self {
            #[cfg(feature = "mldsa")]
            SignatureRegistry::MlDsa44 => <MlDsa44 as SignatureScheme>::PK_LEN,

            #[cfg(feature = "slh-dsa")]
            SignatureRegistry::SlhDsa128f => <SlhDsa128f as SignatureScheme>::PK_LEN,
        }
    }

    pub fn sk_len(&self) -> usize {
        match self {
            #[cfg(feature = "mldsa")]
            SignatureRegistry::MlDsa44 => <MlDsa44 as SignatureScheme>::SK_LEN,

            #[cfg(feature = "slh-dsa")]
            SignatureRegistry::SlhDsa128f => <SlhDsa128f as SignatureScheme>::SK_LEN,
        }
    }

    pub fn sig_max_len(&self) -> usize {
        match self {
            #[cfg(feature = "mldsa")]
            SignatureRegistry::MlDsa44 => <MlDsa44 as SignatureScheme>::SIG_MAX_LEN,

            #[cfg(feature = "slh-dsa")]
            SignatureRegistry::SlhDsa128f => <SlhDsa128f as SignatureScheme>::SIG_MAX_LEN,
        }
    }
}

// -------------------- T34: Suite Rotation Helpers --------------------
/// Canonical suite IDs we expose across components (matches smart-contract side):
/// 1 = ML-DSA-44, 2 = SLH-DSA-128f (SPHINCS+ family)
pub const SUITE_ID_MLDSA44: u8 = 1;
pub const SUITE_ID_SPHINCS: u8 = 2;

/// Rotation state carried by the node / runtime:
/// - `active_suite`: the suite that must be accepted after the window closes
/// - `next_suite`:   optionally the upcoming suite during rotation
/// - `dual_accept_until`: inclusive EEZO block height up to which *both*
///    `active_suite` and `next_suite` are accepted.
#[derive(Clone, Copy, Debug)]
pub struct RotationState {
    pub active_suite: AlgoId,
    pub next_suite: Option<AlgoId>,
    pub dual_accept_until: Option<u64>,
}

impl RotationState {
    /// Returns true if `algo` is acceptable at `height` per rotation policy.
    pub fn accepts(&self, height: u64, algo: AlgoId) -> bool {
        if algo == self.active_suite {
            return true;
        }
        if let (Some(next), Some(until)) = (self.next_suite, self.dual_accept_until) {
            if height <= until && algo == next {
                return true;
            }
        }
        false
    }
}

/// Map an AlgoId to our public suite id (u8) for UI/telemetry/governance.
pub fn algo_to_suite_id(id: AlgoId) -> Option<u8> {
    match id {
        #[cfg(feature = "mldsa")]
        AlgoId::MlDsa44 => Some(SUITE_ID_MLDSA44),
        #[cfg(feature = "slh-dsa")]
        AlgoId::SlhDsa128f => Some(SUITE_ID_SPHINCS),
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

/// Dispatch verify for a *specific* algorithm.
pub fn verify_with_algo(algo: AlgoId, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match algo {
        #[cfg(feature = "mldsa")]
        AlgoId::MlDsa44 => verify_mldsa44_bytes(pubkey, msg, sig),

        #[cfg(all(not(feature = "mldsa"), feature = "slh-dsa"))]
        AlgoId::SlhDsa128f => super::slh_dsa::verify_bytes(pubkey, msg, sig),

        #[cfg(all(feature = "mldsa", feature = "slh-dsa"))]
        AlgoId::SlhDsa128f => super::slh_dsa::verify_bytes(pubkey, msg, sig),

        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// Rotation-aware verifier:
/// - Enforces acceptance rules at `height` using `state`.
/// - If acceptable, dispatches to the concrete verifier for `algo`.
pub fn verify_rotating(
    state: &RotationState,
    height: u64,
    algo: AlgoId,
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
    ) -> bool
{
    if !state.accepts(height, algo) {
        return false;
    }
    verify_with_algo(algo, pubkey, msg, sig)
}

// -------------------- existing APIs --------------------
/// Verify an ML-DSA-44 detached signature for anchors.
/// Returns `true` on valid signature, `false` otherwise.
///
/// Hardening:
/// - Strict size checks (pk=1312, sig=2420) to avoid resource abuse.
/// - Feature-gated: requires `pq44-runtime` to be enabled.
///
/// Inputs:
/// - `pk`: raw ML-DSA-44 public key bytes (1312)
/// - `msg`: message bytes (e.g., `anchor_signing_bytes(chain_id, anchor)`)
/// - `sig`: raw ML-DSA-44 detached signature bytes (2420)
pub fn verify_anchor_mldsa_44(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    #[cfg(feature = "mldsa")]
    {
        verify_mldsa44_bytes(pk, msg, sig)
    }
    #[cfg(not(feature = "mldsa"))]
    {
        let _ = (pk, msg, sig);
        false
    }
}
/// Verify a SPHINCS+ (SLH-DSA SHA2-128f simple) detached signature for anchors.
/// Returns `true` on valid signature, `false` otherwise.
///
/// Hardening:
/// - Strict size checks (pk == PK_LEN, sig <= SIG_MAX_LEN) to avoid resource abuse.
/// - Feature-gated: requires `slh-dsa` to be enabled.
///
/// Inputs:
/// - `pk`: raw SPHINCS+ public key bytes (bytes length per `SlhDsa128f::PK_LEN`)
/// - `msg`: message bytes (e.g., `anchor_signing_bytes(chain_id, anchor)` )
/// - `sig`: raw detached signature bytes (≤ `SlhDsa128f::SIG_MAX_LEN`)
#[cfg(feature = "slh-dsa")]
pub fn verify_anchor_sphincs_sha2_128f_simple(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // Use the scheme constants so a future upgrade stays in sync.
    if pk.len() != <SlhDsa128f as SignatureScheme>::PK_LEN
        || sig.len() > <SlhDsa128f as SignatureScheme>::SIG_MAX_LEN
    {
        return false;
    }
    // Delegate to the bytes-based verifier in slh_dsa.rs
    super::slh_dsa::verify_bytes(pk, msg, sig)
}

/// Stub when `slh-dsa` is disabled — keeps callers compiling.
#[cfg(not(feature = "slh-dsa"))]
pub fn verify_anchor_sphincs_sha2_128f_simple(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
    false
}

/// Unified verifier used by `sig::verify_sig` (Step 1a).
/// Accepts **raw message bytes** and returns true on valid signature.
///
/// Dispatch rules:
/// - If `pq44-runtime` is enabled, use ML-DSA-44 (pk=1312, sig=2420).
/// - Else if `slh-dsa` is enabled, delegate to the SLH-DSA module's byte verifier.
/// - Else, no runtime scheme enabled → false.
pub fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    #[cfg(feature = "mldsa")]
    {
        return verify_mldsa44_bytes(pubkey, msg, sig);
    }

    #[cfg(all(not(feature = "mldsa"), feature = "slh-dsa"))]
    {
        // Expect the SLH-DSA module to provide a bytes-based verifier.
        // If it doesn't exist yet, we'll add it when we wire SLH-DSA.
        return super::slh_dsa::verify_bytes(pubkey, msg, sig);
    }

    // No supported signature scheme compiled in.
    #[allow(unreachable_code)]
    false
}

/// ML-DSA-44 verifier over **raw message bytes**.
/// Hardening: strict pk/sig length checks to avoid abuse.
#[cfg(feature = "mldsa")]
fn verify_mldsa44_bytes(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // Use the scheme constants so a future upgrade stays in sync.
    if pk.len() != <MlDsa44 as SignatureScheme>::PK_LEN
        || sig.len() != <MlDsa44 as SignatureScheme>::SIG_MAX_LEN
    {
        return false;
    }
    // Parse strongly-typed keys/sigs and verify.
    match (mldsa_pk_from_bytes(pk), mldsa_sig_from_bytes(sig)) {
        (Some(pk_typed), Some(sig_typed)) => MlDsa44::verify(&pk_typed, msg, &sig_typed),
        _ => false,
    }
}
