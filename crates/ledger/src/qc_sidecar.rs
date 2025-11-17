//crates/ledger/src/qc_sidecar.rs

//! qc-sidecar v2: additive types (no behavior change).
//! - optional sidecar carried alongside checkpoints
//! - used for re-anchor semantics after rotation / recovery
//! - T41.1 only: types, serde, local sanity helper
//!
//! Enforcement (rejecting if missing/malformed) is added later behind
//! the `qc-sidecar-v2-enforce` feature in T41.4.

use serde::{Deserialize, Serialize};

// NOTE: do **not** depend on `CryptoSuite` here to avoid requiring serde on it.
// We store suite as a compact `u8` identifier (same convention as checkpoints).

/// reason why a re-anchor sidecar is attached to a checkpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReanchorReason {
    /// first header after a signature rotation cutoff (old algo disabled)
    RotationCutover,
    /// node is recovering after a missed window / gap and needs a fresh anchor
    MissedWindowRecovery,
    /// explicit admin trigger (rare, guarded by policy)
    AdminOverride,
}

/// QC sidecar (v2): additive container carried next to a checkpoint.
/// NOTE: This does **not** change consensus or HTR in T41.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QcSidecarV2 {
    /// which suite signs the anchor (e.g., ML-DSA-44, SPHINCS+, …) by numeric id
    /// keep aligned with your existing suite-id mapping in checkpoints/rotation.
    pub anchor_suite: u8,
    /// raw signature bytes over the anchor payload (domain-separated)
    pub anchor_sig: Vec<u8>,
    /// public key bytes that produced `anchor_sig`
    pub anchor_pub: Vec<u8>,
    /// height the anchor attests to (must be <= checkpoint.height when consumed)
    pub anchor_height: u64,
    /// why this sidecar exists
    pub reason: ReanchorReason,
}

impl QcSidecarV2 {
    /// minimal local sanity (format-only) before deeper policy checks.
    ///
    /// - `current_height`: the checkpoint/header height this sidecar accompanies.
    ///   callers should pass the enclosing checkpoint height when available.
    ///
    /// This **does not** cryptographically verify anything.
    pub fn is_sane_for_height(&self, current_height: u64) -> bool {
        const MAX_PK: usize = 8192;   // generous upper bound, refined later
        const MAX_SIG: usize = 16384; // generous upper bound, refined later
        if self.anchor_pub.is_empty() || self.anchor_pub.len() > MAX_PK {
            return false;
        }
        if self.anchor_sig.is_empty() || self.anchor_sig.len() > MAX_SIG {
            return false;
        }
        if self.anchor_height > current_height {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // choose any valid suite-id used in your project (1 = ml-dsa-44 in many setups)
    fn any_suite_id() -> u8 { 1 }

    #[test]
    fn sanity_rejects_future_anchor() {
        let sc = QcSidecarV2 {
            anchor_suite: any_suite_id(),
            anchor_sig: vec![1; 64],
            anchor_pub: vec![2; 32],
            anchor_height: 101,
            reason: ReanchorReason::RotationCutover,
        };
        assert!(!sc.is_sane_for_height(100));
    }

    #[test]
    fn sanity_accepts_basic_valid() {
        let sc = QcSidecarV2 {
            anchor_suite: any_suite_id(),
            anchor_sig: vec![1; 64],
            anchor_pub: vec![2; 32],
            anchor_height: 100,
            reason: ReanchorReason::MissedWindowRecovery,
        };
        assert!(sc.is_sane_for_height(100));
    }
}