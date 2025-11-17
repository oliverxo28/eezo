#![cfg(all(feature = "checkpoints", feature = "checkpoints-verify"))]

use eezo_ledger::checkpoints::{verify_quorum_cert_with_env, QuorumCert};

#[test]
fn qc_with_no_sigset_soft_passes() {
    // This matches the current “soft-pass when sigset is None” policy.
    let qc = QuorumCert {
        height: 42,
        block_hash: [1u8; 32],
        sigset: None,
    };
    assert!(verify_quorum_cert_with_env(&qc, [0u8; 20], 10).is_ok());
}

// Soft-pass must not accidentally depend on threshold or chain id.
#[test]
fn qc_soft_pass_ignores_threshold_and_chain() {
    let base_qc = QuorumCert { height: 5, block_hash: [2u8; 32], sigset: None };

    // Different committee sizes (including 0) should still Ok in soft-pass mode.
    for n in [0u64, 1, 2, 5, 9, 10, 64] {
        assert!(verify_quorum_cert_with_env(&base_qc, [0xAA; 20], n).is_ok());
    }

    // Different chain ids also should not affect soft-pass behavior.
    assert!(verify_quorum_cert_with_env(&base_qc, [0x00; 20], 7u64).is_ok());
    assert!(verify_quorum_cert_with_env(&base_qc, [0xFF; 20], 7u64).is_ok());
    let mut chain = [0u8; 20];
    for (i, item) in chain.iter_mut().enumerate() {
        *item = i as u8;
    }
    assert!(verify_quorum_cert_with_env(&base_qc, chain, 7u64).is_ok());
}

// Sanity: soft-pass should be stable across heights & hashes (no hidden coupling).
#[test]
fn qc_soft_pass_across_various_heights_and_hashes() {
    for h in [1u64, 2, 7, 42, 256, 1024] {
        let mut bh = [0u8; 32];
        bh[0] = (h & 0xFF) as u8;
        let qc = QuorumCert { height: h, block_hash: bh, sigset: None };
        assert!(verify_quorum_cert_with_env(&qc, [0xE0; 20], 3).is_ok());
    }
}