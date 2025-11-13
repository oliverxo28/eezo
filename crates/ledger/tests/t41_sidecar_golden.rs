// crates/ledger/tests/t41_sidecar_golden.rs
//
// T41.8 — QC sidecar v2 golden/invariant test.
// Goal: if a qc_sidecar_v2 is emitted by build_rotation_headers,
// then for all headers at that height:
//
//   - sidecar.anchor_height == dual_accept_until + 1 (cutover+1)
//   - sidecar.reason == ReanchorReason::RotationCutover
//
// This does NOT change any behavior; it's tests-only.

use eezo_ledger::checkpoints::build_rotation_headers;
use eezo_ledger::qc_sidecar::ReanchorReason;
use eezo_ledger::rotation::RotationPolicy;
use eezo_crypto::suite::CryptoSuite;

#[test]
fn qc_sidecar_provenance_matches_cutover_plus_one_for_all_headers() {
    // Same style as your existing tests in checkpoints.rs:
    //  - active = MlDsa44
    //  - next   = SphincsPq
    //  - dual_accept_until = 150 → cutover+1 = 151
    let policy = RotationPolicy {
        active: CryptoSuite::MlDsa44,
        next: Some(CryptoSuite::SphincsPq),
        dual_accept_until: Some(150),
        activated_at_height: Some(100),
    };

    // Height chosen so that qc_sidecar_v2 is already emitted
    // (mirrors your sidecar_emits_exactly_at_cutover_plus_one test).
    let headers = build_rotation_headers(
        &policy,
        151,              // height
        [1u8; 32],        // header_hash
        [2u8; 32],        // state_root_v2
        [3u8; 32],        // tx_root_v2
        123,              // timestamp
        2,                // finality_depth
    );

    let cutover_plus_one = 151_u64;

    // Sanity: at least one header at this height must actually carry a sidecar.
    assert!(
        headers.iter().any(|h| h.qc_sidecar_v2.is_some()),
        "expected at least one qc_sidecar_v2 at cutover+1"
    );

    // Golden invariant: every emitted sidecar must have correct provenance + reason.
    for h in headers {
        if let Some(sc) = &h.qc_sidecar_v2 {
            assert_eq!(
                sc.anchor_height,
                cutover_plus_one,
                "sidecar anchor_height must always equal cutover+1"
            );
            assert_eq!(
                sc.reason,
                ReanchorReason::RotationCutover,
                "sidecar reason at cutover+1 must be RotationCutover"
            );
        }
    }
}
