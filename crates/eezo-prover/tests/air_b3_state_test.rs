#![cfg(feature = "stark-air")]

use eezo_prover::{
    air_spec::{AirPiV2, Boundary},
    witness::build_trace,
    constraints::{assert_boundary, assert_state_root_gadget, assert_constant_cols, assert_state_step_sequence},
    air_spec::Col,
    hash_b3::prove_state_root_digest,
};

/// Build a minimal PI and Boundary for state_root-only tests.
fn make_pi_and_boundary(
    parent: [u8;32],
    htr: [u8;32],
    txs_root: [u8;32],
    state_root: [u8;32],
    sig_digest: [u8;32],
) -> (AirPiV2, Boundary) {

    let pi = AirPiV2 {
        chain_id20: [0u8; 20],
        height: 32,
        parent_hash: parent,
        txs_root_v2: txs_root,
        state_root_v2: state_root,
        sig_batch_digest: sig_digest,
        suite_id: 2,
        circuit_version: 2,
    };

    let boundary = Boundary {
        row0_parent_hash: parent,
        row_last_header_htr: htr,
        row_last_txs_root_v2: txs_root,
        row_last_state_root_v2: state_root,
        row_last_sig_batch_digest: sig_digest,
    };

    (pi, boundary)
}

#[test]
fn golden_state_root_passes() {
    // ----------------------------------------------------------
    // Prepare inputs
    // ----------------------------------------------------------
    let parent = [1u8; 32];
    let htr = [9u8; 32];
    let accounts = [20u8; 32];
    let supply   = [21u8; 32];
	
    // tx leaves (must match what we pass to build_trace)
    let leaves = vec![[10u8; 32], [11u8; 32]]; // sorted OK
    // SSZ vector bytes: len:u32 LE || leaf_0 || leaf_1
    let mut txs_bytes = Vec::new();
    txs_bytes.extend_from_slice(&2u32.to_le_bytes());
    for l in &leaves {
        txs_bytes.extend_from_slice(l);
    }
    let txs_root = *blake3::hash(&txs_bytes).as_bytes();	

    // software BLAKE3 digest over state bytes
    let mut state_bytes = Vec::new();
    state_bytes.extend_from_slice(&2u32.to_le_bytes());
    state_bytes.extend_from_slice(&accounts);
    state_bytes.extend_from_slice(&supply);
    let digest = *blake3::hash(&state_bytes).as_bytes();

    let sig_digest = [4u8; 32];

    let (pi, boundary) =
        make_pi_and_boundary(parent, htr, txs_root, digest, sig_digest);

    let state_pair = (accounts, supply);

    // ----------------------------------------------------------
    // Build trace
    // ----------------------------------------------------------
    let mut trace = build_trace(&pi, &boundary, &leaves, state_pair);

    // ----------------------------------------------------------
    // Apply constraints (phase-0: all pass)
    // ----------------------------------------------------------
    assert_constant_cols(&trace, &[Col::Height, Col::SuiteId, Col::CircuitVer]).unwrap();
    assert_boundary(&trace, &boundary, &pi).unwrap();
	assert_state_step_sequence(&trace).unwrap();

    // build witness and check stub gadget
    let w = prove_state_root_digest(&state_bytes);
    assert_state_root_gadget(&mut trace, &w).unwrap();
}

#[test]
fn tamper_state_root_fails_boundary() {
    // ----------------------------------------------------------
    // Prepare inputs
    // ----------------------------------------------------------
    let parent = [1u8; 32];
    let htr = [9u8; 32];
    let txs_root = [2u8; 32];

    let accounts = [20u8; 32];
    let supply   = [21u8; 32];

    // correct digest:
    let mut state_bytes = Vec::new();
    state_bytes.extend_from_slice(&2u32.to_le_bytes());
    state_bytes.extend_from_slice(&accounts);
    state_bytes.extend_from_slice(&supply);
    let digest = *blake3::hash(&state_bytes).as_bytes();

    // tamper by flipping a bit of the published PI digest
    let mut tampered = digest;
    tampered[0] ^= 0x01;

    let sig_digest = [4u8; 32];

    let (pi, boundary) =
        make_pi_and_boundary(parent, htr, txs_root, tampered, sig_digest);

    let leaves = vec![[10u8; 32], [11u8; 32]];
    let state_pair = (accounts, supply);

    let mut trace = build_trace(&pi, &boundary, &leaves, state_pair);

    // ----------------------------------------------------------
    // constant columns still OK
    // ----------------------------------------------------------
    assert_constant_cols(&trace, &[Col::Height, Col::SuiteId, Col::CircuitVer]).unwrap();

    // ----------------------------------------------------------
    // boundary MUST fail because PI.state_root_v2 != real digest
    // (this is correct behavior in phase-0)
    // ----------------------------------------------------------
    // With T38.3 phase-1, the real digest is placed into lanes,
    // so boundary must now fail when PI is tampered.	
    assert!(assert_boundary(&trace, &boundary, &pi).is_err());

    // gadget check is stubbed; boundary already caught mismatch
	assert_state_step_sequence(&trace).unwrap();
}
