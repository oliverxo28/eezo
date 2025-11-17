#![cfg(feature = "stark-air")]

use eezo_prover::{
    air_spec::{AirPiV2, Boundary, Col},
    constraints::{assert_boundary, assert_constant_cols, assert_sorted_leaves, assert_state_step_sequence},
    witness::build_trace,
};

fn u32_to32(x: u8) -> [u8;32] { [x;32] }

#[test]
fn golden_trace_passes() {
    // build the same state bytes the witness uses
    let accounts = u32_to32(20);
    let supply   = u32_to32(21);
    let mut state_bytes = Vec::new();
    state_bytes.extend_from_slice(&2u32.to_le_bytes());
    state_bytes.extend_from_slice(&accounts);
    state_bytes.extend_from_slice(&supply);
    let state_digest = *blake3::hash(&state_bytes).as_bytes();
    // tx leaves (must match what we pass to build_trace)
    let leaves = vec![u32_to32(10), u32_to32(11)]; // sorted (10 <= 11)
    // SSZ vector: len:u32 LE || leaf_0 || leaf_1
    let mut txs_bytes = Vec::new();
    txs_bytes.extend_from_slice(&2u32.to_le_bytes());
    for l in &leaves {
        txs_bytes.extend_from_slice(l);
    }
    let txs_digest = *blake3::hash(&txs_bytes).as_bytes();	

    let pi = AirPiV2 {
        chain_id20: [0;20],
        height: 32,
        parent_hash: [1;32],
        txs_root_v2: txs_digest,
        state_root_v2: state_digest,
        sig_batch_digest: u32_to32(4),
        suite_id: 2,
        circuit_version: 2,
    };
    let b = Boundary {
        row0_parent_hash: [1;32],
        row_last_header_htr: u32_to32(9),
        row_last_txs_root_v2: txs_digest,
        row_last_state_root_v2: state_digest,
        row_last_sig_batch_digest: u32_to32(4),
    };
    let state = (accounts, supply);

    let t = build_trace(&pi, &b, &leaves, state);

    assert_constant_cols(&t, &[Col::Height, Col::SuiteId, Col::CircuitVer]).unwrap();
    assert_sorted_leaves(&leaves).unwrap();
    assert_boundary(&t, &b, &pi).unwrap();
	assert_state_step_sequence(&t).unwrap();
}

#[test]
fn unsorted_leaves_fail() {
    let pi = AirPiV2 {
        chain_id20: [0;20],
        height: 1,
        parent_hash: [7;32],
        txs_root_v2: u32_to32(8),
        state_root_v2: u32_to32(9),
        sig_batch_digest: u32_to32(10),
        suite_id: 1,
        circuit_version: 1,
    };
    let b = Boundary {
        row0_parent_hash: [7;32],
        row_last_header_htr: u32_to32(12),
        row_last_txs_root_v2: u32_to32(8),
        row_last_state_root_v2: u32_to32(9),
        row_last_sig_batch_digest: u32_to32(10),
    };
    // intentionally UNSORTED: 12 > 11 (should fail)
    let leaves = vec![u32_to32(12), u32_to32(11)];
    let state = (u32_to32(1), u32_to32(2));

    let _t = build_trace(&pi, &b, &leaves, state);
    assert!(assert_sorted_leaves(&leaves).is_err(), "unsorted leaves should fail");
}
