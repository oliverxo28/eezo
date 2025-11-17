#![cfg(feature = "stark-air")]

use eezo_prover::{
    air_spec::{AirPiV2, Boundary, Col},
    constraints::{assert_boundary, assert_constant_cols, assert_txs_step_sequence},
    hash_b3_tx::prove_txs_root_digest,
    witness::build_trace,
};

fn u32s(x: u8) -> [u8;32] { [x;32] }

#[test]
fn txs_sequence_emitted() {
    let leaves = vec![u32s(10), u32s(11), u32s(12)];
    let w = prove_txs_root_digest(&leaves);

    let accounts = u32s(20);
    let supply   = u32s(21);
    let mut state_bytes = Vec::new();
    state_bytes.extend_from_slice(&2u32.to_le_bytes());
    state_bytes.extend_from_slice(&accounts);
    state_bytes.extend_from_slice(&supply);
    let state_digest = *blake3::hash(&state_bytes).as_bytes();

    let pi = AirPiV2 {
        chain_id20: [0;20], height: 32, parent_hash: u32s(1),
        txs_root_v2: w.digest, state_root_v2: state_digest, sig_batch_digest: u32s(4),
        suite_id: 2, circuit_version: 2,
    };
    let b = Boundary {
        row0_parent_hash: u32s(1), row_last_header_htr: u32s(9),
        row_last_txs_root_v2: w.digest, row_last_state_root_v2: state_digest,
        row_last_sig_batch_digest: u32s(4),
    };

    let trace = build_trace(&pi, &b, &leaves, (accounts, supply));
    assert_constant_cols(&trace, &[Col::Height, Col::SuiteId, Col::CircuitVer]).unwrap();
    assert_txs_step_sequence(&trace).unwrap();
    assert_boundary(&trace, &b, &pi).unwrap();
}
