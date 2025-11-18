#![cfg(feature = "stark-air")]

use eezo_prover::{
    air_spec::{AirPiV2, Boundary, Col},
    constraints::{
        assert_boundary, assert_constant_cols, assert_state_step_sequence, assert_txs_root_gadget,
    },
    hash_b3_tx::prove_txs_root_digest,
    witness::build_trace,
};

fn u32s(x: u8) -> [u8; 32] { [x; 32] }

fn ssz_state_digest(accounts: [u8;32], supply: [u8;32]) -> [u8;32] {
    let mut state_bytes = Vec::new();
    state_bytes.extend_from_slice(&2u32.to_le_bytes()); // len=2
    state_bytes.extend_from_slice(&accounts);
    state_bytes.extend_from_slice(&supply);
    *blake3::hash(&state_bytes).as_bytes()
}
#[allow(dead_code)]
fn ssz_txs_digest(leaves: &[[u8;32]]) -> [u8;32] {
    let mut b = Vec::with_capacity(4 + 32 * leaves.len());
    b.extend_from_slice(&(leaves.len() as u32).to_le_bytes());
    for l in leaves { b.extend_from_slice(l); }
    *blake3::hash(&b).as_bytes()
}

#[test]
fn txs_root_gadget_golden() {
    // tx leaves (sorted)
    let leaves = vec![u32s(10), u32s(11), u32s(12)];
    let txs_w = prove_txs_root_digest(&leaves);
    let txs_digest = txs_w.digest; // what witness will put in B3_0..3

    // state inputs and digest (must match witness’s lanes B3_4..7)
    let accounts = u32s(20);
    let supply   = u32s(21);
    let state_digest = ssz_state_digest(accounts, supply);

    // PI and Boundary both reflect what the witness writes at Finalize
    let pi = AirPiV2 {
        chain_id20: [0;20],
        height: 32,
        parent_hash: u32s(1),
        txs_root_v2: txs_digest,
        state_root_v2: state_digest,
        sig_batch_digest: u32s(4),
        suite_id: 2,
        circuit_version: 2,
    };
    let b = Boundary {
        row0_parent_hash: u32s(1),
        row_last_header_htr: u32s(9),
        row_last_txs_root_v2: txs_digest,
        row_last_state_root_v2: state_digest,
        row_last_sig_batch_digest: u32s(4),
    };

    let mut trace = build_trace(&pi, &b, &leaves, (accounts, supply));
    assert_constant_cols(&trace, &[Col::Height, Col::SuiteId, Col::CircuitVer]).unwrap();
    assert_state_step_sequence(&trace).unwrap();
    assert_boundary(&trace, &b, &pi).unwrap();

    // gadget call (currently stubbed Ok(())); keeps API stable for T38.4 step-3+
    assert_txs_root_gadget(&mut trace, &txs_w).unwrap();
}

#[test]
fn txs_root_boundary_tamper_fails() {
    // sorted leaves and correct witness digest
    let leaves = vec![u32s(10), u32s(11)];
    let txs_w = prove_txs_root_digest(&leaves);
    let txs_digest = txs_w.digest;

    // state digest must also be correct to isolate the tamper to txs_root_v2
    let accounts = u32s(20);
    let supply   = u32s(21);
    let state_digest = ssz_state_digest(accounts, supply);

    // Correct boundary; we will tamper the PI (boundary check compares lanes to PI)
    let mut pi = AirPiV2 {
        chain_id20: [0;20],
        height: 32,
        parent_hash: u32s(1),
        txs_root_v2: txs_digest,
        state_root_v2: state_digest,
        sig_batch_digest: u32s(4),
        suite_id: 2,
        circuit_version: 2,
    };
    let b = Boundary {
        row0_parent_hash: u32s(1),
        row_last_header_htr: u32s(9),
        row_last_txs_root_v2: txs_digest,
        row_last_state_root_v2: state_digest,
        row_last_sig_batch_digest: u32s(4),
    };

    // Tamper PI.txs_root_v2 (boundary logic compares final lanes vs PI)
    pi.txs_root_v2 = u32s(2);

    let trace = build_trace(&pi, &b, &leaves, (accounts, supply));
    assert!(assert_boundary(&trace, &b, &pi).is_err());
}
#[test]
fn txs_root_var_lengths_pass() {
    fn u32s(x: u8) -> [u8; 32] { [x; 32] }
    use eezo_prover::{
        air_spec::AirPiV2, constraints::{assert_boundary, assert_constant_cols, assert_state_step_sequence},
        hash_b3_tx::prove_txs_root_digest, witness::build_trace, air_spec::Col,
    };

    let accounts = u32s(20);
    let supply   = u32s(21);
    let mut state_bytes = Vec::new();
    state_bytes.extend_from_slice(&2u32.to_le_bytes());
    state_bytes.extend_from_slice(&accounts);
    state_bytes.extend_from_slice(&supply);
    let state_digest = *blake3::hash(&state_bytes).as_bytes();

    for leaves in [
        vec![],                          // n = 0
        vec![u32s(10)],                  // n = 1
        vec![u32s(10), u32s(11)],        // n = 2
        vec![u32s(7), u32s(9), u32s(12), u32s(15), u32s(18)], // n = 5
    ] {
        let w = prove_txs_root_digest(&leaves);
        let pi = AirPiV2 {
            chain_id20: [0;20], height: 32, parent_hash: u32s(1),
            txs_root_v2: w.digest, state_root_v2: state_digest, sig_batch_digest: u32s(4),
            suite_id: 2, circuit_version: 2,
        };
        let b = eezo_prover::air_spec::Boundary {
            row0_parent_hash: u32s(1), row_last_header_htr: u32s(9),
            row_last_txs_root_v2: w.digest, row_last_state_root_v2: state_digest,
            row_last_sig_batch_digest: u32s(4),
        };
        let trace = build_trace(&pi, &b, &leaves, (accounts, supply));
        assert_constant_cols(&trace, &[Col::Height, Col::SuiteId, Col::CircuitVer]).unwrap();
        assert_state_step_sequence(&trace).unwrap();
        assert_boundary(&trace, &b, &pi).unwrap();
    }
}

#[test]
fn txs_root_unsorted_fails() {
    fn u32s(x: u8) -> [u8; 32] { [x; 32] }
    use eezo_prover::{
        air_spec::AirPiV2, constraints::{assert_boundary, assert_state_step_sequence, assert_sorted_leaves},
        hash_b3_tx::prove_txs_root_digest, witness::build_trace,
    };

    // Intentionally unsorted leaves
    let leaves_unsorted = vec![u32s(11), u32s(10), u32s(12)];
    let w = prove_txs_root_digest(&leaves_unsorted); // witness does not sort for you

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
    let b = eezo_prover::air_spec::Boundary {
        row0_parent_hash: u32s(1), row_last_header_htr: u32s(9),
        row_last_txs_root_v2: w.digest, row_last_state_root_v2: state_digest,
        row_last_sig_batch_digest: u32s(4),
    };

    // Our existing sorted check should flag this condition
    // (we test the helper directly instead of going through boundary).
    assert!(assert_sorted_leaves(&leaves_unsorted).is_err());

    // And the rest of the wiring still builds a trace (no panic), though boundary may still pass/stub.
    let _trace = build_trace(&pi, &b, &leaves_unsorted, (accounts, supply));
    let _ = assert_state_step_sequence(&_trace); // keep API exercised
    let _ = assert_boundary(&_trace, &b, &pi);
}

