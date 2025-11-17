#![cfg(feature = "stark-air")]

use eezo_prover::air_spec::AirSpec;
use eezo_prover::proof::prove;
use eezo_prover::verify::{stark_verify, VerifyError};
use eezo_prover::trace::Trace;
use eezo_prover::proof_encoding::{serialize_proof, deserialize_proof};

#[test]
fn prover_verifier_roundtrip_ok() {
    // tiny toy trace (rows only used by scaffolded prover)
    let mut trace = Trace::new();
    for i in 1..=8 { trace.push_row(i); }

    let air = AirSpec::default();
    let proof = prove(&trace, &air);

    // encode/decode round-trip must preserve proof
    let bytes = serialize_proof(&proof);
    let proof2 = deserialize_proof(&bytes).expect("decode");

    // verifier must accept
    stark_verify(&proof2, &air).expect("valid proof verifies");
}

#[test]
fn tamper_opening_leaf_fails() {
    let mut trace = Trace::new();
    for i in 1..=8 { trace.push_row(i); }

    let air = AirSpec::default();
    let mut proof = prove(&trace, &air);

    // tamper one opened value (breaks leaf hash check)
    assert!(!proof.layer_values.is_empty());
    assert!(!proof.layer_values[0].is_empty());
    proof.layer_values[0][0] ^= 0xDEAD_BEEF_DEAD_BEEF;

    let err = stark_verify(&proof, &air).unwrap_err();
    match err {
        VerifyError::OpeningLeafHashMismatch { .. } => {},
        other => panic!("expected OpeningLeafHashMismatch, got {:?}", other),
    }
}

#[test]
fn tamper_merkle_path_fails() {
    let mut trace = Trace::new();
    for i in 1..=8 { trace.push_row(i); }

    let air = AirSpec::default();
    let mut proof = prove(&trace, &air);

    // tamper a path bit (flip is_left) to invalidate Merkle proof
    assert!(!proof.layer_openings.is_empty());
    assert!(!proof.layer_openings[0].is_empty());
    if let Some(node) = proof.layer_openings[0][0].path.get_mut(0) {
        node.is_left = !node.is_left;
    }

    let err = stark_verify(&proof, &air).unwrap_err();
    match err {
        VerifyError::OpeningPathInvalid { .. } => {},
        other => panic!("expected OpeningPathInvalid, got {:?}", other),
    }
}
