#![cfg(feature = "stark-air")]

use eezo_prover::trace::Trace;
use eezo_prover::air_spec::AirSpec;
use eezo_prover::proof::prove;

#[test]
fn stark_end_to_end() {
    // Build a tiny trace
    let mut trace = Trace::new();
    trace.push_row(1);
    trace.push_row(2);
    trace.push_row(3);
    trace.push_row(4);
    trace.push_row(5);
    trace.push_row(6);
    trace.push_row(7);
    trace.push_row(8);

    // Dummy AirSpec (constants)
    let air = AirSpec::default();

    let proof = prove(&trace, &air);

    // Proof must contain a trace commitment
    assert_ne!(proof.trace_root, [0u8; 32]);

    // Public input digest must be nonzero
    assert_ne!(proof.public_inputs_hash, [0u8; 32]);

    // FRI proof must contain layers
    assert!(!proof.fri.layers.is_empty());
}
