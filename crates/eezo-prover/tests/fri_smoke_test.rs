#![cfg(feature = "stark-air")]

use eezo_prover::domain::Domain;
use eezo_prover::fri::{fri_prove};

#[test]
fn fri_smoke_basic() {
    // small evaluation vector (dummy polynomial evaluations)
    let evals: Vec<u64> = (1..33).collect();

    let domain = Domain::new(evals.len());

    let proof = fri_prove(evals.clone(), &domain);

    // layers must be decreasing in size
    let mut last = evals.len();
    for layer in &proof.layers {
        assert!(layer.evals.len() <= last);
        last = layer.evals.len();
    }

    // final polynomial degree <= 15 (because we stop when <= 16 evals)
    assert!(proof.final_poly.coeffs.len() <= 16);

    // at least one challenge
    assert!(!proof.challenges.is_empty());
}
