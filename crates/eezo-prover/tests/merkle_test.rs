#![cfg(feature = "stark-air")]

use eezo_prover::merkle::{merkle_root, merkle_proof, verify_proof};
use blake3::hash;

#[test]
fn merkle_roundtrip() {
    // simple leaves
    let values = [1u64, 2, 3, 4, 5, 6];
    let leaves: Vec<[u8;32]> =
        values.iter().map(|x| hash(&x.to_le_bytes()).into()).collect();

    let root = merkle_root(&leaves);

    // prove & verify each leaf
    for i in 0..leaves.len() {
        let proof = merkle_proof(&leaves, i).expect("proof");
        assert!(verify_proof(&proof));
        assert_eq!(proof.root, root);
    }
}

#[test]
fn merkle_invalid_proof() {
    let leaves: Vec<[u8; 32]> = vec![
        hash(&1u64.to_le_bytes()).into(),
        hash(&2u64.to_le_bytes()).into(),
    ];

    let mut proof = merkle_proof(&leaves, 0).unwrap();
    proof.leaf = hash(&999u64.to_le_bytes()).into(); // tamper leaf

    assert!(!verify_proof(&proof));
}
