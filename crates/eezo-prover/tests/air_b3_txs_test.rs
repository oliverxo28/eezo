#![cfg(feature = "stark-air")]

use eezo_prover::hash_b3_tx::prove_txs_root_digest;

#[test]
fn txs_witness_smoke() {
    let leaves = vec![[10u8;32], [11u8;32], [12u8;32]];
    let w = prove_txs_root_digest(&leaves);
    // digest is deterministic for the SSZ vector; just sanity-check shape
    assert_eq!(w.leaves.len(), 3);
    assert_ne!(w.digest, [0u8;32]);
}
