#![cfg(feature = "pq44-runtime")]

use eezo_ledger::consensus::{SigBytes, SIG_LEN};
use eezo_ledger::tx::TxWitness;
use std::convert::TryInto;

// ---- Helpers used by a couple tests ----
fn sigs_from_bytes(raw: &[u8]) -> Vec<SigBytes> {
    let mut out = Vec::new();
    for chunk in raw.chunks_exact(SIG_LEN) {
        let arr: [u8; SIG_LEN] = chunk.try_into().unwrap();
        out.push(SigBytes(arr));
    }
    if out.is_empty() {
        out.push(SigBytes([0u8; SIG_LEN]));
    }
    out
}

#[test]
fn witness_basic_shape_and_contents() {
    let payload_hash = [0xAB; 32];

    // ledger SigBytes is array-backed: SigBytes(pub [u8; SIG_LEN])
    let v = vec![7u8; SIG_LEN];
    let arr: [u8; SIG_LEN] = v.try_into().expect("signature length");
    let sig = SigBytes(arr);

    let w = TxWitness {
        payload_hash,
        sigs: vec![sig],
    };

    assert_eq!(w.payload_hash, [0xAB; 32]);
    assert_eq!(w.sigs.len(), 1);
    assert_eq!(&w.sigs[0].0[..], &vec![7u8; SIG_LEN][..]);
}

#[test]
fn validate_witness_happy_path_with_cache() {
    use eezo_ledger::mempool::{validate_witness, VerifyCache};

    // No-op cache that always reports "verified" so we don't depend on crypto here.
    #[derive(Default)]
    struct NoopCache;
    impl VerifyCache for NoopCache {
        fn verify_witness(&mut self, _payload_hash: &[u8], _witness: &TxWitness) -> bool {
            true
        }
    }

    let payload_hash = [0xCD; 32];
    let sig = SigBytes([1u8; SIG_LEN]);
    let w = TxWitness { payload_hash, sigs: vec![sig] };

    let mut cache = NoopCache;
    let res = validate_witness(&payload_hash, &w, &mut cache);
    assert!(res.is_ok(), "expected witness to validate");
}

#[test]
fn oversized_witness_is_rejected() {
    use eezo_ledger::mempool::{validate_witness, MempoolError};

    // Build many signatures to exceed the configured witness size cap.
    // (5–6 KB worth of raw bytes chunked into SIG_LEN sigs.)
    let raw = vec![0xEEu8; 5600];
    let sigs = sigs_from_bytes(&raw);

    let w = TxWitness { payload_hash: [0u8; 32], sigs };

    // No-op cache (won't be reached if size check triggers first).
    #[derive(Default)]
    struct NoopCache;
    impl eezo_ledger::mempool::VerifyCache for NoopCache {
        fn verify_witness(&mut self, _payload_hash: &[u8], _witness: &TxWitness) -> bool {
            true
        }
    }
    let mut cache = NoopCache;

    let res = validate_witness(&[0u8; 32], &w, &mut cache);
    assert!(matches!(res, Err(MempoolError::WitnessTooLarge(_))));
}

#[cfg(feature = "state-sync")]
#[test]
fn sparse_merkle_proof_verifies_against_root() {
    use eezo_ledger::tx::{verify_sparse_merkle_proof, SparseMerkleProof};

    // Minimal synthetic case: no siblings (root == value).
    let root = [0xAB; 32];
    let proof = SparseMerkleProof {
        key: [0u8; 32],
        value_hash: root,
        siblings: Vec::new(),
    };
    assert!(verify_sparse_merkle_proof(&root, &proof));
}
