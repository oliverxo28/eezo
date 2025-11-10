#![cfg(all(test, feature = "eth-ssz"))]
use eezo_ledger::{
    light::{light_verify, LightHeader, TxProofBundle},
    merkle::tx_inclusion_proof,
    tx_types::{SignedTx, TxCore},
    Address, // Import the Address struct
};
use eezo_serde::eth::HashTreeRoot;

// Test helper to create a basic signed transaction
fn mk_tx(to: [u8; 20], from: [u8; 20], amount: u128, fee: u128, nonce: u64) -> SignedTx {
    SignedTx {
        core: TxCore {
            to: Address(from), // Explicitly construct the Address
            amount,
            fee,
            nonce,
        },
        pubkey: to.to_vec(),
        sig: vec![0u8; 64],
    }
}

#[test]
fn light_verify_rejects_time_regression() {
    let txs = vec![mk_tx([1; 20], [2; 20], 10, 1, 0)];
    let (leaf, branch, tx_root_v2) = tx_inclusion_proof(&txs, 0).unwrap();

    let parent = LightHeader {
        height: 10,
		suite_id: 1, // ml-dsa-44
        parent_root: [0u8; 32],
        tx_root_v2: [9u8; 32],
        #[cfg(feature = "checkpoints")]
        qc_root: [8u8; 32],
        timestamp_ms: 2_000,
    };
    let parent_htr = parent.hash_tree_root();

    // child timestamp goes backwards → should fail
    let child = LightHeader {
        height: 11,
		suite_id: 1, // ml-dsa-44
        parent_root: parent_htr,
        tx_root_v2,
        #[cfg(feature = "checkpoints")]
        qc_root: [7u8; 32],
        timestamp_ms: 1_000,
    };

    let proof = TxProofBundle {
        tx_index: 0,
        leaf,
        branch,
    };
    assert!(light_verify(&child, &parent, &proof).is_err());
}

#[test]
fn light_verify_rejects_tampered_proof() {
    // Use at least 2 txs so the proof branch is non-empty (sibling exists).
    let txs = vec![
        mk_tx([1; 20], [2; 20], 10, 1, 0),
        mk_tx([3; 20], [4; 20], 11, 1, 0),
    ];
    let (mut leaf, mut branch, tx_root_v2) = tx_inclusion_proof(&txs, 0).unwrap();
    // Tamper the proof: prefer flipping a branch sibling; fallback to leaf if branch is empty.
    if let Some(first) = branch.get_mut(0) {
        first[0] ^= 1;
    } else {
        leaf[0] ^= 1;
    }

    let parent = LightHeader {
        height: 10,
		suite_id: 1, // ml-dsa-44
        parent_root: [0u8; 32],
        tx_root_v2: [9u8; 32],
        #[cfg(feature = "checkpoints")]
        qc_root: [8u8; 32],
        timestamp_ms: 1_000,
    };
    let parent_htr = parent.hash_tree_root();

    let child = LightHeader {
		suite_id: 1, // ml-dsa-44
        height: 11,
        parent_root: parent_htr,
        tx_root_v2,
        #[cfg(feature = "checkpoints")]
        qc_root: [7u8; 32],
        timestamp_ms: 1_500,
    };

    let proof = TxProofBundle {
        tx_index: 0,
        leaf,
        branch,
    };
    assert!(light_verify(&child, &parent, &proof).is_err());
}