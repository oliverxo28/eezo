#![cfg(feature = "eth-ssz")]
use eezo_ledger::{merkle::verify_tx_inclusion, merkle::tx_inclusion_proof, tx_types::TxCore, Address, SignedTx};

fn mk_tx(sender: [u8; 20], to: [u8; 20], amount: u128, fee: u128, nonce: u64) -> SignedTx {
    // Use whichever constructor your Address exposes:
    #[allow(unused_mut)]
    let from = Address(sender); // or: Address::from_bytes(sender)
    let to = Address(to);
    let mut pk = from.as_bytes().to_vec();
    pk.extend_from_slice(&[0u8; 12]);
    SignedTx {
        core: TxCore { to, amount, fee, nonce },
        pubkey: pk,
        sig: vec![0; 32],
    }
}

#[test]
fn tx_inclusion_proof_roundtrip_ethssz() {
    let txs = vec![
        mk_tx([1; 20], [2; 20], 10, 1, 0),
        mk_tx([1; 20], [3; 20], 20, 2, 1),
        mk_tx([4; 20], [5; 20], 30, 3, 0),
        mk_tx([6; 20], [7; 20], 40, 4, 0),
    ];
    let idx = 2;
    let (leaf, branch, root_v2) = tx_inclusion_proof(&txs, idx).expect("proof");
    assert!(
        verify_tx_inclusion(&leaf, &branch, root_v2, idx),
        "valid inclusion proof must verify"
    );
    // sanity: root is 32-bytes, leaf matches size
    assert_eq!(leaf.len(), 32);
    assert_ne!(root_v2, [0u8; 32], "non-zero tx_root_v2 expected");
}

#[test]
fn tampered_branch_rejected() {
    let txs = vec![
        mk_tx([1; 20], [2; 20], 10, 1, 0),
        mk_tx([1; 20], [3; 20], 20, 2, 1),
        mk_tx([4; 20], [5; 20], 30, 3, 0),
        mk_tx([6; 20], [7; 20], 40, 4, 0),
    ];
    let idx = 1;
    let (leaf, mut branch, root_v2) = tx_inclusion_proof(&txs, idx).expect("proof");
    branch[0][0] ^= 0x01; // flip one bit → should break proof
    assert!(
        !verify_tx_inclusion(&leaf, &branch, root_v2, idx),
        "tampered proof must be rejected"
    );
}

// Optional extras:

#[test]
fn oob_index_returns_none() {
    let txs = vec![mk_tx([1; 20], [2; 20], 1, 0, 0)];
    assert!(
        tx_inclusion_proof(&txs, 5).is_none(),
        "oob index must yield None"
    );
}

#[test]
fn wrong_index_fails_verify() {
    let txs = vec![
        mk_tx([1; 20], [2; 20], 1, 0, 0),
        mk_tx([3; 20], [4; 20], 1, 0, 0),
    ];
    let (leaf, branch, root_v2) = tx_inclusion_proof(&txs, 0).unwrap();
    assert!(
        !verify_tx_inclusion(&leaf, &branch, root_v2, 1),
        "wrong index must not verify"
    );
}

#[test]
fn single_tx_proof_trivial() {
    // root should equal the leaf itself for single-tx case
    let txs = vec![mk_tx([9; 20], [8; 20], 99, 1, 42)];
    let (leaf, branch, root_v2) = tx_inclusion_proof(&txs, 0).expect("proof");
    assert!(branch.is_empty(), "single tx → no branch");
    assert_eq!(leaf.len(), 32);
    assert_eq!(
        root_v2,
        leaf.as_slice(),
        "root equals leaf when only 1 tx"
    );
    assert!(verify_tx_inclusion(&leaf, &branch, root_v2, 0));
}