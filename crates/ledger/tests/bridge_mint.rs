// crates/ledger/tests/bridge_mint.rs
#![cfg(feature = "pq44-runtime")]
use eezo_ledger::{bridge::*, Accounts, Address, Supply};
#[cfg(feature = "eth-ssz")]
use eezo_ledger::merkle::{mint_inclusion_proof, verify_mint_inclusion};

#[test]
fn mint_once_then_replay_rejected() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();
    let mut bridge = BridgeState::default();
    let chain = [0x11u8; 20];
    let to = Address::from_bytes([2u8; 20]);

    let v = BridgeMintVoucher {
        deposit_id: [7u8; 32],
        ext_chain: 1,
        source_tx: [9u8; 32],
        to,
        amount: 500,
        sig: vec![0u8; 32], // ignored if skip-sig-verify
    };

    // first apply ok
    apply_bridge_mint(&mut accts, &mut supply, &mut bridge, chain, &v, &[]).unwrap();
    assert_eq!(accts.balance_of(to), 500);

    // replay rejected
    let err = apply_bridge_mint(&mut accts, &mut supply, &mut bridge, chain, &v, &[]).unwrap_err();
    matches!(err, BridgeError::AlreadyProcessed);
}

// Merkle inclusion proof over bridge-mint leaves (vouchers) — requires eth-ssz (merkle helpers)
#[cfg(all(feature = "pq44-runtime", feature = "eth-ssz"))]
#[test]
fn mint_inclusion_proof_roundtrip() {
    let chain = [0x11u8; 20];
    let to1 = Address::from_bytes([1u8; 20]);
    let to2 = Address::from_bytes([2u8; 20]);
    let to3 = Address::from_bytes([3u8; 20]);

    // Build vouchers with canonical deposit_ids
    let v1 = BridgeMintVoucher {
        deposit_id: compute_deposit_id(1, [0xA1u8; 32], to1, 100),
        ext_chain: 1,
        source_tx: [0xA1u8; 32],
        to: to1,
        amount: 100,
        sig: vec![],
    };
    let v2 = BridgeMintVoucher {
        deposit_id: compute_deposit_id(1, [0xB2u8; 32], to2, 200),
        ext_chain: 1,
        source_tx: [0xB2u8; 32],
        to: to2,
        amount: 200,
        sig: vec![],
    };
    let v3 = BridgeMintVoucher {
        deposit_id: compute_deposit_id(1, [0xC3u8; 32], to3, 300),
        ext_chain: 1,
        source_tx: [0xC3u8; 32],
        to: to3,
        amount: 300,
        sig: vec![],
    };
    let mints = vec![v1, v2, v3];

    // Prove inclusion for v2 (index 1)
    let (leaf, branch, root) = mint_inclusion_proof(&mints, 1, chain).expect("proof");
    assert!(verify_mint_inclusion(&leaf, &branch, root, 1), "proof verifies");

    // Negative check: wrong index must fail
    assert!(!verify_mint_inclusion(&leaf, &branch, root, 0), "wrong index fails");
}
