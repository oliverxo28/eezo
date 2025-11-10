use eezo_ledger::tx::apply_signed_tx;
use eezo_ledger::{Accounts, Supply, SignedTx};
use eezo_ledger::address::Address;
// Use the test transaction builder that signs with ML-DSA-44 correctly.
mod support;
use support::tx_build as tb;

// (No local signer needed; tb::build returns a SignedTx with a valid PQC signature.)

#[test]
#[cfg(all(not(feature = "testing"), not(feature = "skip-sig-verify")))]
fn duplicate_nonce_rejected() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();
    let chain_id = [0u8; 20];
    let to = Address::from_bytes([2u8; 20]);

    // Builder with proper ML-DSA-44 signing; exposes the sender address to fund.
    let builders = tb::new_many(chain_id, 1);
    let b = &builders[0];
    let from = b.sender();

    // Fund EXACTLY the derived sender
    accts.credit(from, 1_000);

    // First tx with current nonce = 0 should succeed
    let stx1: SignedTx = b.build(to, 10, 1, 0);
    assert!(apply_signed_tx(&mut accts, &mut supply, chain_id, &stx1).is_ok());

    // Second tx with the SAME nonce must fail because the account's nonce has now been incremented to 1.
    let stx2: SignedTx = b.build(to, 5, 1, 0);
    assert!(apply_signed_tx(&mut accts, &mut supply, chain_id, &stx2).is_err());
}

/// Nonce gaps must be rejected at apply time (stateful check).
#[test]
fn reject_gaps_at_admit() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();
    let chain_id = [0u8; 20];
    let to = Address::from_bytes([0xCD; 20]);

    let builders = tb::new_many(chain_id, 1);
    let b = &builders[0];
    let from = b.sender();

    // Fund sender, but do not submit nonce 0/1 first.
    accts.credit(from, 1_000);

    // Try nonce=2 without 0 and 1 -> must be rejected.
    let stx_gap: SignedTx = b.build(to, 10, 1, 2);
    let res = apply_signed_tx(&mut accts, &mut supply, chain_id, &stx_gap);
    assert!(res.is_err(), "gap nonce must be rejected (expected nonce=0)");
}

/// Amount+fee larger than balance must be rejected with a stateful error.
#[test]
fn reject_insufficient_funds() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();
    let chain_id = [0u8; 20];
    let to = Address::from_bytes([0xEE; 20]);

    let builders = tb::new_many(chain_id, 1);
    let b = &builders[0];
    let from = b.sender();

    // Intentionally underfund the account.
    accts.credit(from, 5); // balance < amount(10)+fee(1)

    let stx: SignedTx = b.build(to, 10, 1, 0);
    let res = apply_signed_tx(&mut accts, &mut supply, chain_id, &stx);
    assert!(res.is_err(), "insufficient funds must be rejected");
}

/// A bit-flipped signature over an otherwise-valid tx must be rejected under pq44-runtime.
#[test]
#[cfg(all(not(feature = "testing"), not(feature = "skip-sig-verify")))]
fn reject_bad_sig() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();
    let chain_id = [0u8; 20];
    let to = Address::from_bytes([0xAB; 20]);

    let builders = tb::new_many(chain_id, 1);
    let b = &builders[0];
    let from = b.sender();

    // Fund so only signature correctness decides the outcome.
    accts.credit(from, 1_000);

    // Start with a valid, properly signed tx.
    let good: SignedTx = b.build(to, 10, 1, 0);
    
    // We need a mutable copy of accounts to apply the first transaction
    let mut accts_for_good = accts.clone();
    let mut supply_for_good = supply.clone();

    assert!(
        apply_signed_tx(&mut accts_for_good, &mut supply_for_good, chain_id, &good).is_ok(),
        "sanity: good signature should pass"
    );

    // Build another valid tx for the original account state, then flip a bit in the signature to corrupt it.
    let mut bad: SignedTx = b.build(to, 5, 1, 0); // Use nonce 0 again against the original `accts`
    if !bad.sig.is_empty() {
        bad.sig[0] ^= 0x01;
    } else {
        // Defensive: if sig is empty for some reason, force a non-empty invalid sig.
        bad.sig = vec![0x01];
    }
    let res_bad = apply_signed_tx(&mut accts, &mut supply, chain_id, &bad);
    assert!(res_bad.is_err(), "bad signature must be rejected under pq44-runtime");
}