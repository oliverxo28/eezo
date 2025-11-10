#![cfg(feature = "pq44-runtime")]

use eezo_ledger::tx::{apply_signed_tx, TxApplyError};
use eezo_ledger::{Accounts, Supply};

mod support;
use support::tx_build as tb;

/// Build a fresh sender/tx builder for the given chain.
fn builder(chain_id: [u8; 20]) -> tb::TxBuilder {
    let mut v = tb::new_many(chain_id, 1);
    v.pop().expect("one builder")
}

// Requires real signature verification; skip under `testing` or `skip-sig-verify`.
#[test]
#[cfg(all(feature = "pq44-runtime", not(feature = "testing"), not(feature = "skip-sig-verify")))]
fn rejects_bad_signature_flip() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();

    let chain_id = [0xE0; 20];
    let b = builder(chain_id);
    let from = b.sender();
    let to = tb::addr(0xA1);

    // Prefund so we don't fail state checks first.
    accts.credit(from, 10_000);

    let mut stx = b.build(to, 10, 1, 0);
    // Corrupt the signature after building (flip one bit)
    stx.sig[0] ^= 0x01;

    let res = apply_signed_tx(&mut accts, &mut supply, chain_id, &stx);
    assert!(matches!(res, Err(TxApplyError::BadSignature)));
}

// Requires real signature verification; skip under `testing` or `skip-sig-verify`.
#[test]
#[cfg(all(feature = "pq44-runtime", not(feature = "testing"), not(feature = "skip-sig-verify")))]
fn rejects_wrong_chain_id() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();

    let chain_id_ok = [0xE0; 20];
    let chain_id_wrong = [0xEE; 20];
    let b = builder(chain_id_ok);
    let from = b.sender();
    let to = tb::addr(0xA2);

    accts.credit(from, 10_000);

    let stx = b.build(to, 10, 1, 0);
    // Verify against the wrong chain id -> signature mismatch
    let res = apply_signed_tx(&mut accts, &mut supply, chain_id_wrong, &stx);
    assert!(matches!(res, Err(TxApplyError::BadSignature)));
}

#[test]
fn rejects_stateless_bad_shape_amount_zero() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();

    let chain_id = [0xE0; 20];
    let b = builder(chain_id);
    let _from = b.sender(); // no funding needed; we want stateless to trip first
    let to = tb::addr(0xA3);

    // amount = 0 should fail stateless validation
    let stx = b.build(to, 0, 1, 0);
    let res = apply_signed_tx(&mut accts, &mut supply, chain_id, &stx);
    assert!(
        res.is_err(),
        "amount=0 should be rejected during validation, but got: {:?}",
        res
    );
}

#[test]
fn rejects_insufficient_funds() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();

    let chain_id = [0xE0; 20];
    let b = builder(chain_id);
    let from = b.sender();
    let to = tb::addr(0xA4);

    // Balance smaller than amount + fee
    accts.credit(from, 5); // have 5, need 10 + 1

    let stx = b.build(to, 10, 1, 0);
    let res = apply_signed_tx(&mut accts, &mut supply, chain_id, &stx);
    assert!(matches!(res, Err(TxApplyError::State(_))));
}

#[test]
fn rejects_nonce_replay() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();

    let chain_id = [0xE0; 20];
    let b = builder(chain_id);
    let from = b.sender();
    let to = tb::addr(0xA5);

    accts.credit(from, 10_000);

    // First tx with nonce 0 should apply
    let stx0 = b.build(to, 10, 1, 0);
    assert!(apply_signed_tx(&mut accts, &mut supply, chain_id, &stx0).is_ok());

    // Replay nonce 0 should fail (expect stateful BadNonce wrapped in State)
    let replay = b.build(to, 1, 1, 0);
    let res = apply_signed_tx(&mut accts, &mut supply, chain_id, &replay);
    assert!(matches!(res, Err(TxApplyError::State(_))));
}
