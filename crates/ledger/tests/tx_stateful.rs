use eezo_ledger::tx::{apply_tx, validate_tx_stateful, TxStateError};
use eezo_ledger::{Account, Accounts, Address, Supply, TxCore};

#[test]
fn apply_updates_balances_and_nonce_and_burns_fee() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();

    let from = Address::from_bytes([1u8; 20]);
    let to   = Address::from_bytes([2u8; 20]);

    // Fund sender and set starting nonce = 0.
    accts.put(from, Account { balance: 1_000, nonce: 0 });

    // First tx MUST use nonce = current account nonce (0).
    let core = TxCore { to, amount: 100, fee: 1, nonce: 0 };

    // Pure stateful check passes…
    validate_tx_stateful(&accts, from, &core).unwrap();

    // …and applying updates balances + bumps nonce + (implicitly) burns fee.
    apply_tx(&mut accts, &mut supply, from, &core).unwrap();

    assert_eq!(accts.balance_of(from), 1_000 - 100 - 1, "sender pays amount+fee");
    assert_eq!(accts.balance_of(to), 100, "receiver gets amount");
    assert_eq!(accts.nonce_of(from), 1, "nonce increments");
    // We intentionally do not assert on Supply here; fee burn accounting is covered elsewhere.
}

#[test]
fn rejects_insufficient_funds_and_keeps_state_unchanged() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();
    let sender = Address::from_bytes([9u8; 20]);
    let to     = Address::from_bytes([8u8; 20]);

    // Balance is too small to cover amount + fee; nonce starts at 0.
    accts.put(sender, Account { balance: 5, nonce: 0 });

    // Nonce matches current (0) so we specifically hit InsufficientFunds.
    let core = TxCore { to, amount: 10, fee: 1, nonce: 0 };

    let before_sender_bal = accts.balance_of(sender);
    let before_sender_nonce = accts.nonce_of(sender);
    let before_to_bal = accts.balance_of(to);

    let err = validate_tx_stateful(&accts, sender, &core).unwrap_err();
    assert!(matches!(err, TxStateError::InsufficientFunds { .. }));

    // No state changes on failed validation
    assert_eq!(accts.balance_of(sender), before_sender_bal);
    assert_eq!(accts.nonce_of(sender), before_sender_nonce);
    assert_eq!(accts.balance_of(to), before_to_bal);
}

#[test]
fn rejects_bad_nonce_replay_and_keeps_state_unchanged() {
    let mut accts = Accounts::default();
    let mut supply = Supply::default();
    let sender = Address::from_bytes([3u8; 20]);
    let to     = Address::from_bytes([4u8; 20]);

    accts.put(sender, Account { balance: 1_000, nonce: 0 });

    // First, a valid apply with nonce 0 (to move state forward)
    let ok = TxCore { to, amount: 10, fee: 1, nonce: 0 };
    apply_tx(&mut accts, &mut supply, sender, &ok).unwrap();
    assert_eq!(accts.nonce_of(sender), 1);

    // Replay the same nonce 0 -> BadNonce expected:1 got:0
    let replay = TxCore { to, amount: 5, fee: 1, nonce: 0 };

    let bal_before = accts.balance_of(sender);
    let to_before  = accts.balance_of(to);
    let nonce_before = accts.nonce_of(sender);

    let err = validate_tx_stateful(&accts, sender, &replay).unwrap_err();
    assert!(matches!(err, TxStateError::BadNonce { expected: 1, got: 0 }));

    // State unchanged on failed validation
    assert_eq!(accts.balance_of(sender), bal_before);
    assert_eq!(accts.balance_of(to), to_before);
    assert_eq!(accts.nonce_of(sender), nonce_before);
}

#[test]
fn rejects_bad_nonce_gap_and_keeps_state_unchanged() {
    let mut accts = Accounts::default();
    let sender = Address::from_bytes([5u8; 20]);
    let to     = Address::from_bytes([6u8; 20]);

    accts.put(sender, Account { balance: 1_000, nonce: 0 });

    // Gap nonce (5) with current=0 -> BadNonce
    let gap = TxCore { to, amount: 1, fee: 0, nonce: 5 };

    let bal_before = accts.balance_of(sender);
    let to_before  = accts.balance_of(to);
    let nonce_before = accts.nonce_of(sender);

    let err = validate_tx_stateful(&accts, sender, &gap).unwrap_err();
    assert!(matches!(err, TxStateError::BadNonce { expected: 0, got: 5 }));

    // No state changes
    assert_eq!(accts.balance_of(sender), bal_before);
    assert_eq!(accts.balance_of(to), to_before);
    assert_eq!(accts.nonce_of(sender), nonce_before);
}
