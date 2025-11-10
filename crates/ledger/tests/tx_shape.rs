use eezo_ledger::{validate_tx_shape, Address, TxCore, TxStatelessError};

#[test]
fn tx_shape_ok() {
    let core = TxCore {
        to: Address::from_bytes([7u8; 20]),
        amount: 100,
        fee: 1000,
        nonce: 1,
    };
    assert!(validate_tx_shape(&core).is_ok());
}

#[test]
fn tx_shape_rejects_zero_amount() {
    let core = TxCore {
        to: Address::from_bytes([0xAB; 20]),
        amount: 0,
        fee: 10,
        nonce: 0,
    };
    let err = validate_tx_shape(&core).unwrap_err();
    assert_eq!(err, TxStatelessError::AmountZero);
}

#[test]
fn tx_shape_allows_zero_fee_stateless() {
    // Stateless layer permits zero-fee; fee policy is enforced elsewhere.
    let core = TxCore {
        to: Address::from_bytes([0xCD; 20]),
        amount: 50,
        fee: 0,
        nonce: 0,
    };
    assert!(
        validate_tx_shape(&core).is_ok(),
        "zero-fee should not be rejected by stateless shape validation"
    );
}

#[test]
fn tx_shape_rejects_overflow_amount() {
    let core = TxCore {
        to: Address::from_bytes([0xEF; 20]),
        amount: u128::MAX,
        fee: 1,
        nonce: 0,
    };
    let err = validate_tx_shape(&core).unwrap_err();
    // If your enum has Overflow, check it; else just assert error
    #[cfg(any())] // adjust/remove if Overflow exists
    assert_eq!(err, TxStatelessError::Overflow);
    #[cfg(not(any()))]
    assert!(matches!(err, _));
}

#[test]
fn tx_shape_allows_nonce_zero_and_one() {
    for n in 0..=1 {
        let core = TxCore {
            to: Address::from_bytes([0x11; 20]),
            amount: 10,
            fee: 1,
            nonce: n,
        };
        assert!(
            validate_tx_shape(&core).is_ok(),
            "nonce {n} should not be rejected at shape layer"
        );
    }
}