//! rotation window semantics & dual-emit tests (T34.2)

use eezo_ledger::rotation::RotationPolicy;
use eezo_crypto::suite::CryptoSuite;

#[test]
fn accept_matrix_inside_and_after_window() {
    let p = RotationPolicy {
        active: CryptoSuite::MlDsa44,
        next:   Some(CryptoSuite::SphincsPq),
        dual_accept_until: Some(150),
        activated_at_height: Some(100),
    };

    // inside window
    assert!(p.accept(120, CryptoSuite::MlDsa44));
    assert!(p.accept(120, CryptoSuite::SphincsPq));
    assert!(p.is_window_open(120));
    let (first, second) = p.verify_order(120);
    assert_eq!(first, CryptoSuite::MlDsa44);
    assert_eq!(second, Some(CryptoSuite::SphincsPq));
    assert!(p.should_emit_dual(120));
    assert!(p.enforce_suite(120, CryptoSuite::SphincsPq).is_ok());

    // after window
    assert!(p.accept(200, CryptoSuite::MlDsa44));
    assert!(!p.accept(200, CryptoSuite::SphincsPq));
    assert!(!p.is_window_open(200));
    let (first2, second2) = p.verify_order(200);
    assert_eq!(first2, CryptoSuite::MlDsa44);
    assert!(second2.is_none());
    assert!(!p.should_emit_dual(200));
    assert!(p.enforce_suite(200, CryptoSuite::SphincsPq).is_err());
}

#[test]
fn validate_policy_guard_rails() {
    // invalid: window set but no next
    let bad = RotationPolicy {
        active: CryptoSuite::MlDsa44,
        next: None,
        dual_accept_until: Some(123),
        activated_at_height: Some(100),
    };
    assert!(bad.validate().is_err());

    // valid: window aligns with activation height
    let ok = RotationPolicy {
        active: CryptoSuite::MlDsa44,
        next: Some(CryptoSuite::SphincsPq),
        dual_accept_until: Some(130),
        activated_at_height: Some(100),
    };
    assert!(ok.validate().is_ok());
}
