//! T40.3 — rotation policy hardening tests (external test file)
//!
//! These tests verify window boundaries, no-rotation behavior,
//! validation invariants, and gauge semantics. They are pure logic
//! tests (no crypto features required).

use eezo_ledger::rotation::RotationPolicy;
use eezo_crypto::suite::CryptoSuite;

#[test]
fn t403_window_is_inclusive_on_until_and_exclusive_after() {
    // window: heights ≤ 150 accept active OR next; after 150 only next
    let p = RotationPolicy {
        active: CryptoSuite::MlDsa44,
        next: Some(CryptoSuite::SphincsPq),
        dual_accept_until: Some(150),
        activated_at_height: Some(100),
    };
    // exactly at cutoff (inclusive)
    assert!(p.accept(150, CryptoSuite::MlDsa44));
    assert!(p.accept(150, CryptoSuite::SphincsPq));
    // just after cutoff
    assert!(!p.accept(151, CryptoSuite::MlDsa44));
    assert!(p.accept(151, CryptoSuite::SphincsPq));
}

#[test]
fn t403_no_rotation_means_active_only_all_heights() {
    let p = RotationPolicy {
        active: CryptoSuite::MlDsa44,
        next: None,
        dual_accept_until: None,
        activated_at_height: None,
    };
    // any height → only active accepted
    for &h in &[0_u64, 1, 100, 10_000] {
        assert!(p.accept(h, CryptoSuite::MlDsa44), "active must be valid at h={}", h);
        assert!(
            !p.accept(h, CryptoSuite::SphincsPq),
            "next must be invalid when no rotation is scheduled (h={})",
            h
        );
        assert_eq!(p.window_open_gauge(h), 0, "no window gauge when no rotation (h={})", h);
    }
    assert!(p.validate().is_ok());
}

#[test]
fn t403_validate_invariants() {
    // until < activated_at_height → error
    let bad_order = RotationPolicy {
        active: CryptoSuite::MlDsa44,
        next: Some(CryptoSuite::SphincsPq),
        dual_accept_until: Some(99),
        activated_at_height: Some(100),
    };
    assert!(
        bad_order.validate().is_err(),
        "dual_accept_until must be >= activated_at_height"
    );

    // until == 0 → error (must be > 0 if present)
    let zero_until = RotationPolicy {
        active: CryptoSuite::MlDsa44,
        next: Some(CryptoSuite::SphincsPq),
        dual_accept_until: Some(0),
        activated_at_height: Some(1),
    };
    assert!(
        zero_until.validate().is_err(),
        "dual_accept_until must be > 0 when present"
    );
}

#[test]
fn t403_gauge_semantics_match_window_open() {
    let p = RotationPolicy {
        active: CryptoSuite::MlDsa44,
        next: Some(CryptoSuite::SphincsPq),
        dual_accept_until: Some(10),
        activated_at_height: None,
    };
    // gauge == 1 inside window (≤ until), 0 after
    assert_eq!(p.window_open_gauge(0), 1);
    assert_eq!(p.window_open_gauge(10), 1);
    assert_eq!(p.window_open_gauge(11), 0);
}
