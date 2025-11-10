use eezo_crypto::suite::CryptoSuite;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RotationPolicy {
    pub active: CryptoSuite,
    pub next: Option<CryptoSuite>,
    /// Heights ≤ this value accept `next` in addition to `active` (inclusive).
    /// None disables the dual-accept window.
    pub dual_accept_until: Option<u64>,
    /// Optional metadata: first height where `active` became effective.
    pub activated_at_height: Option<u64>,
}

impl RotationPolicy {
    /// T40.2: returns true iff `suite` is acceptable at `height`
    ///  - height < window_start: ONLY active
    ///  - window_start..=dual_accept_until: active OR next
    ///  - height > dual_accept_until: ONLY next
    pub fn accept(&self, height: u64, suite: CryptoSuite) -> bool {
        let active = self.active;
        let next   = self.next;

        // no rotation scheduled → only active is valid
        let Some(next) = next else { return suite == active; };

        // if we have a cutoff height, enforce it strictly (post-cutoff: new only)
        if let Some(cut) = self.dual_accept_until {
            if height > cut {
                return suite == next;
            }
        }

        // window not yet open → active only
        if !self.is_window_open(height) {
            return suite == active;
        }

        // within window → either is acceptable
        suite == active || suite == next
    }

    /// Alias with more explicit name for call sites.
    #[inline]
    pub fn accept_suite_at(&self, height: u64, suite: CryptoSuite) -> bool {
        self.accept(height, suite)
    }

    /// Returns true if the dual-accept window is considered open at `height`.
    #[inline]
    pub fn is_window_open(&self, height: u64) -> bool {
        matches!(self.dual_accept_until, Some(until) if height <= until)
    }

    /// 0/1 helper suitable for a Prometheus gauge.
    #[inline]
    pub fn window_open_gauge(&self, height: u64) -> u8 {
        if self.is_window_open(height) { 1 } else { 0 }
    }

    /// Lightweight sanity checks for config/CLI.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.next.is_none() && self.dual_accept_until.is_some() {
            return Err("dual_accept_until set but next suite is None");
        }
        if let (Some(_next), Some(until)) = (self.next, self.dual_accept_until) {
            if let Some(start) = self.activated_at_height {
                if until < start {
                    return Err("dual_accept_until must be >= activated_at_height");
                }
            }
            if until == 0 {
                return Err("dual_accept_until must be > 0 (or None)");
            }
        }
        Ok(())
    }

    // -------- T34.2 helpers (dual-emit & verify) --------
    /// Preferred verification order at `height`.
    /// Always tries `active` first; if the dual-accept window is open and `next` exists,
    /// returns it as the optional second choice.
    #[inline]
    pub fn verify_order(&self, height: u64) -> (CryptoSuite, Option<CryptoSuite>) {
        let first = self.active;
        let second = if self.is_window_open(height) { self.next } else { None };
        (first, second)
    }

    /// Should producers (node/prover) **emit both anchors** at this `height`?
    /// This lets callers decide whether to attach SPHINCS+ anchors in parallel
    /// to ML-DSA-44 during the rotation window.
    #[inline]
    pub fn should_emit_dual(&self, height: u64) -> bool {
        self.next.is_some() && self.is_window_open(height)
    }

    /// Returns `Some(next)` iff the window is open and a next suite is defined.
    #[inline]
    pub fn next_if_allowed(&self, height: u64) -> Option<CryptoSuite> {
        if self.is_window_open(height) { self.next } else { None }
    }

    /// Enforce that a header/checkpoint/anchor tagged with `suite` is acceptable at `height`.
    /// Use this in header preflight / checkpoint attach code paths.
    #[inline]
    pub fn enforce_suite(&self, height: u64, suite: CryptoSuite) -> Result<(), &'static str> {
        if self.accept(height, suite) { Ok(()) } else { Err("suite not accepted at height") }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_accepts_correctly() {
        let p = RotationPolicy {
            active: CryptoSuite::MlDsa44,
            next: Some(CryptoSuite::SphincsPq),
            dual_accept_until: Some(140),
            activated_at_height: Some(100),
        };
        // inside window
        assert!(p.accept(120, CryptoSuite::MlDsa44));
        assert!(p.accept(120, CryptoSuite::SphincsPq));
        // after window (T40.2): ONLY next is valid
        assert!(!p.accept(200, CryptoSuite::MlDsa44));
        assert!(p.accept(200, CryptoSuite::SphincsPq));
        // validate sane
        assert!(p.validate().is_ok());
    }

    #[test]
    fn invalid_window_detection() {
        let bad = RotationPolicy {
            active: CryptoSuite::MlDsa44,
            next: None,
            dual_accept_until: Some(123),
            activated_at_height: None,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn verify_order_and_dual_emit_semantics() {
        let p = RotationPolicy {
            active: CryptoSuite::MlDsa44,
            next: Some(CryptoSuite::SphincsPq),
            dual_accept_until: Some(150),
            activated_at_height: Some(100),
        };
        // inside window
        let (a, b) = p.verify_order(140);
        assert_eq!(a, CryptoSuite::MlDsa44);
        assert_eq!(b, Some(CryptoSuite::SphincsPq));
        assert!(p.should_emit_dual(140));
        assert_eq!(p.next_if_allowed(140), Some(CryptoSuite::SphincsPq));
        assert!(p.enforce_suite(140, CryptoSuite::MlDsa44).is_ok());
        assert!(p.enforce_suite(140, CryptoSuite::SphincsPq).is_ok());

        // after window
        let (a2, b2) = p.verify_order(200);
        assert_eq!(a2, CryptoSuite::MlDsa44);
        assert_eq!(b2, None);
        assert!(!p.should_emit_dual(200));
        assert_eq!(p.next_if_allowed(200), None);
        // T40.2: after cutoff, old invalid / new valid
        assert!(p.enforce_suite(200, CryptoSuite::MlDsa44).is_err());
        assert!(p.enforce_suite(200, CryptoSuite::SphincsPq).is_ok());
    }
	
}
