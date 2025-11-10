// crates/crypto/src/suite.rs
use core::fmt;
use thiserror::Error;

// Optional serde derives for persistence / config I/O.
// Enabled when the crate is built with the "serde_support" feature.
#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum CryptoSuite {
    MlDsa44   = 1,
    SphincsPq = 2, // wired in T34.2
}

impl Default for CryptoSuite {
    fn default() -> Self { CryptoSuite::MlDsa44 }
}

#[derive(Debug, Error)]
pub enum SuiteError {
    #[error("unknown suite id: {0}")]
    Unknown(u8),
}

impl TryFrom<u8> for CryptoSuite {
    type Error = SuiteError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(CryptoSuite::MlDsa44),
            2 => Ok(CryptoSuite::SphincsPq),
            _ => Err(SuiteError::Unknown(v)),
        }
    }
}

impl From<CryptoSuite> for u8 { fn from(s: CryptoSuite) -> u8 { s as u8 } }

impl CryptoSuite {
    /// Stable numeric ID persisted/emitted on-chain.
    #[inline]
    pub const fn as_id(self) -> u8 { self as u8 }

    /// Human-friendly canonical machine name (stable across releases).
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            CryptoSuite::MlDsa44 => "ml-dsa-44",
            CryptoSuite::SphincsPq => "sphincs+",
        }
    }

    /// Returns true if this suite is compiled in / supported by the build.
    /// (Sphincs+ can be feature-gated; keep this fast check here.)
    #[inline]
    pub const fn is_supported(self) -> bool {
        match self {
            CryptoSuite::MlDsa44 => true,
            CryptoSuite::SphincsPq => true, // toggle at verifier call sites if feature-gated
        }
    }
}

impl fmt::Display for CryptoSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoSuite::MlDsa44 => write!(f, "ml-dsa-44"),
            CryptoSuite::SphincsPq => write!(f, "sphincs+"),
        }
    }
}

// ---- Rotation framework (T34.0) -------------------------------------------

/// Rotation policy describing the currently active suite, the next suite
/// scheduled, and the heights controlling activation and dual-accept window.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationWindow {
    /// Suite used for new signatures/checkpoints after `activated_at_height`.
    pub active: CryptoSuite,
    /// Suite permitted *in addition* to `active` during the dual-accept window.
    pub next: CryptoSuite,
    /// First height at which `active` is enforced for new signatures/headers.
    pub activated_at_height: u64,
    /// Heights ≤ this value accept either `active` or `next` (dual-accept).
    /// Set to 0 to disable the window.
    pub dual_accept_until: u64,
}

impl RotationWindow {
    /// Returns true if the given height is inside the dual-accept window.
    #[inline]
    pub fn is_within_dual_accept(&self, height: u64) -> bool {
        self.dual_accept_until != 0 && height <= self.dual_accept_until
    }

    /// Policy decision: whether `suite` is acceptable at `height`.
    /// - Before/at `dual_accept_until`: both `active` and `next` are accepted.
    /// - After the window: only `active` is accepted (enforced forward).
    #[inline]
    pub fn accept_suite_at(&self, height: u64, suite: CryptoSuite) -> bool {
        if self.is_within_dual_accept(height) {
            suite == self.active || suite == self.next
        } else {
            suite == self.active
        }
    }

    /// Minimal sanity checks for configs (used by CLI / node boot).
    #[inline]
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.active.is_supported() || !self.next.is_supported() {
            return Err("unsupported crypto suite in rotation window");
        }
        if self.dual_accept_until != 0 && self.dual_accept_until < self.activated_at_height {
            return Err("dual_accept_until must be >= activated_at_height or 0");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ids() {
        for id in [1u8, 2u8] {
            let s = CryptoSuite::try_from(id).unwrap();
            assert_eq!(u8::from(s), id);
            assert_eq!(s.as_id(), id);
            assert!(s.is_supported());
            assert!(!s.name().is_empty());
        }
        assert!(matches!(
            CryptoSuite::try_from(99), Err(SuiteError::Unknown(99))
        ));
    }

    #[test]
    fn rotation_policy_accepts_correctly() {
        let r = RotationWindow {
            active: CryptoSuite::MlDsa44,
            next: CryptoSuite::SphincsPq,
            activated_at_height: 100,
            dual_accept_until: 140,
        };
        // inside window
        assert!(r.accept_suite_at(120, CryptoSuite::MlDsa44));
        assert!(r.accept_suite_at(120, CryptoSuite::SphincsPq));
        // after window
        assert!(r.accept_suite_at(200, CryptoSuite::MlDsa44));
        assert!(!r.accept_suite_at(200, CryptoSuite::SphincsPq));
        // validate monotonic constraint
        assert!(r.validate().is_ok());
    }
}

