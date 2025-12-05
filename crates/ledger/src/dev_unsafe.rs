// crates/ledger/src/dev_unsafe.rs
//
// T77.SAFE-2: Centralized dev-unsafe mode gate for security-sensitive features.
//
// This module provides a single point of control for dev-mode features that
// bypass signature verification and other security checks. These features:
// - MUST NEVER be enabled in production, testnet, or mainnet builds
// - Are only available when the `dev-unsafe` feature is explicitly enabled
// - Are useful for local development benchmarks and testing
//
// ## Usage
//
// 1. Check if dev-unsafe mode is available at compile-time:
//    `#[cfg(feature = "dev-unsafe")]`
//
// 2. Check if unsigned tx is allowed at runtime:
//    `dev_unsafe::allow_unsigned_tx()`
//
// 3. Log a warning on startup (call once):
//    `dev_unsafe::log_startup_warning()`

use std::sync::atomic::{AtomicBool, Ordering};

// Track whether we've already logged the startup warning
static STARTUP_WARNING_LOGGED: AtomicBool = AtomicBool::new(false);

/// T77.SAFE-2: Compile-time check - is dev-unsafe mode enabled in this build?
///
/// Returns `true` only when built with the `dev-unsafe` feature.
/// This is a const function for compile-time evaluation.
#[inline]
pub const fn is_dev_unsafe_build() -> bool {
    cfg!(feature = "dev-unsafe")
}

/// T77.SAFE-2: Runtime check - should we allow unsigned transactions?
///
/// Returns `true` only when:
/// 1. The build was compiled with `dev-unsafe` feature AND
/// 2. The `EEZO_DEV_ALLOW_UNSIGNED_TX` environment variable is set to "1", "true", or "yes"
///
/// In builds without `dev-unsafe`, this ALWAYS returns `false` regardless of
/// any environment variable settings.
#[inline]
pub fn allow_unsigned_tx() -> bool {
    // Compile-time gate: if dev-unsafe is not enabled, always return false
    #[cfg(not(feature = "dev-unsafe"))]
    {
        false
    }

    #[cfg(feature = "dev-unsafe")]
    {
        match std::env::var("EEZO_DEV_ALLOW_UNSIGNED_TX") {
            Ok(v) => {
                let v = v.to_ascii_lowercase();
                v == "1" || v == "true" || v == "yes"
            }
            Err(_) => false,
        }
    }
}

/// T77.SAFE-2: Log a startup warning if dev-unsafe mode is active.
///
/// This should be called once at node startup. It will:
/// - Log a prominent warning if `dev-unsafe` feature is compiled in
/// - Log an additional warning if `EEZO_DEV_ALLOW_UNSIGNED_TX` is set
/// - Only log once (subsequent calls are no-ops)
pub fn log_startup_warning() {
    // Only log once
    if STARTUP_WARNING_LOGGED.swap(true, Ordering::SeqCst) {
        return;
    }

    #[cfg(feature = "dev-unsafe")]
    {
        log::warn!("===============================================================================");
        log::warn!("[DEV-UNSAFE] This build has dev-unsafe mode ENABLED.");
        log::warn!("[DEV-UNSAFE] Signature verification bypass is available.");
        log::warn!("[DEV-UNSAFE] NEVER use this build in production, testnet, or mainnet!");
        log::warn!("===============================================================================");

        if allow_unsigned_tx() {
            log::warn!("[DEV-UNSAFE] EEZO_DEV_ALLOW_UNSIGNED_TX=1 is SET.");
            log::warn!("[DEV-UNSAFE] Unsigned transactions WILL BE ACCEPTED.");
            log::warn!("[DEV-UNSAFE] This is extremely dangerous and should only be used for local benchmarks!");
        }
    }

    #[cfg(not(feature = "dev-unsafe"))]
    {
        // In safe builds, log nothing - this is the expected production state
    }
}

/// T77.SAFE-2: Check if skip-sig-verify feature is active.
///
/// Returns `true` only when built with `skip-sig-verify` feature.
/// Since `skip-sig-verify` now requires `dev-unsafe`, this is equivalent
/// to checking for that specific feature combination.
#[inline]
pub const fn is_skip_sig_verify_build() -> bool {
    cfg!(feature = "skip-sig-verify")
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// T77.SAFE-2: Verify that compile-time gate works correctly.
    #[test]
    fn test_is_dev_unsafe_build() {
        // This test's result depends on whether dev-unsafe is enabled
        let expected = cfg!(feature = "dev-unsafe");
        assert_eq!(is_dev_unsafe_build(), expected);
    }

    /// T77.SAFE-2: Verify that skip-sig-verify check works correctly.
    #[test]
    fn test_is_skip_sig_verify_build() {
        let expected = cfg!(feature = "skip-sig-verify");
        assert_eq!(is_skip_sig_verify_build(), expected);
    }

    /// T77.SAFE-2: In builds without dev-unsafe, allow_unsigned_tx() must return false.
    #[cfg(not(feature = "dev-unsafe"))]
    #[test]
    fn test_allow_unsigned_tx_without_dev_unsafe() {
        // Even if someone sets the env var, it should have no effect
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "1");
        assert!(!allow_unsigned_tx(), "allow_unsigned_tx should return false without dev-unsafe feature");
        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
    }

    /// T77.SAFE-2: In builds with dev-unsafe, allow_unsigned_tx() should respect env var.
    #[cfg(feature = "dev-unsafe")]
    #[test]
    fn test_allow_unsigned_tx_with_dev_unsafe() {
        // Default: not set
        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
        assert!(!allow_unsigned_tx(), "should be false when env var not set");

        // Set to "1"
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "1");
        assert!(allow_unsigned_tx(), "should be true when env var is '1'");

        // Set to "true"
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "true");
        assert!(allow_unsigned_tx(), "should be true when env var is 'true'");

        // Set to "yes"
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "yes");
        assert!(allow_unsigned_tx(), "should be true when env var is 'yes'");

        // Set to "TRUE" (case insensitive)
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "TRUE");
        assert!(allow_unsigned_tx(), "should be true when env var is 'TRUE' (case insensitive)");

        // Set to "0" (should be false)
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "0");
        assert!(!allow_unsigned_tx(), "should be false when env var is '0'");

        // Set to "no"
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "no");
        assert!(!allow_unsigned_tx(), "should be false when env var is 'no'");

        // Cleanup
        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
    }
}
