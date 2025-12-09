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
//
// ## T78.8: Devnet-Safe Profile & Guardrails
//
// The `devnet-safe` build profile ensures:
// - Default consensus mode is `dag-primary`
// - Default `EEZO_DAG_ORDERING_ENABLED` is `true`
// - `dev-unsafe` is NOT compiled in (no unsigned tx support)
// - Setting `EEZO_DEV_ALLOW_UNSIGNED_TX=1` logs a loud warning but has no effect
//
// The `dev-unsafe` build profile (for local TPS benchmarks only):
// - `EEZO_DEV_ALLOW_UNSIGNED_TX=1` enables unsigned tx acceptance
// - Prominent `[DEV-UNSAFE]` warnings are printed at startup
//
// See `book/src/dev_unsafe_modes.md` for the full profiles matrix.

use std::sync::atomic::{AtomicBool, Ordering};

// Track whether we've already logged the startup warning
static STARTUP_WARNING_LOGGED: AtomicBool = AtomicBool::new(false);

/// T78.8: Helper function to parse an environment variable as a boolean "truthy" value.
///
/// Returns `true` if the env var is set to "1", "true", or "yes" (case insensitive).
/// Returns `false` if the env var is not set or has any other value.
#[inline]
fn parse_env_var_truthy(var_name: &str) -> bool {
    match std::env::var(var_name) {
        Ok(v) => {
            let v = v.to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        }
        Err(_) => false,
    }
}

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
        parse_env_var_truthy("EEZO_DEV_ALLOW_UNSIGNED_TX")
    }
}

/// T77.SAFE-2/T78.8: Log a startup warning if dev-unsafe mode is active.
///
/// This should be called once at node startup. It will:
/// - Log a prominent warning if `dev-unsafe` feature is compiled in
/// - Log an additional warning if `EEZO_DEV_ALLOW_UNSIGNED_TX` is set
/// - T78.8: Log the build profile name (devnet-safe, dev-unsafe, or generic)
/// - T78.8: In safe builds, log a loud warning if env var is set but ignored
/// - Only log once (subsequent calls are no-ops)
pub fn log_startup_warning() {
    // Only log once
    if STARTUP_WARNING_LOGGED.swap(true, Ordering::SeqCst) {
        return;
    }

    // T78.8: Always log the build profile for clarity
    log::info!("[T78.8] Build profile: {}", build_profile_name());

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
        // T78.8: In safe builds, check if EEZO_DEV_ALLOW_UNSIGNED_TX is set and log a loud warning
        // This helps users understand why their env var is being ignored
        if should_warn_unsigned_tx_env_var_ignored() {
            log::warn!("===============================================================================");
            log::warn!("[T78.8] EEZO_DEV_ALLOW_UNSIGNED_TX is set but this is a SAFE BUILD.");
            log::warn!("[T78.8] The env var has NO EFFECT. Unsigned txs will be REJECTED.");
            log::warn!("[T78.8] Build profile: {}", build_profile_name());
            log::warn!("[T78.8] To enable unsigned tx support, rebuild with: --features dev-unsafe");
            log::warn!("===============================================================================");
        } else {
            // T78.8: Log a friendly message for safe builds
            log::info!("[T78.8] Safe build profile active. Unsigned transactions are disabled.");
        }
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

/// T78.8: Check if `EEZO_DEV_ALLOW_UNSIGNED_TX` env var is set to a "truthy" value.
///
/// Returns `true` if the env var is set to "1", "true", or "yes" (case insensitive).
/// This is useful for detecting when the user *expects* unsigned tx to be enabled,
/// regardless of whether the feature is actually compiled in.
///
/// Unlike `allow_unsigned_tx()`, this function does NOT check the compile-time feature.
#[inline]
pub fn env_var_unsigned_tx_is_set() -> bool {
    parse_env_var_truthy("EEZO_DEV_ALLOW_UNSIGNED_TX")
}

/// T78.8: Check if we should fail fast because `EEZO_DEV_ALLOW_UNSIGNED_TX` is set
/// in a non-dev-unsafe build.
///
/// Returns `true` if:
/// - The `dev-unsafe` feature is NOT compiled in, AND
/// - The `EEZO_DEV_ALLOW_UNSIGNED_TX` env var is set to a truthy value
///
/// In this case, the caller can choose to:
/// 1. Log a warning and continue (lenient mode), or
/// 2. Return an error and refuse to start (strict mode)
///
/// The recommended behavior for devnet-safe builds is to log a loud warning but
/// continue, ensuring developers notice the misconfiguration without breaking CI.
#[inline]
pub fn should_warn_unsigned_tx_env_var_ignored() -> bool {
    #[cfg(feature = "dev-unsafe")]
    {
        false // env var is not ignored when dev-unsafe is compiled in
    }

    #[cfg(not(feature = "dev-unsafe"))]
    {
        env_var_unsigned_tx_is_set()
    }
}

/// T78.8: Get the current build profile name for logging purposes.
///
/// Returns a human-readable string describing the build profile.
/// This is useful for startup banners and diagnostics.
pub fn build_profile_name() -> &'static str {
    if cfg!(feature = "dev-unsafe") {
        "dev-unsafe (benchmark profile)"
    } else if cfg!(feature = "devnet-safe") {
        "devnet-safe"
    } else {
        "generic (safe)"
    }
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

    // =========================================================================
    // T78.8: Devnet-Safe Profile & Guardrails Tests
    // =========================================================================

    /// T78.8: Test that `env_var_unsigned_tx_is_set()` correctly detects env var.
    /// This function does NOT depend on compile-time features.
    #[test]
    fn test_env_var_unsigned_tx_is_set() {
        // Clean state
        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
        assert!(!env_var_unsigned_tx_is_set(), "should be false when env var not set");

        // Set to "1"
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "1");
        assert!(env_var_unsigned_tx_is_set(), "should be true when env var is '1'");

        // Set to "true"
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "true");
        assert!(env_var_unsigned_tx_is_set(), "should be true when env var is 'true'");

        // Set to "yes"
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "yes");
        assert!(env_var_unsigned_tx_is_set(), "should be true when env var is 'yes'");

        // Set to "TRUE" (case insensitive)
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "TRUE");
        assert!(env_var_unsigned_tx_is_set(), "should be true when env var is 'TRUE'");

        // Set to "0" (should be false)
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "0");
        assert!(!env_var_unsigned_tx_is_set(), "should be false when env var is '0'");

        // Set to "no"
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "no");
        assert!(!env_var_unsigned_tx_is_set(), "should be false when env var is 'no'");

        // Set to "false"
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "false");
        assert!(!env_var_unsigned_tx_is_set(), "should be false when env var is 'false'");

        // Cleanup
        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
    }

    /// T78.8: Test that `should_warn_unsigned_tx_env_var_ignored()` works correctly
    /// in non-dev-unsafe builds.
    #[cfg(not(feature = "dev-unsafe"))]
    #[test]
    fn test_should_warn_unsigned_tx_env_var_ignored_safe_build() {
        // In a safe build, should return true when env var is set
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "1");
        assert!(
            should_warn_unsigned_tx_env_var_ignored(),
            "should warn when env var is set in safe build"
        );

        // Should return false when env var is not set
        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
        assert!(
            !should_warn_unsigned_tx_env_var_ignored(),
            "should not warn when env var is not set"
        );

        // Should return false when env var is set to falsy value
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "0");
        assert!(
            !should_warn_unsigned_tx_env_var_ignored(),
            "should not warn when env var is '0'"
        );

        // Cleanup
        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
    }

    /// T78.8: Test that `should_warn_unsigned_tx_env_var_ignored()` always returns false
    /// in dev-unsafe builds (env var is not ignored there).
    #[cfg(feature = "dev-unsafe")]
    #[test]
    fn test_should_warn_unsigned_tx_env_var_ignored_dev_unsafe_build() {
        // In a dev-unsafe build, should always return false
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "1");
        assert!(
            !should_warn_unsigned_tx_env_var_ignored(),
            "should not warn in dev-unsafe build (env var is not ignored)"
        );

        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
        assert!(
            !should_warn_unsigned_tx_env_var_ignored(),
            "should not warn when env var is not set"
        );

        // Cleanup
        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
    }

    /// T78.8: Test that `build_profile_name()` returns a non-empty string.
    #[test]
    fn test_build_profile_name() {
        let profile = build_profile_name();
        assert!(!profile.is_empty(), "build profile name should not be empty");

        // Check that the profile name matches expected values based on features
        if cfg!(feature = "dev-unsafe") {
            assert!(
                profile.contains("dev-unsafe"),
                "dev-unsafe build should include 'dev-unsafe' in profile name"
            );
        } else if cfg!(feature = "devnet-safe") {
            assert_eq!(
                profile, "devnet-safe",
                "devnet-safe build should have 'devnet-safe' profile name"
            );
        } else {
            assert!(
                profile.contains("generic") || profile.contains("safe"),
                "generic build should include 'generic' or 'safe' in profile name"
            );
        }
    }

    /// T78.8: Critical test - in devnet-safe builds, unsigned tx must NEVER be allowed.
    /// This is the key security invariant for devnet-safe.
    #[cfg(all(feature = "devnet-safe", not(feature = "dev-unsafe")))]
    #[test]
    fn test_devnet_safe_unsigned_tx_never_allowed() {
        // Even with env var set, unsigned tx should NOT be allowed
        std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "1");
        assert!(
            !allow_unsigned_tx(),
            "CRITICAL: devnet-safe build must NEVER allow unsigned tx"
        );

        // The warning flag should be raised
        assert!(
            should_warn_unsigned_tx_env_var_ignored(),
            "devnet-safe should warn when env var is set"
        );

        // Cleanup
        std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
    }
}