// Minimal metrics shim for the crypto crate (T40.1 shadow verify counters)

#[cfg(feature = "metrics")]
mod inner {
    use once_cell::sync::Lazy;
    use prometheus::{register_int_counter, IntCounter};

    pub static SIG_SHADOW_SUCCESS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter!(
            "eezo_sig_shadow_success_total",
            "Shadow verify: next-suite signatures that would have succeeded"
        ).expect("register eezo_sig_shadow_success_total")
    });

    pub static SIG_SHADOW_FAILURE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter!(
            "eezo_sig_shadow_failure_total",
            "Shadow verify: next-suite signatures that would have failed"
        ).expect("register eezo_sig_shadow_failure_total")
    });

    pub static SIG_SHADOW_ATTEMPTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter!(
            "eezo_sig_shadow_attempts_total",
            "Shadow verify: attempts to verify with next suite"
        ).expect("register eezo_sig_shadow_attempts_total")
    });

    #[inline] pub fn inc_success() { SIG_SHADOW_SUCCESS_TOTAL.inc(); }
    #[inline] pub fn inc_failure() { SIG_SHADOW_FAILURE_TOTAL.inc(); }
    #[inline] pub fn inc_attempt() { SIG_SHADOW_ATTEMPTS_TOTAL.inc(); }
}

#[cfg(feature = "metrics")]
#[inline] pub fn sig_shadow_success_inc() { inner::inc_success() }
#[cfg(feature = "metrics")]
#[inline] pub fn sig_shadow_failure_inc() { inner::inc_failure() }
#[cfg(feature = "metrics")]
#[inline] pub fn sig_shadow_attempts_inc() { inner::inc_attempt() }

// no-ops when metrics are disabled
#[cfg(not(feature = "metrics"))]
#[inline] pub fn sig_shadow_success_inc() {}
#[cfg(not(feature = "metrics"))]
#[inline] pub fn sig_shadow_failure_inc() {}
#[cfg(not(feature = "metrics"))]
#[inline] pub fn sig_shadow_attempts_inc() {}

// -----------------------------------------------------------------------------
// T40.1: optional eager registration so counters are visible at node startup
// -----------------------------------------------------------------------------
#[cfg(feature = "metrics")]
pub fn register_t40_shadow_metrics() {
    // Touch the Lazy statics so Prometheus registers them without incrementing.
    // Derefing Lazy triggers initialization.
    let _ = &*inner::SIG_SHADOW_SUCCESS_TOTAL;
    let _ = &*inner::SIG_SHADOW_FAILURE_TOTAL;
    let _ = &*inner::SIG_SHADOW_ATTEMPTS_TOTAL;
}

#[cfg(not(feature = "metrics"))]
pub fn register_t40_shadow_metrics() {}
