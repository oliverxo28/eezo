#[cfg(feature = "metrics")]
pub fn measure_batch<F, T>(ok: usize, fail: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    // Align with metrics.rs (VERIFY_BATCH_DURATION)
    let _t = crate::metrics::VERIFY_BATCH_DURATION.start_timer();
    let out = f();
    crate::metrics::VERIFY_BATCH_OK.inc_by(ok as u64);
    crate::metrics::VERIFY_BATCH_FAIL.inc_by(fail as u64);
    out
}

#[cfg(not(feature = "metrics"))]
pub fn measure_batch<F, T>(_ok: usize, _fail: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    f()
}

#[cfg(not(feature = "metrics"))]
#[inline]
pub fn observe_supply(_s: &crate::Supply) {
    // No-op when metrics are disabled
}

// When the `metrics` feature is off, provide no-op registration to keep callers simple.
#[cfg(not(feature = "metrics"))]
pub fn register_t32_metrics() {}