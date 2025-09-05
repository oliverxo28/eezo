#[cfg(feature = "metrics")]
pub fn measure_batch<F, T>(ok: usize, fail: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    let _t = crate::metrics::VERIFY_BATCH_DUR_MS.start_timer();
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