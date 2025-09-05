#![cfg(feature = "metrics")]
use once_cell::sync::Lazy;
use prometheus::{register_histogram, register_int_counter, Histogram, IntCounter};

pub static VERIFY_BATCH_OK: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("verify_batch_ok", "OK msgs in batch").unwrap());

pub static VERIFY_BATCH_FAIL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("verify_batch_fail", "Failed msgs in batch").unwrap());

pub static VERIFY_BATCH_DUR_MS: Lazy<Histogram> =
    Lazy::new(|| register_histogram!("verify_batch_dur_ms", "Batch verification time (ms)").unwrap());

#[cfg(feature = "metrics")]
pub fn observe_batch(ok: usize, fail: usize, _dur_ms: f64) {
    let _t = VERIFY_BATCH_DUR_MS.start_timer();
    VERIFY_BATCH_OK.inc_by(ok as u64);
    VERIFY_BATCH_FAIL.inc_by(fail as u64);
    drop(_t);
}
