#![cfg(feature = "metrics")]
use once_cell::sync::Lazy;
use prometheus::{
    register_gauge_vec, register_histogram, register_int_counter, register_int_counter_vec,
    GaugeVec, Histogram, HistogramOpts, IntCounter, IntCounterVec,
};
use std::sync::atomic::{AtomicU64, Ordering};

fn sec_buckets() -> Vec<f64> {
    // 5ms .. 10s (T32 recommended)
    vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
}

pub static EEZO_KEMTLS_HANDSHAKE_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    let opts = HistogramOpts::new("eezo_kemtls_handshake_seconds", "KEMTLS handshake duration (end-to-end)");
    register_histogram!(opts.buckets(sec_buckets())).unwrap()
});

pub static EEZO_KEMTLS_SESSIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_kemtls_sessions_total",
        "KEMTLS sessions established",
        &["role"] // client|server
    ).unwrap()
});
/// Count of sessions that were established via resumption.
pub static EEZO_KEMTLS_RESUMED_SESSIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_kemtls_resumed_sessions_total",
        "KEMTLS sessions established via resumption",
        &["role"] // client|server
    )
    .unwrap()
});

/// Ratio gauge: resumed / total, maintained per-process (since start).
pub static EEZO_KEMTLS_RESUME_RATIO: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "eezo_kemtls_resume_ratio",
        "Proportion of KEMTLS sessions that resumed (per-process since start)",
        &["role"] // client|server
    )
    .unwrap()
});

/// Handshake failure counter with a coarse reason label.
pub static EEZO_KEMTLS_HANDSHAKE_FAIL_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_kemtls_handshake_fail_total",
        "KEMTLS handshake failures",
        &["role","kind"] // kind: kem|confirm|auth|io|other
    )
    .unwrap()
});
// ── T37.2: AEAD tickets + sharded replay metrics ────────────────────────────
/// Count of AEAD/auth failures when decrypting resume tickets.
pub static TKT_DECRYPT_FAIL_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_kemtls_ticket_decrypt_failures_total",
        "ticket AEAD/auth failures"
    )
    .unwrap()
});

/// Count of resumes dropped due to replay detection.
pub static REPLAY_DROPPED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_kemtls_replay_dropped_total",
        "resumes dropped due to replay"
    )
    .unwrap()
});

// FIX 1: Removed the duplicate IntCounter definition of RESUME_TRUE_TOTAL
//        that was here (lines 75-81).

/// Count of fallback paths taken instead of resumption (invalid|decrypt|replay|expired).
// FIX 2: Kept the IntCounterVec version of RESUME_TRUE_TOTAL
pub static RESUME_TRUE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_resume_true_total",
        "Total successful resume count",
        &["source"]  // label: "ticket", "psk", etc.
    ).unwrap()
});

// FIX 3: Added the missing RESUME_FALLBACK_TOTAL definition
pub static RESUME_FALLBACK_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_resume_fallback_total",
        "Total resume fallback count",
        &["reason"]  // label: "replay", "decrypt", etc.
    ).unwrap()
});


// Rolling in-process tallies to drive the resume_ratio gauge.
static CLIENT_TOTAL: AtomicU64 = AtomicU64::new(0);
static CLIENT_RESUMED: AtomicU64 = AtomicU64::new(0);
static SERVER_TOTAL: AtomicU64 = AtomicU64::new(0);
static SERVER_RESUMED: AtomicU64 = AtomicU64::new(0);


// ── helpers for callers (T36.8) ─────────────────────────────────────────────
#[inline]
pub fn kemtls_handshake_observe_secs(secs: f64) {
    EEZO_KEMTLS_HANDSHAKE_SECONDS.observe(secs);
}

/// role should be "client" or "server"; unknown roles default to "server".
#[inline]
pub fn kemtls_session_inc(role: &'static str) {
    match role {
        "client" | "server" => EEZO_KEMTLS_SESSIONS_TOTAL.with_label_values(&[role]).inc(),
        _ => EEZO_KEMTLS_SESSIONS_TOTAL.with_label_values(&["server"]).inc(),
    }
}

/// Mark a successfully established session and update resume counters/gauge.
#[inline]
pub fn kemtls_session_mark(role: &'static str, resumed: bool) {
    kemtls_session_inc(role);
    match role {
        "client" => {
            let total = CLIENT_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
            if resumed {
                EEZO_KEMTLS_RESUMED_SESSIONS_TOTAL
                    .with_label_values(&["client"])
                    .inc();
                let res = CLIENT_RESUMED.fetch_add(1, Ordering::Relaxed) + 1;
                EEZO_KEMTLS_RESUME_RATIO
                    .with_label_values(&["client"])
                    .set(res as f64 / total as f64);
            } else {
                let res = CLIENT_RESUMED.load(Ordering::Relaxed);
                EEZO_KEMTLS_RESUME_RATIO
                    .with_label_values(&["client"])
                    .set(res as f64 / total as f64);
            }
        }
        _ => {
            let total = SERVER_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
            if resumed {
                EEZO_KEMTLS_RESUMED_SESSIONS_TOTAL
                    .with_label_values(&["server"])
                    .inc();
                let res = SERVER_RESUMED.fetch_add(1, Ordering::Relaxed) + 1;
                EEZO_KEMTLS_RESUME_RATIO
                    .with_label_values(&["server"])
                    .set(res as f64 / total as f64);
            } else {
                let res = SERVER_RESUMED.load(Ordering::Relaxed);
                EEZO_KEMTLS_RESUME_RATIO
                    .with_label_values(&["server"])
                    .set(res as f64 / total as f64);
            }
        }
    }
}

/// Increment a handshake failure with a coarse reason label.
#[inline]
pub fn kemtls_handshake_fail(role: &'static str, kind: &'static str) {
    let r = if role == "client" { "client" } else { "server" };
    let k = match kind {
        "kem" | "confirm" | "auth" | "io" => kind,
        _ => "other",
    };
    EEZO_KEMTLS_HANDSHAKE_FAIL_TOTAL
        .with_label_values(&[r, k])
        .inc();
}
// ── T37.2 helpers ───────────────────────────────────────────────────────────
#[inline]
pub fn tkt_decrypt_fail_inc() {
    TKT_DECRYPT_FAIL_TOTAL.inc();
}

#[inline]
pub fn replay_dropped_inc() {
    REPLAY_DROPPED_TOTAL.inc();
}

#[inline]
pub fn resume_true_inc(source: &str) {
    // FIX: Updated to match IntCounterVec definition
    RESUME_TRUE_TOTAL.with_label_values(&[source]).inc();
}

#[inline]
// FIX 4: This function signature was already correct, and will now compile
//        since RESUME_FALLBACK_TOTAL is defined.
pub fn kemtls_resume_fallback(reason: &str) {
    RESUME_FALLBACK_TOTAL.with_label_values(&[reason]).inc();
}

/// Optional: force metric registration at startup (if you prefer explicit init)
#[inline]
pub fn register_net_metrics() {
    let _ = &*EEZO_KEMTLS_HANDSHAKE_SECONDS;
    let _ = &*EEZO_KEMTLS_SESSIONS_TOTAL;
    let _ = &*EEZO_KEMTLS_RESUMED_SESSIONS_TOTAL;
    let _ = &*EEZO_KEMTLS_RESUME_RATIO;
    let _ = &*EEZO_KEMTLS_HANDSHAKE_FAIL_TOTAL;
    // T37.2 ticket/replay counters
    let _ = &*TKT_DECRYPT_FAIL_TOTAL;
    let _ = &*REPLAY_DROPPED_TOTAL;
    let _ = &*RESUME_TRUE_TOTAL;
    // FIX 5: This line will now work correctly.
    let _ = &*RESUME_FALLBACK_TOTAL;
}
