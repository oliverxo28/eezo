use std::net::SocketAddr;
use std::time::Instant;

use anyhow::Result;
use axum::{routing::get, Router};
use lazy_static::lazy_static;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use tokio::{net::TcpListener, task};

lazy_static! {
    /// Global Prometheus registry for the prover.
    pub static ref REGISTRY: Registry = Registry::new();

    /// Total number of proving jobs successfully completed.
    pub static ref JOBS_TOTAL: IntCounter = IntCounter::new(
        "eezo_prover_jobs_total",
        "Total number of proofs successfully generated",
    ).expect("metric can be created");

    /// Last height proven successfully.
    pub static ref LAST_HEIGHT: IntGauge = IntGauge::new(
        "eezo_prover_last_height",
        "Last checkpoint height for which a proof was written",
    ).expect("metric can be created");

    /// Total number of failures (node offline, PI error, proof error, write error).
    pub static ref FAILURES_TOTAL: IntCounter = IntCounter::new(
        "eezo_prover_failures_total",
        "Total number of failures encountered in prover loop",
    ).expect("metric can be created");

    /// Time (seconds) taken to generate the most recent proof.
    pub static ref LAST_DURATION_SECONDS: IntGauge = IntGauge::new(
        "eezo_prover_last_duration_seconds",
        "Duration of the most recent proof generation in seconds",
    ).expect("metric can be created");

    // ── T37.6: multi-prover orchestration metrics ──────────────────────────────
    /// Number of height locks successfully claimed by this prover.
    pub static ref CLAIMS_TOTAL: IntCounter = IntCounter::new(
        "eezo_prover_claims_total",
        "Total number of height claims (.lock acquired)"
    ).expect("metric can be created");

    /// Number of stale locks reclaimed (treat as claim timeouts).
    pub static ref CLAIM_TIMEOUTS_TOTAL: IntCounter = IntCounter::new(
        "eezo_prover_claim_timeouts_total",
        "Total number of stale .lock files reclaimed (claim timeouts)"
    ).expect("metric can be created");

    /// Number of gap directories healed (partials cleaned, locks reclaimed).
    pub static ref GAPS_HEALED_TOTAL: IntCounter = IntCounter::new(
        "eezo_prover_gaps_healed_total",
        "Total number of gap/heal events performed on startup or during scans"
    ).expect("metric can be created");

    // ── T37.8: lifecycle & GC metrics ─────────────────────────────────────────
    /// Total number of proof directories removed by GC (stale + partial).
    pub static ref GC_REMOVED_TOTAL: IntCounter = IntCounter::new(
        "eezo_prover_gc_removed_total",
        "Total number of proof directories removed by the prover GC"
    ).expect("metric can be created");

    /// Current configured number of rotations kept on disk.
    pub static ref RETAIN_ROTATIONS: IntGauge = IntGauge::new(
        "eezo_prover_retain_rotations",
        "Configured number of checkpoint rotations retained by the prover"
    ).expect("metric can be created");
	
}

/// Register all metrics with the global registry.
pub fn init_metrics() {
    REGISTRY
        .register(Box::new(JOBS_TOTAL.clone()))
        .expect("register jobs");
    REGISTRY
        .register(Box::new(LAST_HEIGHT.clone()))
        .expect("register last height");
    REGISTRY
        .register(Box::new(FAILURES_TOTAL.clone()))
        .expect("register failures");
    REGISTRY
        .register(Box::new(LAST_DURATION_SECONDS.clone()))
        .expect("register duration");
    // T37.6
    REGISTRY
        .register(Box::new(CLAIMS_TOTAL.clone()))
        .expect("register claims total");
    REGISTRY
        .register(Box::new(CLAIM_TIMEOUTS_TOTAL.clone()))
        .expect("register claim timeouts total");
    REGISTRY
        .register(Box::new(GAPS_HEALED_TOTAL.clone()))
        .expect("register gaps healed total");
    // T37.8
    REGISTRY
        .register(Box::new(GC_REMOVED_TOTAL.clone()))
        .expect("register gc removed total");
    REGISTRY
        .register(Box::new(RETAIN_ROTATIONS.clone()))
        .expect("register retain rotations");		
}

/// Start the Prometheus HTTP server (default 127.0.0.1:9099, overridable via EEZO_PROVER_METRICS_BIND).
///
/// Exports `/metrics`, compatible with Prometheus.
/// Should be called once from the binary on startup.
pub async fn spawn_metrics_server() -> Result<()> {
    init_metrics();
    // Reflect configured retention window (if set) in a gauge for observability.
    if let Ok(v) = std::env::var("EEZO_PROVER_RETAIN_ROTATIONS") {
        if let Ok(n) = v.parse::<i64>() {
            RETAIN_ROTATIONS.set(n);
        }
    }

    let app = Router::new().route(
        "/metrics",
        get(|| async {
            let encoder = TextEncoder::new();
            let metric_families = REGISTRY.gather();
            let mut buf = Vec::new();
            encoder.encode(&metric_families, &mut buf).unwrap();
            String::from_utf8_lossy(&buf).to_string()
        }),
    );

    // T37.6: allow multiple provers by making the bind configurable
    let bind = std::env::var("EEZO_PROVER_METRICS_BIND")
        .unwrap_or_else(|_| "127.0.0.1:9099".into());
    let addr: SocketAddr = bind.parse().expect("invalid EEZO_PROVER_METRICS_BIND (use host:port)");
    let app = app.into_make_service();
    task::spawn(async move {
        println!("eezo-prover metrics server running at {}", addr);
        let listener = TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    Ok(())
}

/// Utility to measure job duration:
pub struct JobTimer {
    start: Instant,
}

impl JobTimer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Update LAST_DURATION_SECONDS with elapsed seconds.
    pub fn finish(self) {
        let secs = self.start.elapsed().as_secs_f64();
        LAST_DURATION_SECONDS.set(secs as i64);
    }
}
