//crates/node/src/metrics.rs
use once_cell::sync::Lazy;
use prometheus::{
    register_histogram, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
};

// --- Remove AtomicU64 imports if they are now unused ---
// use std::sync::atomic::{AtomicU64, Ordering};
// T37.1 — bring in KEMTLS resumption metrics from eezo-net
#[cfg(feature = "metrics")]
use eezo_net::register_net_metrics as register_kemtls_net_metrics;


// --- route/status counter for state-sync HTTP (used by http/state.rs) ---
#[cfg(feature = "metrics")]
pub static HTTP_REQS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_statesync_http_requests_total",
        "Total state-sync HTTP requests (labeled by route and status)",
        &["route", "status"]
    )
    .expect("register eezo_statesync_http_requests_total")
});

#[inline]
pub fn http_inc(route: &str, status: u16) {
    #[cfg(not(feature = "metrics"))]
    { let _ = (route, status); }
    #[cfg(feature = "metrics")]
    {
        HTTP_REQS
            .with_label_values(&[route, &status.to_string()])
            .inc();
    }
}

// ===================== T29.9: State-sync security metrics =====================
// TLS client build/handshake failures (including bad CA, builder errors)
#[cfg(feature = "metrics")]
pub static STATE_SYNC_TLS_HANDSHAKE_FAIL_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_tls_handshake_fail_total",
        "Number of TLS client build/handshake failures during state-sync"
    )
    .expect("metric registered")
});

// TLS client config/builder failures (bad PEM, etc)
#[cfg(feature = "metrics")]
pub static STATE_SYNC_TLS_CONFIG_FAIL_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_tls_config_fail_total",
        "Number of TLS client config/builder failures during state-sync"
    )
    .expect("metric registered")
});

// mTLS client-auth failures (bad/missing client cert or key)
#[cfg(feature = "metrics")]
pub static STATE_SYNC_MTLS_FAIL_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_mtls_fail_total",
        "Number of mTLS client-auth failures during state-sync"
    )
    .expect("metric registered")
});

// Anchor signature verification failures, labeled by reason:
//   missing | unsupported_algo | bad_len | bad_sig
#[cfg(feature = "metrics")]
pub static STATE_SYNC_ANCHOR_VERIFY_FAIL_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_state_sync_anchor_verify_fail_total",
        "Anchor signature verification failures (labeled by reason)",
        &["reason"]
    )
    .expect("metric registered")
});

// Count of accepted signed anchors (should increase over time)
#[cfg(feature = "metrics")]
pub static STATE_SYNC_ANCHOR_SIGNED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_anchor_signed_total",
        "Number of signed anchors accepted by state-sync"
    )
    .expect("metric registered")
});

// Count of accepted unsigned anchors (legacy interop; should trend toward 0)
#[cfg(feature = "metrics")]
pub static STATE_SYNC_ANCHOR_UNSIGNED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_anchor_unsigned_total",
        "Number of unsigned anchors accepted by state-sync (legacy)"
    )
    .expect("metric registered")
});

// --- Existing metrics ---
#[cfg(feature = "metrics")]
pub static EEZO_MEMPOOL_LEN: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("eezo_mempool_len", "Current mempool length").unwrap()
});

#[cfg(feature = "metrics")]
pub static EEZO_MEMPOOL_BYTES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("eezo_mempool_bytes_gauge", "Current bytes in mempool").unwrap()
});

// NOTE: eezo_txs_included_total and eezo_block_tx_count metrics are defined
// in the ledger crate (crates/ledger/src/metrics.rs) and automatically updated
// via observe_block_proposed() when blocks are assembled.

// T51.4.d – labeled transaction rejection metrics
pub static EEZO_TX_REJECTED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_tx_rejected_total",
        "Txs rejected by proposer (labeled by reason)",
        &["reason"]
    )
    .expect("metric registered")
});

#[inline]
pub fn tx_rejected_inc(reason: &str) {
    EEZO_TX_REJECTED_TOTAL
        .with_label_values(&[reason])
        .inc();
}

// T32 schema anchors (lower-case names)
pub static EEZO_BLOCK_E2E_LATENCY_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    // Use a tolerant registration pattern: if registration fails (e.g., already registered),
    // create an unregistered fallback HistogramVec and emit a warning instead of panicking.
    register_histogram_vec!(
        "eezo_block_e2e_latency_seconds",
        "End-to-end block latency segmented by stage",
        &["stage"] // e.g., "assemble" | "validate" | "commit"
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "warning: failed to register eezo_block_e2e_latency_seconds: {} (using unregistered fallback histogram)",
            e
        );
        let opts = HistogramOpts::new(
            "eezo_block_e2e_latency_seconds_fallback",
            "unregistered fallback histogram for block e2e latency",
        );
        HistogramVec::new(opts, &["stage"]).expect("fallback histogram constructed")
    })
});

// Keep the old simple counter for backward compatibility during transition
pub static EEZO_TX_REJECTED_SIMPLE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_tx_rejected_simple_total",
        "Rejected transactions (simple counter, deprecated for labeled version)"
    )
    .unwrap()
});

pub static EEZO_BLOCK_HEIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("eezo_block_height", "Current committed block height").unwrap()
});

pub static EEZO_NODE_PEERS_TOTAL: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_node_peers_total",
        "Total peers in configured peer set"
    )
    .unwrap()
});

pub static EEZO_NODE_PEERS_READY: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_node_peers_ready",
        "Number of peers currently reporting /ready = 200"
    )
    .unwrap()
});

pub static EEZO_NODE_CLUSTER_QUORUM_OK: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_node_cluster_quorum_ok",
        "1 when peers_ready/peers_total >= 2/3, else 0"
    )
    .unwrap()
});

pub static EEZO_NODE_QUORUM_DEGRADE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_node_quorum_degrade_total",
        "Times cluster quorum loss flipped local readiness"
    )
    .unwrap()
});

pub static EEZO_NODE_READY: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("eezo_node_ready", "1 when node is ready, 0 when degraded").unwrap()
});

// --- T24.9: Per-peer SLO metrics ---

// Latency histogram (ms) per peer (label is a short hash, not the full URL)
pub static EEZO_NODE_PEER_PING_MS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "eezo_node_peer_ping_ms",
        "Ping latency to peers (ms)",
        &["peer"]
    )
    .unwrap()
});

// Failed pings per peer
pub static EEZO_NODE_PEER_PING_FAIL_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_node_peer_ping_fail_total",
        "Failed pings to peers",
        &["peer"]
    )
    .unwrap()
});

// --- State sync metrics ---
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(feature = "state-sync")]
pub static STATE_SYNC_SNAPSHOT_BYTES_TOTAL: Lazy<prometheus::IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_snapshot_bytes_total",
        "Total bytes served/consumed for snapshot chunks"
    )
    .unwrap()
});

#[cfg(feature = "state-sync")]
pub static STATE_SYNC_DELTA_BYTES_TOTAL: Lazy<prometheus::IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_delta_bytes_total",
        "Total bytes served/consumed for delta batches"
    )
    .unwrap()
});

#[cfg(feature = "state-sync")]
pub static STATE_SYNC_CHUNKS_TOTAL: Lazy<prometheus::IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_state_sync_chunks_total",
        "Number of state-sync chunks processed",
        &["kind"] // "snapshot" | "delta"
    )
    .unwrap()
});

#[cfg(feature = "state-sync")]
pub static STATE_SYNC_SNAPSHOTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_state_sync_snapshots_total",
        "Total number of snapshot fetches (by type)",
        &["kind"]
    )
    .unwrap()
});

#[cfg(feature = "state-sync")]
#[allow(dead_code)]
pub static STATE_SYNC_DELTAS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_state_sync_deltas_total",
        "Total number of delta fetches (by type)",
        &["kind"]
    )
    .unwrap()
});

#[allow(dead_code)]
#[cfg(feature = "state-sync")]
pub static STATE_SYNC_APPLY_MS: Lazy<prometheus::Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_state_sync_apply_ms",
        "Time to apply a state-sync chunk (ms)"
    )
    .unwrap()
});

#[cfg(feature = "state-sync")]
pub static STATE_SYNC_HTTP_ERR_4XX: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_http_4xx_total",
        "4xx responses from state-sync HTTP"
    )
    .unwrap()
});

#[cfg(feature = "state-sync")]
pub static STATE_SYNC_HTTP_ERR_5XX: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_http_5xx_total",
        "5xx responses from state-sync HTTP"
    )
    .unwrap()
});

// ───────────────────────────── T42.3: State-sync progress metrics ───────────
 // These live under `metrics` so operators can always see high-level state-sync
 // progress, even if detailed `state-sync`-specific metrics are disabled.
#[cfg(feature = "metrics")]
pub static EEZO_STATE_SYNC_LATEST_HEIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_state_sync_latest_height",
        "Gauge of the highest state-sync height applied by this node"
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "warning: failed to register eezo_state_sync_latest_height: {} (using unregistered fallback gauge)",
            e
        );
        IntGauge::new(
            "eezo_state_sync_latest_height_fallback",
            "unregistered fallback gauge for state-sync latest height"
        )
        .expect("fallback gauge constructed")
    })
});


#[cfg(feature = "metrics")]
pub static EEZO_STATE_SYNC_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_total",
        "Total successful state-sync applications (snapshot + delta)"
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "warning: failed to register eezo_state_sync_total: {} (using unregistered fallback counter)",
            e
        );
        IntCounter::new(
            "eezo_state_sync_total_fallback",
            "unregistered fallback counter for state-sync total"
        )
        .expect("fallback counter constructed")
    })
});


#[cfg(feature = "metrics")]
pub static EEZO_STATE_SYNC_RETRY_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_retry_total",
        "Total state-sync retries (any HTTP/transport-level retry)"
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "warning: failed to register eezo_state_sync_retry_total: {} (using unregistered fallback counter)",
            e
        );
        IntCounter::new(
            "eezo_state_sync_retry_total_fallback",
            "unregistered fallback counter for state-sync retries"
        )
        .expect("fallback counter constructed")
    })
});


#[cfg(feature = "metrics")]
pub static EEZO_STATE_SYNC_ERRORS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_errors_total",
        "Total state-sync apply failures (after retries exhausted)"
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "warning: failed to register eezo_state_sync_errors_total: {} (using unregistered fallback counter)",
            e
        );
        IntCounter::new(
            "eezo_state_sync_errors_total_fallback",
            "unregistered fallback counter for state-sync errors"
        )
        .expect("fallback counter constructed")
    })
});


/// Helper: set latest state-sync height *monotonically* (never move backwards).
#[inline]
pub fn state_sync_latest_height_set(h: u64) {
    #[cfg(feature = "metrics")]
    {
        let cur = EEZO_STATE_SYNC_LATEST_HEIGHT.get();
        let next = (h as i64).saturating_abs();
        if next > cur {
            EEZO_STATE_SYNC_LATEST_HEIGHT.set(next);
        }
    }
    #[cfg(not(feature = "metrics"))]
    { let _ = h; }
}

/// Helper: increment total successful state-sync applications.
#[inline]
pub fn state_sync_total_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_STATE_SYNC_TOTAL.inc();
    }
}

/// Helper: increment retry counter for state-sync operations.
#[inline]
pub fn state_sync_retry_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_STATE_SYNC_RETRY_TOTAL.inc();
    }
}

/// Helper: increment error counter for failed state-sync operations.
#[inline]
#[allow(dead_code)]
pub fn state_sync_error_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_STATE_SYNC_ERRORS_TOTAL.inc();
    }
}

// --- T29.8: State-sync client hardening metrics ---
#[cfg(feature = "metrics")]
pub static SS_RETRIES_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_state_sync_retries_total", "Total HTTP retries during state-sync").expect("metric")
});

#[cfg(feature = "metrics")]
pub static SS_FAILURES_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_state_sync_failures_total", "Total state-sync bootstrap failures").expect("metric")
});

#[cfg(feature = "metrics")]
pub static SS_PAGES_APPLIED_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_state_sync_pages_applied_total", "Snapshot pages applied").expect("metric")
});

#[cfg(feature = "metrics")]
pub static SS_DELTA_BATCHES_APPLIED_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_state_sync_delta_batches_applied_total", "Delta batches applied").expect("metric")
});

#[cfg(feature = "metrics")]
#[allow(dead_code)]
pub static STATE_SYNC_DELTA_V2_SSZ_SERVE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_delta_v2_ssz_serve_total",
        "Number of SSZ2D delta manifests served"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
#[allow(dead_code)]
pub static STATE_SYNC_DELTA_V2_SSZ_NOTFOUND_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_delta_v2_ssz_notfound_total",
        "Number of SSZ2D delta requests that returned 404"
    )
    .expect("metric registered")
});

// --- T33 Bridge Alpha metrics ---
#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_MINT_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
	register_int_counter_vec!(
	    "eezo_bridge_mint_total",
	    "Bridge mint requests (labeled by result)",
	&["result"] // "ok" | "replay" | "bad_sig"
	)
	.expect("metric registered")
});

#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_OUTBOX_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
	register_int_counter!(
	    "eezo_bridge_outbox_total",
		"Outbox events recorded (withdrawal skeletons)"
	)
	.expect("metric registered")
});


 // Eagerly register ledger consensus metrics so they appear in /metrics even before use.
#[cfg(all(feature = "metrics", feature = "pq44-runtime"))]
pub fn register_ledger_consensus_metrics() {
    // Deref'ing Lazy<T> forces initialization & registration.
    let _ = &*eezo_ledger::metrics::CONSENSUS_PROPOSALS_TOTAL;
    let _ = &*eezo_ledger::metrics::CONSENSUS_VOTES_PREPARE;
    let _ = &*eezo_ledger::metrics::CONSENSUS_VOTES_PRECOMMIT;
    let _ = &*eezo_ledger::metrics::CONSENSUS_VOTES_COMMIT;
    let _ = &*eezo_ledger::metrics::CONSENSUS_QC_FORMED_TOTAL;
    let _ = &*eezo_ledger::metrics::CONSENSUS_VIEW;
    let _ = &*eezo_ledger::metrics::CONSENSUS_COMMIT_HEIGHT;
	// T32 metrics (ensure presence on /metrics even before first observation)
	eezo_ledger::metrics::register_t32_metrics();
	// T51 metrics: force initialization of mempool metrics
	// (tx inclusion metrics are in ledger and initialized via register_t32_metrics)
	#[cfg(feature = "metrics")]
	{
		let _ = &*EEZO_MEMPOOL_LEN;
		let _ = &*EEZO_MEMPOOL_BYTES;
	}
}
 // Eagerly register T33 Bridge metrics so they appear on /metrics immediately.
#[cfg(feature = "metrics")]
pub fn register_t33_bridge_metrics() {
    let _ = &*EEZO_BRIDGE_MINT_TOTAL;
    let _ = &*EEZO_BRIDGE_OUTBOX_TOTAL;
}
 // ───────────────────────────── T36.6: Bridge index & serve metrics ──────────
#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_CHECKPOINTS_EMITTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_bridge_checkpoints_emitted_total",
        "Number of checkpoints emitted to disk by the node"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_HEADERS_SERVED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_bridge_headers_served_total",
        "Bridge headers served over HTTP (labeled by route)",
        &["route"] // "latest" | "height" | "index"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_INDEX_QUERIES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_bridge_index_queries_total",
        "Total /bridge/index queries (any status)"
    )
    .expect("metric registered")
});

// T36.8: /bridge/branch & /bridge/prove queries
#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_BRANCH_QUERIES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_bridge_branch_queries_total",
        "Total /bridge/branch queries (any status)"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_PROVE_QUERIES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_bridge_prove_queries_total",
        "Total /bridge/prove queries (any status)"
    )
    .expect("metric registered")
});

// T36.7: /bridge/summary queries
#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_SUMMARY_QUERIES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_bridge_summary_queries_total",
        "Total /bridge/summary queries (any status)"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_LATEST_HEIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_bridge_latest_height",
        "Gauge of the highest checkpoint height known/emitted"
    )
    .expect("metric registered")
});

// ───────────────────────────── T37: BridgeOps gauges ─────────────────────────
#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_LAST_SERVED_HEIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_bridge_last_served_height",
        "Gauge of the highest checkpoint height the node has served over HTTP"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
pub static EEZO_BRIDGE_NODE_LAG: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_bridge_node_lag",
        "Computed lag: eezo_bridge_latest_height - eezo_bridge_last_served_height (>= 0)"
    )
    .expect("metric registered")
});

/// Eagerly register T36.6 bridge metrics so they appear on /metrics immediately.
#[cfg(feature = "metrics")]
pub fn register_t36_bridge_metrics() {
    let _ = &*EEZO_BRIDGE_CHECKPOINTS_EMITTED_TOTAL;
    let _ = &*EEZO_BRIDGE_HEADERS_SERVED_TOTAL;
    let _ = &*EEZO_BRIDGE_INDEX_QUERIES_TOTAL;
	let _ = &*EEZO_BRIDGE_SUMMARY_QUERIES_TOTAL; // T36.7
	let _ = &*EEZO_BRIDGE_BRANCH_QUERIES_TOTAL;  // T36.8
	let _ = &*EEZO_BRIDGE_PROVE_QUERIES_TOTAL;   // T36.8
    let _ = &*EEZO_BRIDGE_LATEST_HEIGHT;
    // T37: eager-register BridgeOps gauges
    let _ = &*EEZO_BRIDGE_LAST_SERVED_HEIGHT;
    let _ = &*EEZO_BRIDGE_NODE_LAG;
}
/// ─────────────────────────── T37.1: KEMTLS metrics hook ───────────────────────────
/// Eagerly register **net/KEMTLS** metrics (handshake seconds, resume ratio, etc.)
/// so they appear on `/metrics` even before the first connection.
#[cfg(feature = "metrics")]
pub fn register_t37_kemtls_metrics() {
    // delegate to eezo-net's registrar (idempotent)
    register_kemtls_net_metrics();
}
 // ─────────────────────────── T40.1: Shadow sig metrics registrar ───────────
 /// Eagerly register the crypto crate's shadow-verify counters so they are
 /// visible on `/metrics` even before the first shadow verification attempt.
#[cfg(feature = "metrics")]
pub fn register_t40_shadow_sig_metrics() {
    // idempotent touch of Lazy statics in eezo-crypto
    eezo_crypto::metrics::register_t40_shadow_metrics();
}
 // ─────────────────────────── T40.2: Cutover metrics registrar ───────────
 /// Eagerly register the cutover-enforcement counters so they appear on
 /// `/metrics` at boot. Delegates to the same crypto helper, which also
 /// materializes the T40.2 counters.
#[cfg(feature = "metrics")]
pub fn register_t40_cutover_metrics() {
    eezo_crypto::metrics::register_t40_shadow_metrics();
}
 // ─────────────────────────── T41.3: QC sidecar v2 metrics ───────────
#[cfg(feature = "metrics")]
pub static EEZO_QC_SIDECAR_V2_EMITTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_emitted_total",
        "QC-sidecar v2 objects attached/emitted alongside checkpoints"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
pub static EEZO_QC_SIDECAR_V2_VERIFY_OK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_verify_ok_total",
        "QC-sidecar v2 format checks passed (reader-only)"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
pub static EEZO_QC_SIDECAR_V2_VERIFY_ERR_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_verify_err_total",
        "QC-sidecar v2 format checks failed (reader-only)"
    )
    .expect("metric registered")
});
 // ── T41.4: strict mode outcomes ─────────────────────────────────────────────
#[cfg(feature = "metrics")]
pub static EEZO_QC_SIDECAR_V2_ENFORCE_OK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_enforce_ok_total",
        "QC-sidecar v2 enforcement passed at cutover+1"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
pub static EEZO_QC_SIDECAR_V2_ENFORCE_FAIL_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_enforce_fail_total",
        "QC-sidecar v2 enforcement failed at cutover+1 (missing/malformed)"
    )
    .expect("metric registered")
});
 /// Eagerly register T41.3 QC sidecar metrics so they show on /metrics immediately.
#[cfg(feature = "metrics")]
#[allow(dead_code)]
pub fn register_t41_qc_sidecar_metrics() {
    let _ = &*EEZO_QC_SIDECAR_V2_EMITTED_TOTAL;
    let _ = &*EEZO_QC_SIDECAR_V2_VERIFY_OK_TOTAL;
    let _ = &*EEZO_QC_SIDECAR_V2_VERIFY_ERR_TOTAL;
    let _ = &*EEZO_QC_SIDECAR_V2_ENFORCE_OK_TOTAL;   // T41.4
    let _ = &*EEZO_QC_SIDECAR_V2_ENFORCE_FAIL_TOTAL; // T41.4	
}

#[inline]
pub fn qc_sidecar_emitted_inc() {
    #[cfg(feature = "metrics")]
    { EEZO_QC_SIDECAR_V2_EMITTED_TOTAL.inc(); }
}

#[inline]
pub fn qc_sidecar_verify_ok_inc() {
    #[cfg(feature = "metrics")]
    { EEZO_QC_SIDECAR_V2_VERIFY_OK_TOTAL.inc(); }
}

#[inline]
pub fn qc_sidecar_verify_err_inc() {
    #[cfg(feature = "metrics")]
    { EEZO_QC_SIDECAR_V2_VERIFY_ERR_TOTAL.inc(); }
}

#[inline]
pub fn qc_sidecar_enforce_ok_inc() {
    #[cfg(feature = "metrics")]
    { EEZO_QC_SIDECAR_V2_ENFORCE_OK_TOTAL.inc(); }
}

#[inline]
pub fn qc_sidecar_enforce_fail_inc() {
    #[cfg(feature = "metrics")]
    { EEZO_QC_SIDECAR_V2_ENFORCE_FAIL_TOTAL.inc(); }
}

/// Helper: increment emitted counter when a checkpoint is written.
#[inline]
pub fn bridge_emitted_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_BRIDGE_CHECKPOINTS_EMITTED_TOTAL.inc();
    }
}

/// Helper: increment served counter with a specific route label.
#[inline]
pub fn bridge_served_inc(route: &str) {
    #[cfg(not(feature = "metrics"))]
    { let _ = route; }
    #[cfg(feature = "metrics")]
    {
        EEZO_BRIDGE_HEADERS_SERVED_TOTAL
            .with_label_values(&[route])
            .inc();
    }
}

/// Helper: set last-served gauge *monotonically* (T37).
#[inline]
pub fn bridge_last_served_set(h: u64) {
    #[cfg(not(feature = "metrics"))]
    { let _ = h; }
    #[cfg(feature = "metrics")]
    {
        let cur = EEZO_BRIDGE_LAST_SERVED_HEIGHT.get();
        let next = (h as i64).saturating_abs();
        if next > cur {
            EEZO_BRIDGE_LAST_SERVED_HEIGHT.set(next);
        }
        // keep node lag in sync whenever last-served moves
        bridge_update_node_lag();
    }
}

/// Helper: increment /bridge/index query counter.
#[inline]
pub fn bridge_index_query_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_BRIDGE_INDEX_QUERIES_TOTAL.inc();
    }
}

/// Helper: increment /bridge/branch query counter.
#[inline]
pub fn bridge_branch_query_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_BRIDGE_BRANCH_QUERIES_TOTAL.inc();
    }
}

/// Helper: increment /bridge/prove query counter.
#[inline]
pub fn bridge_prove_query_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_BRIDGE_PROVE_QUERIES_TOTAL.inc();
    }
}

/// Helper: increment /bridge/summary query counter.
#[inline]
pub fn bridge_summary_query_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_BRIDGE_SUMMARY_QUERIES_TOTAL.inc();
    }
}

/// Helper: set latest checkpoint height gauge *monotonically* (Teacher's simpler version).
#[inline]
pub fn bridge_latest_height_set(h: u64) {
    #[cfg(not(feature = "metrics"))]
    { let _ = h; } // Avoid unused warning
    #[cfg(feature = "metrics")]
    {
        let cur = EEZO_BRIDGE_LATEST_HEIGHT.get();
        // Cast u64 height safely to i64 for comparison and setting
        // Use try_into().unwrap_or(i64::MAX) or saturating_abs() as teacher suggested.
        // Saturating_abs is simpler if heights are never negative (which they shouldn't be).
        let next = (h as i64).saturating_abs();
        if next > cur {
            EEZO_BRIDGE_LATEST_HEIGHT.set(next);
			// keep node lag in sync whenever latest-emitted moves
			bridge_update_node_lag();
        }
        // If next <= cur, we do nothing.
    }
}

/// Helper (T36.8): set latest checkpoint height gauge (name used by bridge.rs).
/// This now correctly calls the monotonic version.
#[inline]
pub fn bridge_latest_set(height: u64) {
    // Call the monotonic version directly
    bridge_latest_height_set(height);
}

/// Helper (T37): recompute and set node lag = latest_emitted - last_served (>= 0).
#[inline]
pub fn bridge_update_node_lag() {
    #[cfg(feature = "metrics")]
    {
        let latest = EEZO_BRIDGE_LATEST_HEIGHT.get();
        let served = EEZO_BRIDGE_LAST_SERVED_HEIGHT.get();
        let lag = (latest - served).max(0);
        EEZO_BRIDGE_NODE_LAG.set(lag);
    }
}


// ───────────────────────────── T34: Suite Rotation metrics ───────────────────
#[cfg(feature = "metrics")]
pub static EEZO_SUITE_ACCEPT_WINDOW_OPEN: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_suite_accept_window_open",
        "1 when dual-accept window is open (suite rotation), else 0"
    )
    .unwrap()
});

#[cfg(feature = "metrics")]
pub static EEZO_SUITE_ROTATION_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_suite_rotation_total",
        "Number of suite rotation events applied (policy flips)"
    )
    .unwrap()
});

/// Eagerly register T34 metrics so they appear on /metrics immediately.
#[cfg(feature = "metrics")]
pub fn register_t34_rotation_metrics() {
    let _ = &*EEZO_SUITE_ACCEPT_WINDOW_OPEN;
    let _ = &*EEZO_SUITE_ROTATION_TOTAL;
}

/// Helper to set the dual-accept window gauge (0/1).
#[inline]
#[allow(dead_code)]
pub fn suite_window_set(open: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_SUITE_ACCEPT_WINDOW_OPEN.set(if open { 1 } else { 0 });
    }
    #[cfg(not(feature = "metrics"))]
    { let _ = open; }
}

/// Helper to record a rotation event (policy flip).
#[inline]
#[allow(dead_code)]
pub fn suite_rotation_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_SUITE_ROTATION_TOTAL.inc();
    }
}

// -----------------------------------------------------------------------------
// T51.5a — TPS / block builder metrics
// -----------------------------------------------------------------------------

// NOTE: EEZO_BLOCK_TX_COUNT is defined in the ledger crate and updated automatically

/// Counter: blocks that reached the configured EEZO_BLOCK_MAX_TX (i.e. fully packed).
pub static EEZO_BLOCK_FULL_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_block_full_total",
        "Total number of blocks that reached EEZO_BLOCK_MAX_TX transactions"
    )
    .unwrap()
});

/// Counter: blocks that had at least 1 tx but fewer than EEZO_BLOCK_MAX_TX.
pub static EEZO_BLOCK_UNDERFILLED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_block_underfilled_total",
        "Total number of non-empty blocks built with fewer than EEZO_BLOCK_MAX_TX transactions"
    )
    .unwrap()
});

// -----------------------------------------------------------------------------
// T52.1 — executor timing metrics
// -----------------------------------------------------------------------------
#[cfg(feature = "metrics")]
pub static EEZO_EXECUTOR_BLOCK_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "eezo_executor_block_seconds",
        "Time spent executing blocks (seconds, executor hot path)",
        &["kind"] // currently always "block"
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "warning: failed to register eezo_executor_block_seconds: {} (using unregistered fallback histogram)",
            e
        );
        let opts = HistogramOpts::new(
            "eezo_executor_block_seconds_fallback",
            "unregistered fallback histogram for executor block time (seconds)",
        );
        HistogramVec::new(opts, &["kind"]).expect("fallback histogram constructed")
    })
});

#[cfg(feature = "metrics")]
pub static EEZO_EXECUTOR_TX_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "eezo_executor_tx_seconds",
        "Execution time per transaction (seconds, inferred from blocks)",
        &["kind"] // currently always "tx"
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "warning: failed to register eezo_executor_tx_seconds: {} (using unregistered fallback histogram)",
            e
        );
        let opts = HistogramOpts::new(
            "eezo_executor_tx_seconds_fallback",
            "unregistered fallback histogram for executor per-tx time (seconds)",
        );
        HistogramVec::new(opts, &["kind"]).expect("fallback histogram constructed")
    })
});

#[cfg(feature = "metrics")]
pub static EEZO_EXECUTOR_TPS_INFERRED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_executor_tps_inferred",
        "Instantaneous TPS estimated from executor timings (tx_count / block_time)"
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "warning: failed to register eezo_executor_tps_inferred: {} (using unregistered fallback gauge)",
            e
        );
        IntGauge::new(
            "eezo_executor_tps_inferred_fallback",
            "unregistered fallback gauge for executor TPS"
        )
        .expect("fallback gauge constructed")
    })
});

// -----------------------------------------------------------------------------
// T54 — Parallel executor metrics (non-colliding names)
// -----------------------------------------------------------------------------
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_PARALLEL_WAVES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_parallel_waves_total",
        "Total number of parallel executor waves per block"
    )
    .unwrap()
});

#[cfg(feature = "metrics")]
pub static EEZO_EXEC_PARALLEL_WAVE_LEN: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_parallel_wave_len",
        "Histogram of wave sizes (txs executed in each parallel wave)"
    )
    .unwrap()
});

#[cfg(feature = "metrics")]
pub static EEZO_EXEC_PARALLEL_APPLY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_parallel_apply_seconds",
        "Time spent executing a single wave in parallel executor (seconds)"
    )
    .unwrap()
});

// -----------------------------------------------------------------------------
// T54.6 — Prefetch + small-wave fusion metrics
// -----------------------------------------------------------------------------
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_PREFETCH_MS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_prefetch_ms",
        "Milliseconds spent prefetching access-lists / metadata per block"
    )
    .unwrap()
});

#[cfg(feature = "metrics")]
pub static EEZO_EXEC_WAVE_FUSE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_wave_fuse_total",
        "Number of small waves fused into previous waves (prefix-only)"
    )
    .unwrap()
});

#[cfg(feature = "metrics")]
pub static EEZO_EXEC_WAVE_FUSED_LEN: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_wave_fused_len",
        "Histogram of tx count of waves that were fused"
    )
    .unwrap()
});
// -----------------------------------------------------------------------------
// T51.5a — sigpool metrics
// -----------------------------------------------------------------------------

pub static EEZO_SIGPOOL_QUEUED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_sigpool_queued_total",
        "Total number of txs submitted to the sigpool"
    )
    .unwrap()
});

pub static EEZO_SIGPOOL_VERIFIED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_sigpool_verified_total",
        "Total number of txs whose signatures verified in sigpool"
    )
    .unwrap()
});

pub static EEZO_SIGPOOL_FAILED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_sigpool_failed_total",
        "Total number of txs whose signatures failed in sigpool"
    )
    .unwrap()
});

pub static EEZO_SIGPOOL_ACTIVE_THREADS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_sigpool_active_threads",
        "Number of active sigpool worker threads"
    )
    .unwrap()
});

// -----------------------------------------------------------------------------
// T55.3 — DAG runner metrics
// -----------------------------------------------------------------------------
/// Gauge: DAG runner state
/// 0 = absent (no DagRunnerHandle attached)
/// 1 = disabled (stop flag set / runner stopping)
/// 2 = running (active DAG loop)
#[cfg(feature = "metrics")]
pub static EEZO_DAG_RUNNER_STATE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_runner_state",
        "DAG runner state: 0=absent,1=disabled,2=running"
    )
    .unwrap()
});

/// Counter: how many times we've spawned a DAG runner in this process.
/// This stays monotonic and helps detect restart loops.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_RUNNER_RESTARTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_runner_restarts_total",
        "Total DAG runner spawn() invocations in this process"
    )
    .unwrap()
});

// -----------------------------------------------------------------------------
// T56.2 — DAG structure metrics
// -----------------------------------------------------------------------------
/// Total number of DAG vertices ever created in this process.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_VERTICES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_vertices_total",
        "Total DAG vertices ever created in this process"
    )
    .unwrap()
});

/// Current number of DAG vertices stored in memory.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_VERTICES_CURRENT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_vertices_current",
        "Current number of DAG vertices stored in memory"
    )
    .unwrap()
});

/// Current number of DAG tips (vertices with no children).
#[cfg(feature = "metrics")]
pub static EEZO_DAG_TIPS_CURRENT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_tips_current",
        "Current number of DAG tips (vertices with no children)"
    )
    .unwrap()
});
// -----------------------------------------------------------------------------
// T56.3 — DAG round/height observability
// -----------------------------------------------------------------------------
/// Gauge: maximum DAG round observed so far (local to this node).
#[cfg(feature = "metrics")]
pub static EEZO_DAG_ROUND_MAX: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_round_max",
        "Maximum DAG round observed in this process (local, monotonic)"
    )
    .unwrap()
});

/// Gauge: maximum DAG height observed so far (local ledger height proxy).
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HEIGHT_MAX: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_height_max",
        "Maximum DAG height observed in this process (local, monotonic)"
    )
    .unwrap()
});
// -----------------------------------------------------------------------------
// T65.2 — DAG template & compare metrics
// -----------------------------------------------------------------------------
/// Gauge: number of txs in the DAG shadow block template that would succeed
/// under dry-run execution.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_TEMPLATE_TXS_OK: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_template_txs_ok",
        "Number of txs that would succeed in the DAG shadow block template"
    )
    .unwrap()
});

/// Gauge: number of txs in the DAG shadow block template that would fail
/// under dry-run execution.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_TEMPLATE_TXS_FAILED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_template_txs_failed",
        "Number of txs that would fail in the DAG shadow block template"
    )
    .unwrap()
});

/// Gauge: 1 if the current DAG shadow template would apply cleanly
/// (no failed txs), else 0.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_TEMPLATE_WOULD_APPLY_CLEANLY: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_template_would_apply_cleanly",
        "1 if DAG shadow block template would apply cleanly, else 0"
    )
    .unwrap()
});

/// Gauge: overlap count between DAG candidate tx hashes and last committed block.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_COMPARE_OVERLAP: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_compare_overlap",
        "Number of tx hashes shared by DAG candidate and latest committed block"
    )
    .unwrap()
});

/// Gauge: tx hashes only present in DAG candidate, not in last committed block.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_COMPARE_ONLY_IN_DAG: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_compare_only_in_dag",
        "Number of tx hashes only in DAG candidate (not in last committed block)"
    )
    .unwrap()
});

/// Gauge: tx hashes only present in latest committed block, not in DAG candidate.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_COMPARE_ONLY_IN_BLOCK: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_compare_only_in_block",
        "Number of tx hashes only in latest committed block (not in DAG candidate)"
    )
    .unwrap()
});

/// Helper: update DAG template metrics from optional template fields.
#[inline]
pub fn dag_template_metrics_set(
    txs_ok: Option<usize>,
    txs_failed: Option<usize>,
    would_apply_cleanly: Option<bool>,
) {
    #[cfg(feature = "metrics")]
    {
        let ok = txs_ok.unwrap_or(0) as i64;
        let failed = txs_failed.unwrap_or(0) as i64;
        let clean_flag = match would_apply_cleanly {
            Some(true) => 1,
            Some(false) => 0,
            None => 0,
        };

        EEZO_DAG_TEMPLATE_TXS_OK.set(ok);
        EEZO_DAG_TEMPLATE_TXS_FAILED.set(failed);
        EEZO_DAG_TEMPLATE_WOULD_APPLY_CLEANLY.set(clean_flag);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (txs_ok, txs_failed, would_apply_cleanly);
    }
}

/// Helper: update DAG candidate vs block compare metrics.
#[inline]
pub fn dag_compare_metrics_set(
    overlap: usize,
    only_in_dag: usize,
    only_in_block: usize,
) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_COMPARE_OVERLAP.set(overlap as i64);
        EEZO_DAG_COMPARE_ONLY_IN_DAG.set(only_in_dag as i64);
        EEZO_DAG_COMPARE_ONLY_IN_BLOCK.set(only_in_block as i64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (overlap, only_in_dag, only_in_block);
    }
}

// -----------------------------------------------------------------------------
// T68.1 — DAG block tx source metrics
// -----------------------------------------------------------------------------
/// Counter: blocks built using DAG candidate as tx source.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_BLOCK_SOURCE_USED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_block_source_used_total",
        "Number of blocks built using DAG candidate as tx source"
    )
    .unwrap()
});

/// Counter: blocks that fell back to mempool when DAG source was selected.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_BLOCK_SOURCE_FALLBACK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_block_source_fallback_total",
        "Number of blocks that fell back to mempool when DAG source was selected"
    )
    .unwrap()
});

/// Helper: increment DAG block source used counter.
#[inline]
pub fn dag_block_source_used_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_BLOCK_SOURCE_USED_TOTAL.inc();
    }
}

/// Helper: increment DAG block source fallback counter.
#[inline]
pub fn dag_block_source_fallback_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_BLOCK_SOURCE_FALLBACK_TOTAL.inc();
    }
}

// -----------------------------------------------------------------------------
// T69.0 — DAG template gate metrics
// -----------------------------------------------------------------------------
/// Counter: DAG candidates rejected due to template quality gate.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_TEMPLATE_GATE_REJECTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_template_gate_rejected_total",
        "Number of DAG candidates rejected due to template quality gate"
    )
    .unwrap()
});

/// Helper: increment DAG template gate rejected counter.
#[inline]
pub fn dag_template_gate_rejected_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_TEMPLATE_GATE_REJECTED_TOTAL.inc();
    }
}

// -----------------------------------------------------------------------------
// T70.0 — Performance harness metrics
// -----------------------------------------------------------------------------

/// Gauge: unique run ID for correlating perf experiments
#[cfg(feature = "metrics")]
pub static EEZO_PERF_RUN_ID: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_perf_run_id",
        "Unique run ID for correlating performance experiment metrics"
    )
    .unwrap()
});

/// Histogram: executor time per block (seconds)
#[cfg(feature = "metrics")]
pub static EEZO_BLOCK_EXEC_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_block_exec_seconds",
        "Time spent executing a block (seconds)",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap()
});

/// Histogram: DAG candidate + template preparation time per block (seconds)
#[cfg(feature = "metrics")]
pub static EEZO_BLOCK_DAG_PREPARE_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_block_dag_prepare_seconds",
        "Time spent preparing DAG candidate and template per block (seconds)",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap()
});

/// Histogram: total block latency from slot start to block applied (seconds)
#[cfg(feature = "metrics")]
pub static EEZO_BLOCK_TOTAL_LATENCY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_block_total_latency_seconds",
        "Total time from slot start to block applied (seconds)",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap()
});

/// T70.0: Perf mode configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfMode {
    /// No performance instrumentation (default)
    Off,
    /// Measure Hotstuff + mempool baseline path
    Baseline,
    /// Measure DAG tx source path
    DagSource,
}

impl Default for PerfMode {
    fn default() -> Self {
        PerfMode::Off
    }
}

impl PerfMode {
    /// Parse perf mode from the EEZO_PERF_MODE environment variable.
    pub fn from_env() -> Self {
        match std::env::var("EEZO_PERF_MODE")
            .unwrap_or_else(|_| "off".to_string())
            .to_lowercase()
            .as_str()
        {
            "baseline" => PerfMode::Baseline,
            "dag_source" | "dagsource" => PerfMode::DagSource,
            _ => PerfMode::Off,
        }
    }

    /// Check if perf instrumentation is enabled
    pub fn is_enabled(&self) -> bool {
        !matches!(self, PerfMode::Off)
    }
}

/// Helper: set the perf run ID (called once at startup)
#[inline]
pub fn set_perf_run_id(id: i64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_PERF_RUN_ID.set(id);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = id;
    }
}

/// Helper: observe block execution time (seconds)
#[inline]
pub fn observe_block_exec_seconds(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_BLOCK_EXEC_SECONDS.observe(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

/// Helper: observe DAG prepare time (seconds)
#[inline]
pub fn observe_block_dag_prepare_seconds(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_BLOCK_DAG_PREPARE_SECONDS.observe(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

/// Helper: observe total block latency (seconds)
#[inline]
pub fn observe_block_total_latency_seconds(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_BLOCK_TOTAL_LATENCY_SECONDS.observe(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

// -----------------------------------------------------------------------------
// T70.0 — Unit tests for PerfMode
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perf_mode_default_is_off() {
        assert_eq!(PerfMode::default(), PerfMode::Off);
    }

    #[test]
    fn perf_mode_is_enabled() {
        assert!(!PerfMode::Off.is_enabled());
        assert!(PerfMode::Baseline.is_enabled());
        assert!(PerfMode::DagSource.is_enabled());
    }
}

// -----------------------------------------------------------------------------
// T71.0 / T71.2 — Node GPU hash adapter metrics
// -----------------------------------------------------------------------------

/// T71.2: Gauge indicating whether GPU hashing was successfully initialized.
/// Value: 0 = GPU unavailable/disabled/init failed, 1 = GPU successfully initialized.
/// This gauge is set once during GPU initialization and does not change afterward.
/// Runtime errors are tracked separately via error_total counter.
#[cfg(feature = "metrics")]
pub static EEZO_NODE_GPU_HASH_ENABLED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_node_gpu_hash_enabled",
        "Whether GPU hashing was successfully initialized (0=no, 1=yes)"
    )
    .unwrap()
});

/// Counter: Total number of GPU hash attempts that actually reached the GPU backend.
/// This counts only runtime hash calls when GPU is available and mode is shadow/prefer.
/// If GPU init fails at startup, this stays at 0.
/// See also: error_total which counts both init and runtime failures.
#[cfg(feature = "metrics")]
pub static EEZO_NODE_GPU_HASH_ATTEMPTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_node_gpu_hash_attempts_total",
        "Total GPU hash attempts that reached the GPU backend (runtime only)"
    )
    .unwrap()
});

/// Counter: GPU hash runs that matched CPU digest (success).
/// Only incremented during runtime when GPU produces correct results.
#[cfg(feature = "metrics")]
pub static EEZO_NODE_GPU_HASH_SUCCESS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_node_gpu_hash_success_total",
        "Total GPU hash runs that matched CPU digest"
    )
    .unwrap()
});

/// Counter: GPU hash runs that did NOT match CPU digest (mismatch).
/// Only incremented during runtime when GPU produces different results than CPU.
#[cfg(feature = "metrics")]
pub static EEZO_NODE_GPU_HASH_MISMATCH_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_node_gpu_hash_mismatch_total",
        "Total GPU hash runs with digest mismatch vs CPU"
    )
    .unwrap()
});

/// Counter: Total GPU-related errors, including both initialization failures
/// and runtime hash failures.
/// - Init failures: incremented once at startup if GPU context creation fails
/// - Runtime failures: incremented each time a hash operation fails
/// When this is > 0 but attempts_total = 0, it indicates an init failure.
#[cfg(feature = "metrics")]
pub static EEZO_NODE_GPU_HASH_ERROR_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_node_gpu_hash_error_total",
        "Total GPU errors (init failures + runtime failures)"
    )
    .unwrap()
});

/// T71.2: Helper to set the GPU enabled gauge.
/// Call with 1 when GPU init succeeds, 0 when it fails or is disabled.
#[inline]
pub fn node_gpu_hash_enabled_set(val: i64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_NODE_GPU_HASH_ENABLED.set(val);
    }
    let _ = val; // suppress unused warning when metrics feature is off
}

/// Helper: increment GPU hash attempts counter.
/// Only called during runtime hash operations, not during init.
#[inline]
pub fn node_gpu_hash_attempts_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_NODE_GPU_HASH_ATTEMPTS_TOTAL.inc();
    }
}

/// Helper: increment GPU hash success counter.
#[inline]
pub fn node_gpu_hash_success_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_NODE_GPU_HASH_SUCCESS_TOTAL.inc();
    }
}

/// Helper: increment GPU hash mismatch counter.
#[inline]
pub fn node_gpu_hash_mismatch_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_NODE_GPU_HASH_MISMATCH_TOTAL.inc();
    }
}

/// Helper: increment GPU hash error counter.
/// Called for both init failures and runtime failures.
#[inline]
pub fn node_gpu_hash_error_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_NODE_GPU_HASH_ERROR_TOTAL.inc();
    }
}

/// Eagerly register T71.0/T71.2 GPU hash metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t71_gpu_hash_metrics() {
    let _ = &*EEZO_NODE_GPU_HASH_ENABLED;
    let _ = &*EEZO_NODE_GPU_HASH_ATTEMPTS_TOTAL;
    let _ = &*EEZO_NODE_GPU_HASH_SUCCESS_TOTAL;
    let _ = &*EEZO_NODE_GPU_HASH_MISMATCH_TOTAL;
    let _ = &*EEZO_NODE_GPU_HASH_ERROR_TOTAL;
}

// -----------------------------------------------------------------------------
// T72.0 — Detailed executor performance metrics
// -----------------------------------------------------------------------------

/// Histogram: time spent in executor prepare/plan phase per block (seconds).
/// This captures any pre-loop work such as building execution plans, prefetching state, etc.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_BLOCK_PREPARE_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_block_prepare_seconds",
        "Time spent in executor prepare/plan phase per block (seconds)",
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap()
});

/// Histogram: time spent executing the main tx apply loop per block (seconds).
/// This is the core execution time running all transactions in a block.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_BLOCK_APPLY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_block_apply_seconds",
        "Time spent executing the main tx apply loop per block (seconds)",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap()
});

/// Histogram: time spent in block commit/finalize phase (seconds).
/// This captures state finalization after all transactions are applied.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_BLOCK_COMMIT_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_block_commit_seconds",
        "Time spent in block commit/finalize phase (seconds)",
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
    )
    .unwrap()
});

/// Histogram: per-transaction apply time (seconds).
/// Tracks the cost of executing individual transactions.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_TX_APPLY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_tx_apply_seconds",
        "Per-transaction apply time (seconds)",
        vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1]
    )
    .unwrap()
});

/// Histogram: number of transactions per block.
/// Helps correlate latency with transaction count.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_TXS_PER_BLOCK: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_txs_per_block",
        "Number of transactions per block",
        vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0]
    )
    .unwrap()
});

/// Histogram: total bytes of transactions per block.
/// Helps correlate latency with block size.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_BLOCK_BYTES: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_block_bytes",
        "Total bytes of transactions per block",
        vec![100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0, 500000.0, 1000000.0]
    )
    .unwrap()
});

/// Helper: observe executor block prepare time (seconds).
#[inline]
pub fn observe_exec_block_prepare_seconds(duration_sec: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_BLOCK_PREPARE_SECONDS.observe(duration_sec);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = duration_sec;
    }
}

/// Helper: observe executor block apply time (seconds).
#[inline]
pub fn observe_exec_block_apply_seconds(duration_sec: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_BLOCK_APPLY_SECONDS.observe(duration_sec);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = duration_sec;
    }
}

/// Helper: observe executor block commit time (seconds).
#[inline]
pub fn observe_exec_block_commit_seconds(duration_sec: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_BLOCK_COMMIT_SECONDS.observe(duration_sec);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = duration_sec;
    }
}

/// Helper: observe per-transaction apply time (seconds).
#[inline]
pub fn observe_exec_tx_apply_seconds(duration_sec: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_TX_APPLY_SECONDS.observe(duration_sec);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = duration_sec;
    }
}

/// Helper: observe transactions per block count.
#[inline]
pub fn observe_exec_txs_per_block(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_TXS_PER_BLOCK.observe(count as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: observe block bytes.
#[inline]
pub fn observe_exec_block_bytes(bytes: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_BLOCK_BYTES.observe(bytes as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = bytes;
    }
}

/// Eagerly register T72.0 executor performance metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t72_exec_perf_metrics() {
    let _ = &*EEZO_EXEC_BLOCK_PREPARE_SECONDS;
    let _ = &*EEZO_EXEC_BLOCK_APPLY_SECONDS;
    let _ = &*EEZO_EXEC_BLOCK_COMMIT_SECONDS;
    let _ = &*EEZO_EXEC_TX_APPLY_SECONDS;
    let _ = &*EEZO_EXEC_TXS_PER_BLOCK;
    let _ = &*EEZO_EXEC_BLOCK_BYTES;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t72_exec_perf_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T73.4 — STM-specific metrics and instrumentation
// -----------------------------------------------------------------------------

/// Counter: Total number of STM waves processed across all blocks.
#[cfg(feature = "metrics")]
pub static EEZO_STM_BLOCK_WAVES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_stm_block_waves_total",
        "Total number of STM waves processed across all blocks"
    )
    .unwrap()
});

/// Counter: Total number of conflicts detected by STM (per tx, summed across blocks).
#[cfg(feature = "metrics")]
pub static EEZO_STM_BLOCK_CONFLICTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_stm_block_conflicts_total",
        "Total number of conflicts detected by STM (per tx, summed across blocks)"
    )
    .unwrap()
});

/// Counter: Total number of transaction retries due to conflicts.
#[cfg(feature = "metrics")]
pub static EEZO_STM_BLOCK_RETRIES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_stm_block_retries_total",
        "Total number of transaction retries due to conflicts"
    )
    .unwrap()
});

/// Histogram: Distribution of "waves per block" when STM is used.
#[cfg(feature = "metrics")]
pub static EEZO_STM_WAVES_PER_BLOCK: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_stm_waves_per_block",
        "Distribution of waves per block when STM is used"
    )
    .unwrap()
});

/// Histogram: Distribution of total conflicts per block.
#[cfg(feature = "metrics")]
pub static EEZO_STM_CONFLICTS_PER_BLOCK: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_stm_conflicts_per_block",
        "Distribution of total conflicts per block"
    )
    .unwrap()
});

/// Histogram: Distribution of total retries per block.
#[cfg(feature = "metrics")]
pub static EEZO_STM_RETRIES_PER_BLOCK: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_stm_retries_per_block",
        "Distribution of total retries per block"
    )
    .unwrap()
});

/// Helper: Increment STM block waves counter.
#[inline]
pub fn stm_block_waves_inc(by: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_BLOCK_WAVES_TOTAL.inc_by(by);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = by;
    }
}

/// Helper: Increment STM block conflicts counter.
#[inline]
pub fn stm_block_conflicts_inc(by: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_BLOCK_CONFLICTS_TOTAL.inc_by(by);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = by;
    }
}

/// Helper: Increment STM block retries counter.
#[inline]
pub fn stm_block_retries_inc(by: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_BLOCK_RETRIES_TOTAL.inc_by(by);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = by;
    }
}

/// Helper: Observe waves per block histogram.
#[inline]
pub fn stm_observe_waves_per_block(waves: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_WAVES_PER_BLOCK.observe(waves as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = waves;
    }
}

/// Helper: Observe conflicts per block histogram.
#[inline]
pub fn stm_observe_conflicts_per_block(conflicts: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_CONFLICTS_PER_BLOCK.observe(conflicts as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = conflicts;
    }
}

/// Helper: Observe retries per block histogram.
#[inline]
pub fn stm_observe_retries_per_block(retries: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_RETRIES_PER_BLOCK.observe(retries as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = retries;
    }
}

/// Eagerly register T73.4 STM metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t73_stm_metrics() {
    let _ = &*EEZO_STM_BLOCK_WAVES_TOTAL;
    let _ = &*EEZO_STM_BLOCK_CONFLICTS_TOTAL;
    let _ = &*EEZO_STM_BLOCK_RETRIES_TOTAL;
    let _ = &*EEZO_STM_WAVES_PER_BLOCK;
    let _ = &*EEZO_STM_CONFLICTS_PER_BLOCK;
    let _ = &*EEZO_STM_RETRIES_PER_BLOCK;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t73_stm_metrics() {
    // No metrics to register when the feature is off.
}
// -----------------------------------------------------------------------------
// T75.1 — Shadow DAG consensus sync metrics
// -----------------------------------------------------------------------------

/// Gauge: Whether shadow DAG is in sync with canonical consensus.
/// 1 = in sync, 0 = out of sync or mismatched.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_SHADOW_IN_SYNC: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_shadow_in_sync",
        "Whether shadow DAG consensus is in sync with canonical (1=yes, 0=no)"
    )
    .unwrap()
});

/// Gauge: How many block heights the shadow DAG is behind canonical consensus.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_SHADOW_LAG_BLOCKS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_shadow_lag_blocks",
        "Number of block heights shadow DAG is behind canonical consensus"
    )
    .unwrap()
});

/// Counter: Total number of hash mismatches detected between canonical and shadow DAG.
/// Incremented when tx count differs or tx hashes differ at a height where both have data.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_SHADOW_HASH_MISMATCH_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_shadow_hash_mismatch_total",
        "Total hash mismatches between canonical and shadow DAG (tx count or tx hashes differ)"
    )
    .unwrap()
});

/// Helper: Set the shadow DAG in_sync gauge.
#[inline]
pub fn dag_shadow_sync_set(in_sync: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_SHADOW_IN_SYNC.set(if in_sync { 1 } else { 0 });
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = in_sync;
    }
}

/// Helper: Set the shadow DAG lag gauge.
#[inline]
pub fn dag_shadow_lag_set(lag: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_SHADOW_LAG_BLOCKS.set(lag as i64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = lag;
    }
}

/// Helper: Increment the shadow DAG hash mismatch counter.
#[inline]
pub fn dag_shadow_hash_mismatch_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_SHADOW_HASH_MISMATCH_TOTAL.inc();
    }
}

/// Eagerly register T75.1/T75.2 shadow DAG metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_dag_shadow_metrics() {
    let _ = &*EEZO_DAG_SHADOW_IN_SYNC;
    let _ = &*EEZO_DAG_SHADOW_LAG_BLOCKS;
    let _ = &*EEZO_DAG_SHADOW_HASH_MISMATCH_TOTAL;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_dag_shadow_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.1 — DAG Hybrid mode metrics
// -----------------------------------------------------------------------------

/// Counter: Blocks built from DAG consensus ordered batches in hybrid mode.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_BATCHES_USED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_batches_used_total",
        "Blocks built from DAG consensus ordered batches (hybrid mode)"
    )
    .unwrap()
});

/// Counter: Hybrid mode fallbacks to mempool/legacy tx source.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_FALLBACK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_fallback_total",
        "Hybrid mode fallbacks to mempool/legacy tx source"
    )
    .unwrap()
});

/// Helper: Increment hybrid batches used counter.
#[inline]
pub fn dag_hybrid_batches_used_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_BATCHES_USED_TOTAL.inc();
    }
}

/// Helper: Increment hybrid fallback counter.
#[inline]
pub fn dag_hybrid_fallback_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_FALLBACK_TOTAL.inc();
    }
}

/// Eagerly register T76.1 DAG hybrid mode metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_dag_hybrid_metrics() {
    let _ = &*EEZO_DAG_HYBRID_BATCHES_USED_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_FALLBACK_TOTAL;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_dag_hybrid_metrics() {
    // No metrics to register when the feature is off.
}