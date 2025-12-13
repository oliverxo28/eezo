//crates/node/src/metrics.rs
use once_cell::sync::Lazy;
use prometheus::{
    register_histogram, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, Counter, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
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

// ===================== T76.8: /account endpoint metrics =====================
/// Counter for account endpoint requests (labeled by route type and status)
#[cfg(feature = "metrics")]
pub static EEZO_HTTP_ACCOUNT_SERVED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_http_account_served_total",
        "Total /account endpoint requests (labeled by route type and status)",
        &["route", "status"]
    )
    .expect("register eezo_http_account_served_total")
});

/// Helper to increment account served counter
#[inline]
pub fn http_account_served_inc(route: &str, status: &str) {
    #[cfg(not(feature = "metrics"))]
    { let _ = (route, status); }
    #[cfg(feature = "metrics")]
    {
        EEZO_HTTP_ACCOUNT_SERVED_TOTAL
            .with_label_values(&[route, status])
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

// T82.2b: Mempool actor metrics
#[cfg(feature = "metrics")]
pub static EEZO_MEMPOOL_INFLIGHT_LEN: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_mempool_inflight_len",
        "Number of transactions currently in-flight (reserved for block building)"
    ).unwrap()
});

#[cfg(feature = "metrics")]
pub static EEZO_MEMPOOL_BATCHES_SERVED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_mempool_batches_served_total",
        "Total number of batches served by mempool for block building"
    ).unwrap()
});

#[cfg(feature = "metrics")]
pub static EEZO_MEMPOOL_ACTOR_ENABLED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_mempool_actor_enabled",
        "1 if mempool actor is enabled, 0 otherwise"
    ).unwrap()
});

/// T82.2b: Set the mempool actor enabled gauge.
#[cfg(feature = "metrics")]
pub fn mempool_actor_enabled_set(enabled: bool) {
    EEZO_MEMPOOL_ACTOR_ENABLED.set(if enabled { 1 } else { 0 });
}

/// T82.2b: Update the in-flight length gauge.
#[cfg(feature = "metrics")]
pub fn mempool_inflight_len_set(len: usize) {
    EEZO_MEMPOOL_INFLIGHT_LEN.set(len as i64);
}

/// T82.2b: Increment the batches served counter.
#[cfg(feature = "metrics")]
pub fn mempool_batches_served_inc() {
    EEZO_MEMPOOL_BATCHES_SERVED_TOTAL.inc();
}

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

 // T85.0: Legacy HotStuff metrics have been removed. Only DAG metrics remain.
#[cfg(all(feature = "metrics", feature = "pq44-runtime"))]
pub fn register_ledger_consensus_metrics() {
	// T32 metrics (ensure presence on /metrics even before first observation)
	eezo_ledger::metrics::register_t32_metrics();
	// T51 metrics: force initialization of mempool metrics
	// (tx inclusion metrics are in ledger and initialized via register_t32_metrics)
	#[cfg(feature = "metrics")]
	{
		let _ = &*EEZO_MEMPOOL_LEN;
		let _ = &*EEZO_MEMPOOL_BYTES;
		// T82.2b: mempool actor metrics
		let _ = &*EEZO_MEMPOOL_INFLIGHT_LEN;
		let _ = &*EEZO_MEMPOOL_BATCHES_SERVED_TOTAL;
		let _ = &*EEZO_MEMPOOL_ACTOR_ENABLED;
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
// T83.0 — Enhanced SigPool metrics (micro-batching + cache)
// -----------------------------------------------------------------------------

/// Counter: Total micro-batches executed by sigpool.
pub static EEZO_SIGPOOL_BATCHES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_sigpool_batches_total",
        "Total number of micro-batches executed by sigpool (T83.0)"
    )
    .unwrap()
});

/// Histogram: Distribution of batch sizes.
pub static EEZO_SIGPOOL_BATCH_SIZE: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_sigpool_batch_size",
        "Distribution of sigpool micro-batch sizes (T83.0)",
        vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0]
    )
    .unwrap()
});

/// Counter: Cache hits in the signature verification cache.
pub static EEZO_SIGPOOL_CACHE_HITS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_sigpool_cache_hits_total",
        "Total cache hits in sigpool replay cache (T83.0)"
    )
    .unwrap()
});

/// Counter: Cache misses in the signature verification cache.
pub static EEZO_SIGPOOL_CACHE_MISSES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_sigpool_cache_misses_total",
        "Total cache misses in sigpool replay cache (T83.0)"
    )
    .unwrap()
});

/// Histogram: Batch verification latency in seconds.
pub static EEZO_SIGPOOL_BATCH_LATENCY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_sigpool_batch_latency_seconds",
        "Sigpool micro-batch verification latency (seconds) (T83.0)",
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
    )
    .unwrap()
});

/// Eagerly register T83.0 sigpool metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t83_sigpool_metrics() {
    let _ = &*EEZO_SIGPOOL_QUEUED_TOTAL;
    let _ = &*EEZO_SIGPOOL_VERIFIED_TOTAL;
    let _ = &*EEZO_SIGPOOL_FAILED_TOTAL;
    let _ = &*EEZO_SIGPOOL_ACTIVE_THREADS;
    let _ = &*EEZO_SIGPOOL_BATCHES_TOTAL;
    let _ = &*EEZO_SIGPOOL_BATCH_SIZE;
    let _ = &*EEZO_SIGPOOL_CACHE_HITS_TOTAL;
    let _ = &*EEZO_SIGPOOL_CACHE_MISSES_TOTAL;
    let _ = &*EEZO_SIGPOOL_BATCH_LATENCY_SECONDS;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t83_sigpool_metrics() {
    // No metrics to register when the feature is off.
}

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
    /// Measure legacy + mempool baseline path
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
// T90.0 — GPU Hash Plumbing metrics (non-consensus, feature-gated)
// -----------------------------------------------------------------------------
//
// These metrics track the T90.0 GPU hash plumbing milestone:
// - eezo_gpu_hash_enabled: gauge (0/1) indicating GPU hash backend availability
// - eezo_gpu_hash_jobs_total: counter of GPU hash batches requested
// - eezo_gpu_hash_failures_total: counter of failed GPU jobs
// - eezo_gpu_hash_latency_seconds: histogram of per-batch wall-clock time
// - eezo_gpu_hash_bytes_total: counter of total bytes hashed via GPU
// - eezo_gpu_hash_mismatch_total: counter of GPU/CPU hash mismatches

/// T90.0: Gauge indicating whether GPU hash backend was successfully initialized.
/// Value: 0 = GPU unavailable/disabled/init failed, 1 = GPU successfully initialized.
#[cfg(feature = "metrics")]
pub static EEZO_GPU_HASH_ENABLED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_gpu_hash_enabled",
        "Whether GPU hash backend was successfully initialized (0=no, 1=yes)"
    )
    .unwrap()
});

/// T90.0: Counter of GPU hash batches requested.
#[cfg(feature = "metrics")]
pub static EEZO_GPU_HASH_JOBS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_gpu_hash_jobs_total",
        "Total number of GPU hash batches requested"
    )
    .unwrap()
});

/// T90.0: Counter of failed GPU hash operations (including device unavailable).
#[cfg(feature = "metrics")]
pub static EEZO_GPU_HASH_FAILURES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_gpu_hash_failures_total",
        "Total number of GPU hash failures (device unavailable, compute errors)"
    )
    .unwrap()
});

/// T90.0: Histogram of GPU hash batch latency in seconds.
#[cfg(feature = "metrics")]
pub static EEZO_GPU_HASH_LATENCY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_gpu_hash_latency_seconds",
        "GPU hash batch latency (seconds)",
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
    )
    .unwrap()
});

/// T90.0: Counter of total bytes hashed via GPU.
#[cfg(feature = "metrics")]
pub static EEZO_GPU_HASH_BYTES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_gpu_hash_bytes_total",
        "Total bytes hashed via GPU"
    )
    .unwrap()
});

/// T90.0: Counter of GPU/CPU hash mismatches detected.
#[cfg(feature = "metrics")]
pub static EEZO_GPU_HASH_MISMATCH_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_gpu_hash_mismatch_total",
        "Total GPU/CPU hash mismatches detected (GPU disagrees with CPU)"
    )
    .unwrap()
});

/// T90.0: Helper to set the GPU hash enabled gauge.
#[inline]
pub fn gpu_hash_enabled_set(val: i64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_GPU_HASH_ENABLED.set(val);
    }
    let _ = val;
}

/// T90.0: Helper to increment GPU hash jobs counter.
#[inline]
pub fn gpu_hash_jobs_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_GPU_HASH_JOBS_TOTAL.inc();
    }
}

/// T90.0: Helper to increment GPU hash failures counter.
#[inline]
pub fn gpu_hash_failures_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_GPU_HASH_FAILURES_TOTAL.inc();
    }
}

/// T90.0: Helper to observe GPU hash latency.
#[inline]
pub fn gpu_hash_latency_observe(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_GPU_HASH_LATENCY_SECONDS.observe(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

/// T90.0: Helper to increment GPU hash bytes counter.
#[inline]
pub fn gpu_hash_bytes_inc(bytes: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_GPU_HASH_BYTES_TOTAL.inc_by(bytes);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = bytes;
    }
}

/// T90.0: Helper to increment GPU/CPU mismatch counter.
#[inline]
pub fn gpu_hash_mismatch_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_GPU_HASH_MISMATCH_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// T90.0: Eagerly register GPU hash plumbing metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t90_gpu_hash_metrics() {
    let _ = &*EEZO_GPU_HASH_ENABLED;
    let _ = &*EEZO_GPU_HASH_JOBS_TOTAL;
    let _ = &*EEZO_GPU_HASH_FAILURES_TOTAL;
    let _ = &*EEZO_GPU_HASH_LATENCY_SECONDS;
    let _ = &*EEZO_GPU_HASH_BYTES_TOTAL;
    let _ = &*EEZO_GPU_HASH_MISMATCH_TOTAL;
}

/// T90.0: No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t90_gpu_hash_metrics() {
    // No metrics to register when the feature is off.
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
    // T76.7: Also register exec lanes/wave cap gauges
    register_t76_stm_tuning_metrics();
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t73_stm_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.7 — STM executor tuning gauges
// -----------------------------------------------------------------------------

/// Gauge: Number of execution lanes configured for STM executor.
/// Set from EEZO_EXEC_LANES env var (default 16, allow 32/48/64).
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_LANES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_exec_lanes",
        "Number of execution lanes configured for STM executor"
    )
    .unwrap()
});

/// Gauge: Optional cap on transactions per wave in STM executor.
/// Set from EEZO_EXEC_WAVE_CAP env var (0 = unlimited).
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_WAVE_CAP: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_exec_wave_cap",
        "Optional cap on transactions per wave in STM executor (0=unlimited)"
    )
    .unwrap()
});

/// Helper: Set the exec_lanes gauge.
#[inline]
pub fn exec_lanes_set(lanes: usize) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_LANES.set(lanes as i64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = lanes;
    }
}

/// Helper: Set the wave_cap gauge.
#[inline]
pub fn exec_wave_cap_set(cap: usize) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_WAVE_CAP.set(cap as i64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = cap;
    }
}

/// Eagerly register T76.7 STM tuning metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t76_stm_tuning_metrics() {
    let _ = &*EEZO_EXEC_LANES;
    let _ = &*EEZO_EXEC_WAVE_CAP;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t76_stm_tuning_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.7 — Hybrid aggregation metrics
// -----------------------------------------------------------------------------

/// Histogram: Number of DAG batches aggregated per block in hybrid mode.
#[cfg(feature = "metrics")]
pub static EEZO_HYBRID_AGG_BATCHES_PER_BLOCK: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_hybrid_agg_batches_per_block",
        "Number of DAG batches aggregated per block in hybrid mode",
        vec![1.0, 2.0, 3.0, 5.0, 8.0, 10.0, 15.0, 20.0, 30.0, 50.0]
    )
    .unwrap()
});

/// Histogram: Total tx candidates aggregated per block in hybrid mode.
#[cfg(feature = "metrics")]
pub static EEZO_HYBRID_AGG_TX_CANDIDATES: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_hybrid_agg_tx_candidates",
        "Total tx candidates aggregated per block in hybrid mode",
        vec![1.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0]
    )
    .unwrap()
});

/// Helper: Observe number of batches aggregated per block.
#[inline]
pub fn observe_hybrid_agg_batches_per_block(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_HYBRID_AGG_BATCHES_PER_BLOCK.observe(count as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Observe total tx candidates aggregated per block.
#[inline]
pub fn observe_hybrid_agg_tx_candidates(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_HYBRID_AGG_TX_CANDIDATES.observe(count as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Eagerly register T76.7 hybrid aggregation metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t76_hybrid_agg_metrics() {
    let _ = &*EEZO_HYBRID_AGG_BATCHES_PER_BLOCK;
    let _ = &*EEZO_HYBRID_AGG_TX_CANDIDATES;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t76_hybrid_agg_metrics() {
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
// T76.1 / T81.2 / T81.5 — DAG mode metrics (pure DAG semantics)
// -----------------------------------------------------------------------------

/// Gauge: Active consensus mode (3=dag-primary is the only production mode).
/// Set at startup based on EEZO_CONSENSUS_MODE environment variable.
///
/// # T85.0: DAG-Only Semantics
///
/// After T85.0, EEZO is 100% DAG-only. All HotStuff code has been removed.
/// The gauge values are:
/// - 3 = DagPrimary (PRODUCTION: the only recommended mode)
/// - 2 = Dag (legacy transition mode)
/// - 1 = DagHybrid with ordering enabled (deprecated transition mode)
/// - 0 = DagHybrid-without-ordering (DEPRECATED, not valid in production)
///
/// Unknown mode strings will cause a config warning and fallback to dag-primary.
#[cfg(feature = "metrics")]
pub static EEZO_CONSENSUS_MODE_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_consensus_mode_active",
        "Active consensus mode: 3=dag-primary (production), 2=dag, 1=dag-hybrid, 0=legacy(deprecated)"
    )
    .unwrap()
});

/// Helper: Set the consensus mode gauge value.
/// - 3 = DagPrimary (T81.5: DAG-only production mode, RECOMMENDED)
/// - 2 = Dag (legacy transition)
/// - 1 = DagHybrid with ordering (deprecated transition)
/// - 0 = Legacy/deprecated (should not appear in production)
#[inline]
pub fn consensus_mode_active_set(mode: i64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_CONSENSUS_MODE_ACTIVE.set(mode);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = mode;
    }
}

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
/// DEPRECATED: Use EEZO_DAG_HYBRID_FALLBACK_REASON_TOTAL with labels instead.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_FALLBACK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_fallback_total",
        "Hybrid mode fallbacks to mempool/legacy tx source"
    )
    .unwrap()
});

/// T76.12: Counter with labels for fallback reasons.
/// Labels:
/// - reason="min_dag_not_met" — min DAG threshold not met
/// - reason="timeout" — waited for DAG, hit timeout
/// - reason="empty" — DAG batch came back empty after de-dup or prefilter
/// - reason="no_handle" — no hybrid handle attached
/// - reason="queue_empty" — no batches in queue when checked
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_FALLBACK_REASON_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_dag_hybrid_fallback_reason_total",
        "Hybrid mode fallbacks to mempool (labeled by reason)",
        &["reason"]
    )
    .expect("metric registered")
});

/// Helper: Increment hybrid batches used counter.
#[inline]
pub fn dag_hybrid_batches_used_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_BATCHES_USED_TOTAL.inc();
    }
}

/// Helper: Increment hybrid fallback counter (legacy unlabeled).
#[inline]
pub fn dag_hybrid_fallback_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_FALLBACK_TOTAL.inc();
    }
}

/// T76.12: Increment hybrid fallback counter with a specific reason label.
/// Valid reasons: "min_dag_not_met", "timeout", "empty", "no_handle", "queue_empty"
#[inline]
pub fn dag_hybrid_fallback_reason_inc(reason: &str) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_FALLBACK_REASON_TOTAL
            .with_label_values(&[reason])
            .inc();
        // Also increment the legacy unlabeled counter for backward compatibility
        EEZO_DAG_HYBRID_FALLBACK_TOTAL.inc();
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = reason;
    }
}

/// Eagerly register T76.1 DAG hybrid mode metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_dag_hybrid_metrics() {
    // T76.11: Register consensus mode gauge
    let _ = &*EEZO_CONSENSUS_MODE_ACTIVE;
    let _ = &*EEZO_DAG_HYBRID_BATCHES_USED_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_FALLBACK_TOTAL;
    // T76.12: Register labeled fallback counter
    let _ = &*EEZO_DAG_HYBRID_FALLBACK_REASON_TOTAL;
    // T76.3: Also register the bytes-level metrics
    register_dag_hybrid_bytes_metrics();
    // T76.4: Also register the apply-level metrics
    register_dag_hybrid_apply_metrics();
    // T76.5: Also register the de-dup and nonce prefilter metrics
    register_dag_hybrid_dedup_metrics();
    // T76.6: Also register the startup/stale batch metrics
    register_dag_hybrid_startup_metrics();
    // T76.7: Also register the aggregation metrics
    register_t76_hybrid_agg_metrics();
    // T76.10: Also register the adaptive aggregation metrics
    register_t76_adaptive_agg_metrics();
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_dag_hybrid_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.2 — DAG ordered batch visibility metrics
// -----------------------------------------------------------------------------

/// Gauge: Number of DAG ordered batches currently ready for consumption.
/// This allows visibility into the DAG ordering queue without consuming batches.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_ORDERED_READY: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_ordered_ready",
        "Number of DAG ordered batches currently ready for consumption"
    )
    .unwrap()
});

/// Helper: Set the ordered ready gauge value.
#[inline]
pub fn dag_ordered_ready_set(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_ORDERED_READY.set(count as i64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count; // silence unused warning
    }
}

/// Eagerly register T76.2 DAG ordered visibility metrics.
#[cfg(feature = "metrics")]
pub fn register_dag_ordered_metrics() {
    let _ = &*EEZO_DAG_ORDERED_READY;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_dag_ordered_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.3 — DAG hybrid bytes consumption metrics
// -----------------------------------------------------------------------------

/// Counter: Total tx hashes received from DAG batches (before resolution).
/// This is the total count of tx hashes in all DAG batches passed to the hybrid consumer.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_HASHES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_hashes_total",
        "Total tx hashes received from DAG batches (before resolution)"
    )
    .unwrap()
});

/// Counter: Total tx hashes that were successfully resolved (bytes available + decoded successfully).
/// Aliased as "hashes_resolved" per T76.3 requirements.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_HASHES_RESOLVED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_hashes_resolved_total",
        "Total tx hashes successfully resolved from DAG batch (bytes available and decoded)"
    )
    .unwrap()
});

/// Counter: Total tx hashes where bytes were missing from DAG batch.
/// Aliased as "hashes_missing" per T76.3 requirements.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_HASHES_MISSING_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_hashes_missing_total",
        "Total tx hashes where bytes were missing from DAG batch"
    )
    .unwrap()
});

/// Counter: Total transactions where decoding the tx bytes failed.
/// Aliased as "decode_errors" per T76.3 requirements.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_DECODE_ERRORS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_decode_errors_total",
        "Total transactions where decoding the tx bytes from DAG batch failed"
    )
    .unwrap()
});

/// Counter: Total transactions where bytes were directly available from DAG batch.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_BYTES_USED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_bytes_used_total",
        "Total transactions where bytes were directly available from DAG batch"
    )
    .unwrap()
});

/// Counter: Total transactions where bytes were missing from DAG batch (required mempool lookup).
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_BYTES_MISSING_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_bytes_missing_total",
        "Total transactions where bytes were missing from DAG batch (required mempool lookup)"
    )
    .unwrap()
});

/// Counter: Total transactions where decoding the tx bytes failed.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_DECODE_ERROR_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_decode_error_total",
        "Total transactions where decoding the tx bytes from DAG batch failed"
    )
    .unwrap()
});

/// Helper: Increment bytes used counter.
#[inline]
pub fn dag_hybrid_bytes_used_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_BYTES_USED_TOTAL.inc();
    }
}

/// Helper: Increment bytes used counter by a specific amount.
#[inline]
pub fn dag_hybrid_bytes_used_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_BYTES_USED_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment bytes missing counter.
#[inline]
pub fn dag_hybrid_bytes_missing_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_BYTES_MISSING_TOTAL.inc();
    }
}

/// Helper: Increment bytes missing counter by a specific amount.
#[inline]
pub fn dag_hybrid_bytes_missing_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_BYTES_MISSING_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment decode error counter.
#[inline]
pub fn dag_hybrid_decode_error_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_DECODE_ERROR_TOTAL.inc();
    }
}

/// Helper: Increment decode error counter by a specific amount.
#[inline]
pub fn dag_hybrid_decode_error_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_DECODE_ERROR_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment total hashes counter by a specific amount.
#[inline]
pub fn dag_hybrid_hashes_total_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_HASHES_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment resolved hashes counter by a specific amount.
#[inline]
pub fn dag_hybrid_hashes_resolved_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_HASHES_RESOLVED_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment missing hashes counter by a specific amount.
#[inline]
pub fn dag_hybrid_hashes_missing_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_HASHES_MISSING_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment decode errors counter by a specific amount.
#[inline]
pub fn dag_hybrid_decode_errors_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_DECODE_ERRORS_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Eagerly register T76.3 DAG hybrid bytes metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_dag_hybrid_bytes_metrics() {
    let _ = &*EEZO_DAG_HYBRID_HASHES_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_HASHES_RESOLVED_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_HASHES_MISSING_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_DECODE_ERRORS_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_BYTES_USED_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_BYTES_MISSING_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_DECODE_ERROR_TOTAL;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_dag_hybrid_bytes_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.4 — Hybrid batch apply metrics (apply_ok, apply_fail)
// -----------------------------------------------------------------------------

/// Counter: Total transactions successfully applied from hybrid DAG batches.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_APPLY_OK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_apply_ok_total",
        "Total transactions successfully applied from hybrid DAG batches"
    )
    .unwrap()
});

/// Counter: Total transactions that failed to apply from hybrid DAG batches.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_APPLY_FAIL_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_apply_fail_total",
        "Total transactions that failed to apply from hybrid DAG batches"
    )
    .unwrap()
});

/// Helper: Increment apply_ok counter by a specific amount.
#[inline]
pub fn dag_hybrid_apply_ok_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_APPLY_OK_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment apply_fail counter by a specific amount.
#[inline]
pub fn dag_hybrid_apply_fail_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_APPLY_FAIL_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

// -----------------------------------------------------------------------------
// T76.5 — Per-reason apply failure metrics
// -----------------------------------------------------------------------------

/// Counter: BadNonce failures from hybrid DAG batches.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_APPLY_FAIL_BAD_NONCE: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_apply_fail_bad_nonce_total",
        "Transactions that failed due to bad nonce in hybrid DAG batches"
    )
    .unwrap()
});

/// Counter: InsufficientFunds failures from hybrid DAG batches.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_APPLY_FAIL_INSUFFICIENT_FUNDS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_apply_fail_insufficient_funds_total",
        "Transactions that failed due to insufficient funds in hybrid DAG batches"
    )
    .unwrap()
});

/// Counter: InvalidSender failures from hybrid DAG batches.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_APPLY_FAIL_INVALID_SENDER: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_apply_fail_invalid_sender_total",
        "Transactions that failed due to invalid sender in hybrid DAG batches"
    )
    .unwrap()
});

/// Counter: Other failures from hybrid DAG batches.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_APPLY_FAIL_OTHER: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_apply_fail_other_total",
        "Transactions that failed due to other reasons in hybrid DAG batches"
    )
    .unwrap()
});

/// Helper: Increment bad_nonce failure counter.
#[inline]
pub fn dag_hybrid_apply_fail_bad_nonce_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_APPLY_FAIL_BAD_NONCE.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment insufficient_funds failure counter.
#[inline]
pub fn dag_hybrid_apply_fail_insufficient_funds_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_APPLY_FAIL_INSUFFICIENT_FUNDS.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment invalid_sender failure counter.
#[inline]
pub fn dag_hybrid_apply_fail_invalid_sender_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_APPLY_FAIL_INVALID_SENDER.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment other failure counter.
#[inline]
pub fn dag_hybrid_apply_fail_other_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_APPLY_FAIL_OTHER.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Eagerly register T76.4 DAG hybrid apply metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_dag_hybrid_apply_metrics() {
    let _ = &*EEZO_DAG_HYBRID_APPLY_OK_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_APPLY_FAIL_TOTAL;
    // T76.5: Also register per-reason failure metrics
    let _ = &*EEZO_DAG_HYBRID_APPLY_FAIL_BAD_NONCE;
    let _ = &*EEZO_DAG_HYBRID_APPLY_FAIL_INSUFFICIENT_FUNDS;
    let _ = &*EEZO_DAG_HYBRID_APPLY_FAIL_INVALID_SENDER;
    let _ = &*EEZO_DAG_HYBRID_APPLY_FAIL_OTHER;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_dag_hybrid_apply_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.5 — Hybrid de-dup + nonce guard metrics
// -----------------------------------------------------------------------------

/// Counter: Total transactions filtered out by de-dup LRU (already committed).
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_SEEN_BEFORE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_seen_before_total",
        "Total transactions filtered by de-dup (already committed)"
    )
    .unwrap()
});

/// Counter: Total candidate transactions after de-dup filtering.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_CANDIDATE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_candidate_total",
        "Total candidate transactions after de-dup filtering"
    )
    .unwrap()
});

/// Counter: Total transactions dropped by nonce prefilter (nonce too low).
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_BAD_NONCE_PREFILTER_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_bad_nonce_prefilter_total",
        "Total transactions dropped by nonce prefilter (nonce < account nonce)"
    )
    .unwrap()
});

/// T78.SAFE: Counter: Total transactions dropped due to nonce gaps.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_NONCE_GAP_DROPPED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_nonce_gap_dropped_total",
        "Total transactions dropped due to nonce gaps (tx.nonce != expected nonce)"
    )
    .unwrap()
});

/// Gauge: Current size of the de-dup LRU cache.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_DEDUP_LRU_SIZE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_hybrid_dedup_lru_size",
        "Current number of tx hashes in the de-dup LRU cache"
    )
    .unwrap()
});

/// Helper: Increment seen_before counter by a specific amount.
#[inline]
pub fn dag_hybrid_seen_before_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_SEEN_BEFORE_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment candidate counter by a specific amount.
#[inline]
pub fn dag_hybrid_candidate_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_CANDIDATE_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment bad_nonce_prefilter counter by a specific amount.
#[inline]
pub fn dag_hybrid_bad_nonce_prefilter_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_BAD_NONCE_PREFILTER_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// T78.SAFE: Helper: Increment nonce_gap_dropped counter by a specific amount.
#[inline]
pub fn dag_hybrid_nonce_gap_dropped_inc_by(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_NONCE_GAP_DROPPED_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Set the de-dup LRU size gauge.
#[inline]
pub fn dag_hybrid_dedup_lru_size_set(size: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_DEDUP_LRU_SIZE.set(size as i64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = size;
    }
}

/// Eagerly register T76.5 DAG hybrid de-dup metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_dag_hybrid_dedup_metrics() {
    let _ = &*EEZO_DAG_HYBRID_SEEN_BEFORE_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_CANDIDATE_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_BAD_NONCE_PREFILTER_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_NONCE_GAP_DROPPED_TOTAL; // T78.SAFE
    let _ = &*EEZO_DAG_HYBRID_DEDUP_LRU_SIZE;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_dag_hybrid_dedup_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.6 — Quiet startup + stale-batch handling metrics
// -----------------------------------------------------------------------------

/// Counter: Batches where all tx hashes were filtered by de-dup (filtered_seen == n).
/// Incremented when a batch arrives but all txs are already committed.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_ALL_FILTERED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_all_filtered_total",
        "Batches where all tx hashes were filtered by de-dup (pure dedup, no candidates)"
    )
    .unwrap()
});

/// Counter: Stale batches dropped at startup (round <= node_start_round).
/// Incremented when a pre-start DAG batch is detected and dropped.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_STALE_BATCHES_DROPPED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_stale_batches_dropped_total",
        "Stale DAG batches dropped at startup (round <= node_start_round)"
    )
    .unwrap()
});

/// Counter: Batches where candidate == 0 after dedup/nonce-pref.
/// Incremented when a batch yields no valid candidates after filtering.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_HYBRID_EMPTY_CANDIDATES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_hybrid_empty_candidates_total",
        "Batches with zero candidates after dedup and nonce prefilter"
    )
    .unwrap()
});

/// Helper: Increment all_filtered counter.
#[inline]
pub fn dag_hybrid_all_filtered_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_ALL_FILTERED_TOTAL.inc();
    }
}

/// Helper: Increment stale_batches_dropped counter.
#[inline]
pub fn dag_hybrid_stale_batches_dropped_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_STALE_BATCHES_DROPPED_TOTAL.inc();
    }
}

/// Helper: Increment empty_candidates counter.
#[inline]
pub fn dag_hybrid_empty_candidates_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_HYBRID_EMPTY_CANDIDATES_TOTAL.inc();
    }
}

/// Eagerly register T76.6 quiet startup metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_dag_hybrid_startup_metrics() {
    let _ = &*EEZO_DAG_HYBRID_ALL_FILTERED_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_STALE_BATCHES_DROPPED_TOTAL;
    let _ = &*EEZO_DAG_HYBRID_EMPTY_CANDIDATES_TOTAL;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_dag_hybrid_startup_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.9 — Fast Decode Pool metrics
// -----------------------------------------------------------------------------

/// Counter: Total transactions processed by the decode pool.
#[cfg(feature = "metrics")]
pub static EEZO_DECODE_POOL_TX_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_decode_pool_tx_total",
        "Total transactions processed by the decode pool"
    )
    .unwrap()
});

/// Counter: Cache hits in the decode pool.
#[cfg(feature = "metrics")]
pub static EEZO_DECODE_POOL_CACHE_HIT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_decode_pool_cache_hit_total",
        "Number of cache hits in the decode pool"
    )
    .unwrap()
});

/// Counter: Cache misses in the decode pool.
#[cfg(feature = "metrics")]
pub static EEZO_DECODE_POOL_CACHE_MISS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_decode_pool_cache_miss_total",
        "Number of cache misses in the decode pool"
    )
    .unwrap()
});

/// Histogram: Per-transaction decode latency in seconds.
#[cfg(feature = "metrics")]
pub static EEZO_DECODE_LATENCY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_decode_latency_seconds",
        "Per-transaction decode latency (seconds)",
        vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1]
    )
    .unwrap()
});

/// Counter: Cache evictions in the decode pool.
#[cfg(feature = "metrics")]
pub static EEZO_DECODE_POOL_EVICTIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_decode_pool_evictions_total",
        "Number of cache evictions in the decode pool"
    )
    .unwrap()
});

/// Gauge: Current size of the decode pool cache.
#[cfg(feature = "metrics")]
pub static EEZO_DECODE_POOL_CACHE_SIZE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_decode_pool_cache_size",
        "Current number of entries in the decode pool cache"
    )
    .unwrap()
});

/// Helper: Increment the decode pool tx counter.
#[inline]
pub fn decode_pool_tx_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DECODE_POOL_TX_TOTAL.inc();
    }
}

/// Helper: Increment the decode pool cache hit counter.
#[inline]
pub fn decode_pool_cache_hit_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DECODE_POOL_CACHE_HIT_TOTAL.inc();
    }
}

/// Helper: Increment the decode pool cache miss counter.
#[inline]
pub fn decode_pool_cache_miss_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DECODE_POOL_CACHE_MISS_TOTAL.inc();
    }
}

/// Helper: Observe decode latency.
#[inline]
pub fn observe_decode_latency_seconds(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DECODE_LATENCY_SECONDS.observe(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

/// Helper: Increment the decode pool evictions counter.
#[inline]
pub fn decode_pool_evictions_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DECODE_POOL_EVICTIONS_TOTAL.inc();
    }
}

/// Helper: Set the decode pool cache size gauge.
#[inline]
pub fn decode_pool_cache_size_set(size: usize) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DECODE_POOL_CACHE_SIZE.set(size as i64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = size;
    }
}

/// Eagerly register T76.9 decode pool metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t76_decode_pool_metrics() {
    let _ = &*EEZO_DECODE_POOL_TX_TOTAL;
    let _ = &*EEZO_DECODE_POOL_CACHE_HIT_TOTAL;
    let _ = &*EEZO_DECODE_POOL_CACHE_MISS_TOTAL;
    let _ = &*EEZO_DECODE_LATENCY_SECONDS;
    let _ = &*EEZO_DECODE_POOL_EVICTIONS_TOTAL;
    let _ = &*EEZO_DECODE_POOL_CACHE_SIZE;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t76_decode_pool_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T76.10 — Adaptive Aggregation & Block Size Shaping metrics
// -----------------------------------------------------------------------------

/// Counter: Aggregation cap reason (labeled by reason: time, bytes, tx, empty).
/// Records why each aggregation ended.
#[cfg(feature = "metrics")]
pub static EEZO_HYBRID_AGG_CAP_REASON_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_hybrid_agg_cap_reason_total",
        "Reason aggregation ended (labeled by reason: time, bytes, tx, empty)",
        &["reason"]
    )
    .unwrap()
});

/// Gauge: Current adaptive aggregation time budget in milliseconds.
#[cfg(feature = "metrics")]
pub static EEZO_HYBRID_AGG_TIME_BUDGET_MS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_hybrid_agg_time_budget_ms",
        "Current adaptive aggregation time budget in milliseconds"
    )
    .unwrap()
});

/// Gauge: Whether adaptive mode is enabled (1) or fixed budget is used (0).
#[cfg(feature = "metrics")]
pub static EEZO_HYBRID_AGG_ADAPTIVE_ENABLED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_hybrid_agg_adaptive_enabled",
        "Whether adaptive aggregation mode is enabled (1=adaptive, 0=fixed)"
    )
    .unwrap()
});

/// Helper: Observe aggregation cap reason (time, bytes, tx, empty).
#[inline]
pub fn observe_hybrid_agg_cap_reason(reason: &str) {
    #[cfg(feature = "metrics")]
    {
        EEZO_HYBRID_AGG_CAP_REASON_TOTAL
            .with_label_values(&[reason])
            .inc();
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = reason;
    }
}

/// Helper: Set the current adaptive aggregation time budget in milliseconds.
#[inline]
pub fn observe_hybrid_agg_time_budget_ms(budget_ms: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_HYBRID_AGG_TIME_BUDGET_MS.set(budget_ms as i64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = budget_ms;
    }
}

/// Helper: Set whether adaptive mode is enabled.
#[inline]
pub fn observe_hybrid_agg_adaptive_enabled(enabled: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_HYBRID_AGG_ADAPTIVE_ENABLED.set(if enabled { 1 } else { 0 });
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = enabled;
    }
}

/// Eagerly register T76.10 adaptive aggregation metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t76_adaptive_agg_metrics() {
    let _ = &*EEZO_HYBRID_AGG_CAP_REASON_TOTAL;
    let _ = &*EEZO_HYBRID_AGG_TIME_BUDGET_MS;
    let _ = &*EEZO_HYBRID_AGG_ADAPTIVE_ENABLED;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t76_adaptive_agg_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T77.1 — DAG Ordering Latency Histogram
// -----------------------------------------------------------------------------

/// Histogram: Time from submit_pending_txs() to batch consumption in hybrid aggregation.
/// This measures the DAG ordering latency in seconds.
/// Buckets are chosen for millisecond-scale latency up to a few hundred ms.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_ORDERING_LATENCY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_dag_ordering_latency_seconds",
        "Time from pending tx submission to batch readiness in hybrid mode (seconds)",
        vec![0.001, 0.005, 0.010, 0.020, 0.030, 0.050, 0.100, 0.200, 0.500, 1.0]
    )
    .unwrap()
});

/// Helper: Observe DAG ordering latency (seconds).
/// Called when a batch is successfully consumed from the DAG ordering queue.
#[inline]
pub fn observe_dag_ordering_latency_seconds(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_ORDERING_LATENCY_SECONDS.observe(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

/// Eagerly register T77.1 DAG ordering latency metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t77_dag_ordering_latency_metrics() {
    let _ = &*EEZO_DAG_ORDERING_LATENCY_SECONDS;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t77_dag_ordering_latency_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T82.0 — DAG TPS Baseline & Profiling - Executor metrics with eezo_exec_* prefix
// -----------------------------------------------------------------------------
//
// These metrics follow the eezo_exec_* naming convention as requested for T82.0.
// They track STM executor behavior (waves, conflicts, retries) per block for
// TPS baseline measurement and profiling.

/// Counter: Total number of STM execution waves across all blocks.
/// Alias for eezo_stm_block_waves_total with eezo_exec_* prefix.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_WAVES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_stm_waves_total",
        "Total STM execution waves across all blocks (T82.0)"
    )
    .unwrap()
});

/// Counter: Total tx conflicts detected during STM execution.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_CONFLICTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_stm_conflicts_total",
        "Total tx conflicts detected during STM execution (T82.0)"
    )
    .unwrap()
});

/// Counter: Total txs retried due to conflicts during STM execution.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_RETRIES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_stm_retries_total",
        "Total txs retried due to conflicts during STM execution (T82.0)"
    )
    .unwrap()
});

/// Counter: Total txs aborted after max retries in STM execution.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_ABORTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_stm_aborted_total",
        "Total txs aborted after max retries in STM execution (T82.0)"
    )
    .unwrap()
});

/// Histogram: STM waves per block distribution.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_WAVES_PER_BLOCK: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_stm_waves_per_block",
        "Distribution of STM waves per block (T82.0)",
        vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 15.0, 20.0]
    )
    .unwrap()
});

/// Histogram: Conflicts per block distribution.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_CONFLICTS_PER_BLOCK: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_stm_conflicts_per_block",
        "Distribution of conflicts per block (T82.0)",
        vec![0.0, 1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0]
    )
    .unwrap()
});

/// Histogram: Retries per block distribution.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_RETRIES_PER_BLOCK: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_stm_retries_per_block",
        "Distribution of retries per block (T82.0)",
        vec![0.0, 1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0]
    )
    .unwrap()
});

/// Helper: Increment STM waves counter (T82.0).
#[inline]
pub fn exec_stm_waves_inc(by: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_WAVES_TOTAL.inc_by(by);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = by;
    }
}

/// Helper: Increment STM conflicts counter (T82.0).
#[inline]
pub fn exec_stm_conflicts_inc(by: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_CONFLICTS_TOTAL.inc_by(by);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = by;
    }
}

/// Helper: Increment STM retries counter (T82.0).
#[inline]
pub fn exec_stm_retries_inc(by: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_RETRIES_TOTAL.inc_by(by);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = by;
    }
}

/// Helper: Increment STM aborted counter (T82.0).
#[inline]
pub fn exec_stm_aborted_inc(by: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_ABORTED_TOTAL.inc_by(by);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = by;
    }
}

/// Helper: Observe STM waves per block (T82.0).
#[inline]
pub fn exec_stm_observe_waves_per_block(waves: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_WAVES_PER_BLOCK.observe(waves as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = waves;
    }
}

/// Helper: Observe STM conflicts per block (T82.0).
#[inline]
pub fn exec_stm_observe_conflicts_per_block(conflicts: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_CONFLICTS_PER_BLOCK.observe(conflicts as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = conflicts;
    }
}

/// Helper: Observe STM retries per block (T82.0).
#[inline]
pub fn exec_stm_observe_retries_per_block(retries: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_RETRIES_PER_BLOCK.observe(retries as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = retries;
    }
}

/// Eagerly register T82.0 executor metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t82_exec_metrics() {
    let _ = &*EEZO_EXEC_STM_WAVES_TOTAL;
    let _ = &*EEZO_EXEC_STM_CONFLICTS_TOTAL;
    let _ = &*EEZO_EXEC_STM_RETRIES_TOTAL;
    let _ = &*EEZO_EXEC_STM_ABORTED_TOTAL;
    let _ = &*EEZO_EXEC_STM_WAVES_PER_BLOCK;
    let _ = &*EEZO_EXEC_STM_CONFLICTS_PER_BLOCK;
    let _ = &*EEZO_EXEC_STM_RETRIES_PER_BLOCK;
    // T82.4: Also register wave building and pre-screen metrics
    register_t82_4_wave_metrics();
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t82_exec_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T82.4 — Conflict-Aware STM Wave Building & Pre-Screening metrics
// -----------------------------------------------------------------------------
//
// These metrics track the performance of the T82.4 wave building optimization:
// - Waves built total (how many waves were formed)
// - Wave size distribution (histogram of txs per wave)
// - Pre-screen hits/misses (effectiveness of the bloom filter pre-screening)

/// Counter: Total number of STM waves built across all blocks.
/// This counts the number of waves formed by the wave builder, not retries.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_WAVES_BUILT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_stm_waves_built_total",
        "Total STM waves built across all blocks (T82.4)"
    )
    .unwrap()
});

/// Histogram: Distribution of transactions per wave.
/// Tracks how well the wave builder is packing non-conflicting txs together.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_WAVE_SIZE: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_stm_wave_size",
        "Distribution of transactions per wave (T82.4)",
        vec![1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0]
    )
    .unwrap()
});

/// Counter: Pre-screen indicated "may conflict" (bloom filter hit).
/// When this fires, we fall back to precise conflict detection.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_PRESCREEN_HITS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_stm_conflict_prescreen_hits_total",
        "Pre-screen indicated 'may conflict' - fell back to precise check (T82.4)"
    )
    .unwrap()
});

/// Counter: Pre-screen indicated "no conflict" (bloom filter miss).
/// The tx was safely added to the wave without precise conflict checking.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_PRESCREEN_MISSES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_stm_conflict_prescreen_misses_total",
        "Pre-screen indicated 'no conflict' - tx added to wave safely (T82.4)"
    )
    .unwrap()
});

/// Helper: Increment waves built counter (T82.4).
#[inline]
pub fn exec_stm_waves_built_inc(by: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_WAVES_BUILT_TOTAL.inc_by(by);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = by;
    }
}

/// Helper: Observe wave size (T82.4).
#[inline]
pub fn exec_stm_observe_wave_size(size: usize) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_WAVE_SIZE.observe(size as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = size;
    }
}

/// Helper: Increment pre-screen hits counter (T82.4).
#[inline]
pub fn exec_stm_prescreen_hit_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_PRESCREEN_HITS_TOTAL.inc();
    }
}

/// Helper: Increment pre-screen misses counter (T82.4).
#[inline]
pub fn exec_stm_prescreen_miss_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_PRESCREEN_MISSES_TOTAL.inc();
    }
}

/// Eagerly register T82.4 wave building metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t82_4_wave_metrics() {
    let _ = &*EEZO_EXEC_STM_WAVES_BUILT_TOTAL;
    let _ = &*EEZO_EXEC_STM_WAVE_SIZE;
    let _ = &*EEZO_EXEC_STM_PRESCREEN_HITS_TOTAL;
    let _ = &*EEZO_EXEC_STM_PRESCREEN_MISSES_TOTAL;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t82_4_wave_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T87.x — Deep Performance Pass Metrics
// -----------------------------------------------------------------------------
//
// These metrics track T87.x optimizations:
// - Wave build timing (how long to construct each wave)
// - Aggressive wave mode stats

/// Histogram: Time to build each wave (conflict detection phase).
/// This helps identify if wave building is a bottleneck.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_WAVE_BUILD_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_stm_wave_build_seconds",
        "Time to build/detect conflicts for each wave (seconds) (T87.x)",
        vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
    )
    .unwrap()
});

/// Gauge: Whether aggressive wave mode is enabled.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_WAVE_AGGRESSIVE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_exec_stm_wave_aggressive",
        "1 if aggressive wave grouping is enabled, 0 otherwise (T87.1)"
    )
    .unwrap()
});

/// Helper: Observe wave build time (T87.x).
#[inline]
pub fn exec_stm_observe_wave_build_seconds(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_WAVE_BUILD_SECONDS.observe(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

/// Helper: Set aggressive wave mode gauge (T87.1).
#[inline]
pub fn exec_stm_wave_aggressive_set(enabled: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_WAVE_AGGRESSIVE.set(if enabled { 1 } else { 0 });
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = enabled;
    }
}

/// Eagerly register T87.x deep perf metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t87_deep_perf_metrics() {
    let _ = &*EEZO_EXEC_STM_WAVE_BUILD_SECONDS;
    let _ = &*EEZO_EXEC_STM_WAVE_AGGRESSIVE;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t87_deep_perf_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T87.4 — Arena-Indexed STM Kernel Metrics
// -----------------------------------------------------------------------------
//
// These metrics track the T87.4 arena kernel performance:
// - Kernel mode (legacy vs arena)
// - Accounts loaded into arena per block
// - Time to build arena per block

/// Gauge: Current STM kernel mode (0=legacy, 1=arena).
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_KERNEL_MODE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_exec_stm_kernel_mode",
        "Current STM kernel mode: 0=legacy, 1=arena (T87.4)"
    )
    .unwrap()
});

/// Counter: Total accounts loaded into arena across all blocks.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_ARENA_ACCOUNTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_exec_stm_arena_accounts_total",
        "Total accounts loaded into arena across all blocks (T87.4)"
    )
    .unwrap()
});

/// Histogram: Time to build arena per block.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_ARENA_BUILD_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_exec_stm_arena_build_seconds",
        "Time to build arena per block (seconds) (T87.4)",
        vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
    )
    .unwrap()
});

/// Helper: Set STM kernel mode gauge (T87.4).
#[inline]
pub fn exec_stm_kernel_mode_set(is_arena: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_KERNEL_MODE.set(if is_arena { 1 } else { 0 });
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = is_arena;
    }
}

/// Helper: Increment arena accounts counter (T87.4).
#[inline]
pub fn exec_stm_arena_accounts_inc(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_ARENA_ACCOUNTS_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Observe arena build time (T87.4).
#[inline]
pub fn exec_stm_observe_arena_build_seconds(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_ARENA_BUILD_SECONDS.observe(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

/// Eagerly register T87.4 arena kernel metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t87_arena_kernel_metrics() {
    let _ = &*EEZO_EXEC_STM_KERNEL_MODE;
    let _ = &*EEZO_EXEC_STM_ARENA_ACCOUNTS_TOTAL;
    let _ = &*EEZO_EXEC_STM_ARENA_BUILD_SECONDS;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t87_arena_kernel_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T93.2 + T93.3 — Simple Transfer Fast Path Metrics
// -----------------------------------------------------------------------------
//
// ## T93.3 Semantic Invariants
//
// These metrics track per-transaction outcomes (not per-wave or per-lane):
//
// 1. `eezo_stm_simple_candidate_total`: Number of transactions classified as
//    SimpleTransfer by the analyzer. Incremented exactly once per tx at block
//    start when the tx is tagged AnalyzedTxKind::SimpleTransfer.
//
// 2. `eezo_stm_simple_fastpath_total`: Number of candidate txs that were
//    successfully executed via the fast path. Incremented once per tx when
//    it commits via the fast path.
//
// 3. `eezo_stm_simple_fallback_total`: Number of candidate txs that were
//    forced to fall back to the general STM path (e.g., conflict/scheduling
//    invariant violated during fast path wave). Incremented once per tx when
//    it ultimately commits via the general path.
//
// Expected invariants:
//   eezo_stm_simple_candidate_total ≈ eezo_stm_simple_fastpath_total + eezo_stm_simple_fallback_total
//   eezo_stm_simple_candidate_total <= eezo_txs_included_total
//
// All three are monotonic counters, updated in the executor flow to avoid
// double-counting.

/// Gauge: Simple fast path enabled (0=disabled, 1=enabled).
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_SIMPLE_FASTPATH_ENABLED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_exec_stm_simple_fastpath_enabled",
        "Simple transfer fast path: 0=disabled, 1=enabled (T93.2)"
    )
    .unwrap()
});

/// T93.3: Counter for transactions classified as SimpleTransfer by the analyzer.
/// Incremented exactly once per tx at block start when tagged as SimpleTransfer.
#[cfg(feature = "metrics")]
pub static EEZO_STM_SIMPLE_CANDIDATE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_stm_simple_candidate_total",
        "Transactions classified as SimpleTransfer by the analyzer (T93.3)"
    )
    .unwrap()
});

/// T93.3: Counter for candidate txs executed via the simple fast path.
/// Incremented once per tx when it successfully commits via fast path.
/// Invariant: fastpath + fallback ≈ candidate.
#[cfg(feature = "metrics")]
pub static EEZO_STM_SIMPLE_FASTPATH_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_stm_simple_fastpath_total",
        "Candidate txs successfully executed via the simple fast path (T93.3)"
    )
    .unwrap()
});

/// T93.3: Counter for candidate txs that fell back to the general STM path.
/// Incremented once per tx when it commits via the general path after being
/// unable to use the fast path (conflict/scheduling invariant violated).
/// Invariant: fastpath + fallback ≈ candidate.
#[cfg(feature = "metrics")]
pub static EEZO_STM_SIMPLE_FALLBACK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_stm_simple_fallback_total",
        "Candidate txs that fell back to the general STM path (T93.3)"
    )
    .unwrap()
});

/// Counter: Total CPU time spent in the simple fast path execution (seconds).
#[cfg(feature = "metrics")]
pub static EEZO_STM_SIMPLE_TIME_SECONDS: Lazy<Counter> = Lazy::new(|| {
    prometheus::register_counter!(
        "eezo_stm_simple_time_seconds",
        "Total CPU time spent in the simple fast path execution (T93.2)"
    )
    .unwrap()
});

/// Helper: Set simple fastpath enabled gauge (T93.2).
#[inline]
pub fn exec_stm_simple_fastpath_enabled_set(enabled: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_SIMPLE_FASTPATH_ENABLED.set(if enabled { 1 } else { 0 });
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = enabled;
    }
}

/// T93.3: Helper to increment simple candidate counter.
/// Called once per tx at block start when classified as SimpleTransfer.
#[inline]
pub fn stm_simple_candidate_inc(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_SIMPLE_CANDIDATE_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// T93.3: Helper to increment simple fastpath counter.
/// Called once per tx when it successfully commits via fast path.
#[inline]
pub fn stm_simple_fastpath_inc(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_SIMPLE_FASTPATH_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// T93.3: Helper to increment simple fallback counter.
/// Called once per tx when it commits via the general path after failing
/// to use the fast path.
#[inline]
pub fn stm_simple_fallback_inc(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_SIMPLE_FALLBACK_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Add to simple time seconds counter (T93.2).
#[inline]
pub fn stm_simple_time_add(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_SIMPLE_TIME_SECONDS.inc_by(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

// -----------------------------------------------------------------------------
// T95.0 — STM Conflict Pre-Screen Bitmap Metrics
// -----------------------------------------------------------------------------
//
// Track when the bitmap pre-screen falls back to HashMap due to arena indices
// exceeding the bitmap capacity (default 1024). A high fallback rate suggests
// increasing ARENA_BITMAP_CAPACITY.

/// Counter for bitmap fallback events (T95.0).
/// Incremented when an arena index exceeds the bitmap capacity and we must
/// use the HashMap fallback path.
#[cfg(feature = "metrics")]
pub static EEZO_STM_BITMAP_FALLBACK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    prometheus::register_int_counter!(
        "eezo_stm_bitmap_fallback_total",
        "Total times the STM conflict bitmap fell back to HashMap due to index overflow (T95.0)"
    )
    .unwrap()
});

/// T95.0: Helper to increment bitmap fallback counter.
/// Called when an arena index exceeds the bitmap capacity.
#[inline]
pub fn stm_bitmap_fallback_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_BITMAP_FALLBACK_TOTAL.inc();
    }
}

// -----------------------------------------------------------------------------
// T97.0 — Arc-Free Tx Handles Metrics
// -----------------------------------------------------------------------------
//
// Track Arc clones in the STM execution path. After T97.0 refactor, this should
// remain zero or near-zero during normal operation.

/// T97.0: Counter for Arc<SignedTx> clones in STM execution path.
/// Should be zero after T97.0 refactor is complete.
#[cfg(feature = "metrics")]
pub static EEZO_STM_TX_ARC_CLONES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    prometheus::register_int_counter!(
        "eezo_stm_tx_arc_clones_total",
        "Total Arc<SignedTx> clones in STM execution path (T97.0)"
    )
    .unwrap()
});

/// T97.0: Helper to increment Arc clone counter.
#[inline]
pub fn stm_tx_arc_clones_inc(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_TX_ARC_CLONES_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// T97.0: Counter for Account clones in STM execution path.
/// Tracks deep clones during speculative execution.
#[cfg(feature = "metrics")]
pub static EEZO_STM_ACCOUNT_CLONES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    prometheus::register_int_counter!(
        "eezo_stm_account_clones_total",
        "Total Account clones in STM execution path (T97.0)"
    )
    .unwrap()
});

/// T97.0: Helper to increment account clone counter.
#[inline]
pub fn stm_account_clones_inc(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_STM_ACCOUNT_CLONES_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Eagerly register T93.2/T93.3/T95.0/T97.0 simple fastpath metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t93_simple_fastpath_metrics() {
    let _ = &*EEZO_EXEC_STM_SIMPLE_FASTPATH_ENABLED;
    let _ = &*EEZO_STM_SIMPLE_CANDIDATE_TOTAL;
    let _ = &*EEZO_STM_SIMPLE_FASTPATH_TOTAL;
    let _ = &*EEZO_STM_SIMPLE_FALLBACK_TOTAL;
    let _ = &*EEZO_STM_SIMPLE_TIME_SECONDS;
    // T95.0: Bitmap fallback metric
    let _ = &*EEZO_STM_BITMAP_FALLBACK_TOTAL;
    // T97.0: Arc clone metrics
    let _ = &*EEZO_STM_TX_ARC_CLONES_TOTAL;
    let _ = &*EEZO_STM_ACCOUNT_CLONES_TOTAL;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t93_simple_fastpath_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T82.0 — CPU Profiling Hooks
// -----------------------------------------------------------------------------
//
// When EEZO_PROFILING=perf is set, the node runs with minimal extra overhead
// and is friendly to perf record / flamegraph tooling.
//
// The profiling mode is determined at startup by checking the environment.

/// Profiling mode configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilingMode {
    /// No profiling instrumentation
    Off,
    /// Perf-friendly mode with lightweight span markers
    Perf,
}

impl Default for ProfilingMode {
    fn default() -> Self {
        ProfilingMode::Off
    }
}

impl ProfilingMode {
    /// Parse profiling mode from the EEZO_PROFILING environment variable.
    /// - "perf" or "1" enables perf-friendly mode
    /// - Any other value or unset means profiling is off
    pub fn from_env() -> Self {
        match std::env::var("EEZO_PROFILING")
            .unwrap_or_else(|_| "off".to_string())
            .to_lowercase()
            .as_str()
        {
            "perf" | "1" | "true" | "on" => ProfilingMode::Perf,
            _ => ProfilingMode::Off,
        }
    }

    /// Check if profiling is enabled
    pub fn is_enabled(&self) -> bool {
        !matches!(self, ProfilingMode::Off)
    }
}

/// Global profiling mode (set once at startup).
/// Thread-safe via atomic loading in PROFILING_MODE_CACHE.
static PROFILING_MODE_CACHE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Initialize profiling mode from environment. Should be called once at startup.
pub fn init_profiling_mode() {
    let mode = ProfilingMode::from_env();
    let val = match mode {
        ProfilingMode::Off => 0,
        ProfilingMode::Perf => 1,
    };
    PROFILING_MODE_CACHE.store(val, std::sync::atomic::Ordering::Relaxed);
    
    if mode.is_enabled() {
        log::info!("T82.0: Profiling mode enabled (EEZO_PROFILING=perf). \
                   Node is perf/flamegraph friendly.");
    }
}

/// Get the current profiling mode.
/// 
/// This function is part of T82.0's profiling infrastructure. It returns the current
/// profiling mode (Off or Perf) based on the EEZO_PROFILING environment variable.
/// 
/// The profiling mode is used to enable perf/flamegraph-friendly behavior when
/// profiling is requested. Currently, enabling profiling mode just logs a message;
/// future tasks (T82.1+) may add explicit span markers in hot paths.
#[inline]
#[allow(dead_code)] // Available for use in profiling spans when needed
pub fn profiling_mode() -> ProfilingMode {
    match PROFILING_MODE_CACHE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => ProfilingMode::Perf,
        _ => ProfilingMode::Off,
    }
}

/// Lightweight profiling span marker.
/// When profiling is enabled, this creates a named span that helps attribute
/// CPU time in perf/flamegraph output. When disabled, this is a no-op.
///
/// This macro is part of T82.0's profiling infrastructure. It can be added to hot paths
/// (STM execute, sig verification, DAG ordering) to help perf/flamegraph attribute time.
/// The macro is currently available but not yet placed in hot paths - future work (T82.1+)
/// may add explicit spans if profiling shows value in having them.
///
/// Usage:
/// ```ignore
/// let _span = profiling_span!("stm_execute");
/// // ... hot code ...
/// // span ends when _span drops
/// ```
#[macro_export]
macro_rules! profiling_span {
    ($name:expr) => {{
        // When profiling is enabled, we use a scope guard that does minimal work.
        // The function name appears in stack traces for perf/flamegraph attribution.
        struct ProfilingSpan;
        impl Drop for ProfilingSpan {
            #[inline(never)]
            fn drop(&mut self) {
                // Force this function to appear in stack traces
                std::hint::black_box(());
            }
        }
        
        #[inline(never)]
        fn create_span() -> ProfilingSpan {
            // This function name helps with perf attribution
            std::hint::black_box(());
            ProfilingSpan
        }
        
        if $crate::metrics::profiling_mode().is_enabled() {
            Some(create_span())
        } else {
            None
        }
    }};
}

// Re-export the macro for use in other modules. Currently available but not yet
// placed in hot paths; can be added during T82.1+ profiling work if needed.
#[allow(unused_imports)]
pub use profiling_span;

// =============================================================================
// T91.2 — CUDA BLAKE3 Shadow Path Metrics
// =============================================================================
//
// These metrics track the T91.2 CUDA hash shadow path:
// - eezo_cuda_hash_enabled: gauge (0/1) indicating CUDA hash engine availability
// - eezo_cuda_hash_jobs_total: counter of successful CUDA hash batch calls
// - eezo_cuda_hash_failures_total: counter of CUDA initialization or compute failures
// - eezo_cuda_hash_bytes_total: counter of total bytes hashed via CUDA
// - eezo_cuda_hash_mismatch_total: counter of CUDA/CPU hash mismatches

/// T91.2: Gauge indicating whether CUDA hash engine was successfully initialized.
/// Value: 0 = CUDA unavailable/disabled/init failed, 1 = CUDA successfully initialized.
#[cfg(feature = "metrics")]
pub static EEZO_CUDA_HASH_ENABLED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_cuda_hash_enabled",
        "Whether CUDA hash engine was successfully initialized (0=no, 1=yes)"
    )
    .unwrap()
});

/// T91.2: Counter of successful CUDA hash batch calls.
#[cfg(feature = "metrics")]
pub static EEZO_CUDA_HASH_JOBS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_cuda_hash_jobs_total",
        "Total number of successful CUDA hash batch calls"
    )
    .unwrap()
});

/// T91.2: Counter of CUDA hash failures (init or compute).
#[cfg(feature = "metrics")]
pub static EEZO_CUDA_HASH_FAILURES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_cuda_hash_failures_total",
        "Total number of CUDA hash failures (init or compute)"
    )
    .unwrap()
});

/// T91.2: Counter of total bytes hashed via CUDA.
#[cfg(feature = "metrics")]
pub static EEZO_CUDA_HASH_BYTES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_cuda_hash_bytes_total",
        "Total bytes hashed via CUDA"
    )
    .unwrap()
});

/// T91.2: Counter of CUDA/CPU hash mismatches detected.
#[cfg(feature = "metrics")]
pub static EEZO_CUDA_HASH_MISMATCH_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_cuda_hash_mismatch_total",
        "Total CUDA/CPU hash mismatches detected (CUDA disagrees with CPU)"
    )
    .unwrap()
});

/// T91.2: Helper to set the CUDA hash enabled gauge.
#[inline]
pub fn cuda_hash_enabled_set(val: i64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_CUDA_HASH_ENABLED.set(val);
    }
    let _ = val;
}

/// T91.2: Helper to increment CUDA hash jobs counter.
#[inline]
pub fn cuda_hash_jobs_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_CUDA_HASH_JOBS_TOTAL.inc();
    }
}

/// T91.2: Helper to increment CUDA hash failures counter.
#[inline]
pub fn cuda_hash_failures_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_CUDA_HASH_FAILURES_TOTAL.inc();
    }
}

/// T91.2: Helper to increment CUDA hash bytes counter.
#[inline]
pub fn cuda_hash_bytes_inc(bytes: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_CUDA_HASH_BYTES_TOTAL.inc_by(bytes);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = bytes;
    }
}

/// T91.2: Helper to increment CUDA/CPU mismatch counter.
#[inline]
pub fn cuda_hash_mismatch_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_CUDA_HASH_MISMATCH_TOTAL.inc();
    }
}

/// T91.2: Eagerly register CUDA hash metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t91_cuda_hash_metrics() {
    let _ = &*EEZO_CUDA_HASH_ENABLED;
    let _ = &*EEZO_CUDA_HASH_JOBS_TOTAL;
    let _ = &*EEZO_CUDA_HASH_FAILURES_TOTAL;
    let _ = &*EEZO_CUDA_HASH_BYTES_TOTAL;
    let _ = &*EEZO_CUDA_HASH_MISMATCH_TOTAL;
}

/// T91.2: No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t91_cuda_hash_metrics() {
    // No metrics to register when the feature is off.
}

// =============================================================================
// T92.0 — Hash vs Executor Profiling Metrics
// =============================================================================
//
// These metrics track CPU time spent in:
// - BLAKE3 consensus-related hashing (tx hashes, block body hashes)
// - STM executor runs (block execution)
//
// This enables profiling under load to identify bottlenecks.

/// T92.0: Counter for total CPU time (seconds) spent in consensus-related BLAKE3 hashing.
#[cfg(feature = "metrics")]
pub static EEZO_HASH_CPU_TIME_SECONDS: Lazy<Counter> = Lazy::new(|| {
    prometheus::register_counter!(
        "eezo_hash_cpu_time_seconds",
        "Total CPU time (seconds) spent in consensus-related BLAKE3 hashing"
    )
    .unwrap()
});

/// T92.0: Counter for total CPU time (seconds) spent in STM executor runs.
#[cfg(feature = "metrics")]
pub static EEZO_EXEC_STM_TIME_SECONDS: Lazy<Counter> = Lazy::new(|| {
    prometheus::register_counter!(
        "eezo_exec_stm_time_seconds",
        "Total CPU time (seconds) spent in STM executor runs executed by consensus"
    )
    .unwrap()
});

/// T92.0: Helper to increment the hash CPU time counter.
#[inline]
pub fn hash_cpu_time_inc(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_HASH_CPU_TIME_SECONDS.inc_by(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

/// T92.0: Helper to increment the STM executor time counter.
#[inline]
pub fn exec_stm_time_inc(seconds: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_EXEC_STM_TIME_SECONDS.inc_by(seconds);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = seconds;
    }
}

/// T92.0: Eagerly register profiling metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t92_perf_metrics() {
    let _ = &*EEZO_HASH_CPU_TIME_SECONDS;
    let _ = &*EEZO_EXEC_STM_TIME_SECONDS;
}

/// T92.0: No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t92_perf_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T94.0 — Block Packing & DAG Tick Tuning Metrics
// -----------------------------------------------------------------------------

/// T94.0: Counter for early tick events (when we trigger block building before
/// the full tick interval expires due to mempool backlog).
#[cfg(feature = "metrics")]
pub static EEZO_T94_EARLY_TICK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_t94_early_tick_total",
        "Number of early tick events (block built before tick expired due to mempool backlog)"
    )
    .expect("register eezo_t94_early_tick_total")
});

/// T94.0: Increment the early tick counter.
#[inline]
pub fn t94_early_tick_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_T94_EARLY_TICK_TOTAL.inc();
    }
}

/// T94.0: Gauge for block packing mode (0 = conservative, 1 = aggressive).
#[cfg(feature = "metrics")]
pub static EEZO_T94_BLOCK_PACKING_MODE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_t94_block_packing_mode",
        "Block packing mode (0 = conservative, 1 = aggressive)"
    )
    .expect("register eezo_t94_block_packing_mode")
});

/// T94.0: Set block packing mode gauge.
#[inline]
pub fn t94_block_packing_mode_set(is_aggressive: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_T94_BLOCK_PACKING_MODE.set(if is_aggressive { 1 } else { 0 });
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = is_aggressive;
    }
}

/// T94.0: Gauge for perf mode enabled status (0 = disabled, 1 = enabled).
#[cfg(feature = "metrics")]
pub static EEZO_T94_PERF_MODE_ENABLED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_t94_perf_mode_enabled",
        "Perf mode enabled (0 = disabled, 1 = enabled)"
    )
    .expect("register eezo_t94_perf_mode_enabled")
});

/// T94.0: Set perf mode gauge.
#[inline]
pub fn t94_perf_mode_set(enabled: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_T94_PERF_MODE_ENABLED.set(if enabled { 1 } else { 0 });
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = enabled;
    }
}

/// T94.0: Eagerly register T94 block packing metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t94_block_packing_metrics() {
    let _ = &*EEZO_T94_EARLY_TICK_TOTAL;
    let _ = &*EEZO_T94_BLOCK_PACKING_MODE;
    let _ = &*EEZO_T94_PERF_MODE_ENABLED;
}

/// T94.0: No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t94_block_packing_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T96.0 — Real DAG Ordering + Better Block Packing Metrics
// -----------------------------------------------------------------------------
//
// These metrics track the new T96.0 DAG ordering mode:
// - eezo_dag_ordering_enabled: Gauge showing if ordering is on (0/1)
// - eezo_dag_ordered_txs_total: Counter of txs ordered via DAG
// - eezo_dag_ordering_fallback_total: Counter of fallback events
// - eezo_dag_block_tx_per_block_hist: Histogram of txs per block with DAG ordering

/// Gauge: DAG ordering mode enabled (0=off, 1=on).
/// Updated at startup and reflects EEZO_DAG_ORDERING_ENABLED config.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_ORDERING_ENABLED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_dag_ordering_enabled",
        "Whether DAG ordering mode is enabled (0=off, 1=on) (T96.0)"
    )
    .unwrap()
});

/// Counter: Total transactions ordered via the DAG ordering path.
/// Incremented when blocks are built using DAG-ordered tx sequences.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_ORDERED_TXS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_ordered_txs_total",
        "Total txs ordered via DAG ordering path (T96.0)"
    )
    .unwrap()
});

/// Counter: Total fallback events when DAG ordering is enabled but unavailable.
/// Incremented when DAG ordering is enabled but falls back to mempool for a block.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_ORDERING_FALLBACK_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_ordering_fallback_total",
        "Total fallback events from DAG ordering to mempool (T96.0)"
    )
    .unwrap()
});

/// Histogram: Txs per block when DAG ordering is enabled.
/// Useful for tracking block packing efficiency with DAG ordering.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_BLOCK_TX_PER_BLOCK_HIST: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_dag_block_tx_per_block_hist",
        "Histogram of txs per block with DAG ordering (T96.0)",
        vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2000.0]
    )
    .unwrap()
});

/// Histogram: Nonce span of txs in a DAG-ordered block.
/// Lower values indicate better nonce contiguity.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_NONCE_SPAN_HIST: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_dag_nonce_span_hist",
        "Histogram of avg nonce span per block with DAG ordering (T96.0)",
        vec![0.0, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0]
    )
    .unwrap()
});

/// Counter: Simple transfer candidates (txs classified for fast path) via DAG ordering.
#[cfg(feature = "metrics")]
pub static EEZO_DAG_FASTPATH_CANDIDATES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_dag_fastpath_candidates_total",
        "Total simple transfer candidates in DAG-ordered batches (T96.0)"
    )
    .unwrap()
});

/// Helper: Set DAG ordering enabled gauge.
#[inline]
pub fn dag_ordering_enabled_set(enabled: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_ORDERING_ENABLED.set(if enabled { 1 } else { 0 });
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = enabled;
    }
}

/// Helper: Increment DAG ordered txs counter.
#[inline]
pub fn dag_ordered_txs_inc(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_ORDERED_TXS_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Helper: Increment DAG ordering fallback counter.
#[inline]
pub fn dag_ordering_fallback_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_ORDERING_FALLBACK_TOTAL.inc();
    }
}

/// Helper: Observe txs per block with DAG ordering.
#[inline]
pub fn dag_block_tx_per_block_observe(tx_count: usize) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_BLOCK_TX_PER_BLOCK_HIST.observe(tx_count as f64);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = tx_count;
    }
}

/// Helper: Observe avg nonce span for DAG-ordered block.
#[inline]
pub fn dag_nonce_span_observe(avg_span: f64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_NONCE_SPAN_HIST.observe(avg_span);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = avg_span;
    }
}

/// Helper: Increment fast path candidates counter.
#[inline]
pub fn dag_fastpath_candidates_inc(count: u64) {
    #[cfg(feature = "metrics")]
    {
        EEZO_DAG_FASTPATH_CANDIDATES_TOTAL.inc_by(count);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = count;
    }
}

/// Eagerly register T96.0 DAG ordering metrics so they appear on /metrics at boot.
#[cfg(feature = "metrics")]
pub fn register_t96_dag_ordering_metrics() {
    let _ = &*EEZO_DAG_ORDERING_ENABLED;
    let _ = &*EEZO_DAG_ORDERED_TXS_TOTAL;
    let _ = &*EEZO_DAG_ORDERING_FALLBACK_TOTAL;
    let _ = &*EEZO_DAG_BLOCK_TX_PER_BLOCK_HIST;
    let _ = &*EEZO_DAG_NONCE_SPAN_HIST;
    let _ = &*EEZO_DAG_FASTPATH_CANDIDATES_TOTAL;
}

/// No-op version when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn register_t96_dag_ordering_metrics() {
    // No metrics to register when the feature is off.
}

// -----------------------------------------------------------------------------
// T82.0 — Unit tests for ProfilingMode
// -----------------------------------------------------------------------------
#[cfg(test)]
mod t82_tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to serialize env var access across tests
    static T82_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_profiling_mode_default_is_off() {
        assert_eq!(ProfilingMode::default(), ProfilingMode::Off);
    }

    #[test]
    fn test_profiling_mode_is_enabled() {
        assert!(!ProfilingMode::Off.is_enabled());
        assert!(ProfilingMode::Perf.is_enabled());
    }

    #[test]
    fn test_profiling_mode_from_env_off() {
        let _guard = T82_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        std::env::remove_var("EEZO_PROFILING");
        assert_eq!(ProfilingMode::from_env(), ProfilingMode::Off);
        
        std::env::set_var("EEZO_PROFILING", "off");
        assert_eq!(ProfilingMode::from_env(), ProfilingMode::Off);
        
        std::env::set_var("EEZO_PROFILING", "disabled");
        assert_eq!(ProfilingMode::from_env(), ProfilingMode::Off);
        
        std::env::remove_var("EEZO_PROFILING");
    }

    #[test]
    fn test_profiling_mode_from_env_perf() {
        let _guard = T82_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        std::env::set_var("EEZO_PROFILING", "perf");
        assert_eq!(ProfilingMode::from_env(), ProfilingMode::Perf);
        
        std::env::set_var("EEZO_PROFILING", "PERF");
        assert_eq!(ProfilingMode::from_env(), ProfilingMode::Perf);
        
        std::env::set_var("EEZO_PROFILING", "1");
        assert_eq!(ProfilingMode::from_env(), ProfilingMode::Perf);
        
        std::env::set_var("EEZO_PROFILING", "true");
        assert_eq!(ProfilingMode::from_env(), ProfilingMode::Perf);
        
        std::env::set_var("EEZO_PROFILING", "on");
        assert_eq!(ProfilingMode::from_env(), ProfilingMode::Perf);
        
        std::env::remove_var("EEZO_PROFILING");
    }
}