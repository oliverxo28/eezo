use once_cell::sync::Lazy;
use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, HistogramVec, IntCounter, IntCounterVec, IntGauge,
};
// only needed when `state-sync` metrics are compiled
#[cfg(feature = "state-sync")]
use prometheus::register_histogram;
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
    #[cfg(feature = "metrics")]
    {
        HTTP_REQS
            .with_label_values(&[route, &status.to_string()])
            .inc();
    }
    #[cfg(not(feature = "metrics"))]
    { let _ = (route, status); }
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
pub static EEZO_MEMPOOL_LEN: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("eezo_mempool_len", "Current mempool length").unwrap()
});

pub static EEZO_MEMPOOL_BYTES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("eezo_mempool_bytes_gauge", "Current bytes in mempool").unwrap()
});

// T32 schema anchors (lower-case names)
pub static EEZO_BLOCK_E2E_LATENCY_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "eezo_block_e2e_latency_seconds",
        "End-to-end block latency segmented by stage",
        &["stage"] // e.g., "assemble" | "validate" | "commit"
    )
    .unwrap()
});

pub static EEZO_TX_REJECTED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "eezo_tx_rejected_total",
        "Rejected transactions by reason",
        &["reason"] // e.g., "bad_sig" | "nonce" | "insufficient_funds" | "decoding"
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
pub static STATE_SYNC_DELTA_V2_SSZ_SERVE_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_delta_v2_ssz_serve_total",
        "Number of SSZ2D delta manifests served"
    )
    .expect("metric registered")
});

#[cfg(feature = "metrics")]
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
    #[cfg(feature = "metrics")]
    {
        EEZO_BRIDGE_HEADERS_SERVED_TOTAL
            .with_label_values(&[route])
            .inc();
    }
    #[cfg(not(feature = "metrics"))]
    { let _ = route; }
}

/// Helper: set last-served gauge *monotonically* (T37).
#[inline]
pub fn bridge_last_served_set(h: u64) {
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
    #[cfg(not(feature = "metrics"))]
    { let _ = h; }
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
    #[cfg(not(feature = "metrics"))]
    { let _ = h; } // Avoid unused warning
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
pub fn suite_rotation_inc() {
    #[cfg(feature = "metrics")]
    {
        EEZO_SUITE_ROTATION_TOTAL.inc();
    }
}

