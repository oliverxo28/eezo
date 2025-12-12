// crates/ledger/src/metrics.rs

use once_cell::sync::Lazy;
use prometheus::{
    register_histogram, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
};

//
// Batch-verify + supply metrics
//

#[cfg(feature = "metrics")]
pub static VERIFY_BATCH_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_ledger_verify_batch_total",
        "Total batch verify invocations"
    )
    .unwrap()
});

pub static VERIFY_BATCH_OK: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_ledger_verify_batch_ok",
        "Batches with all signatures valid"
    )
    .unwrap()
});

pub static VERIFY_BATCH_FAIL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_ledger_verify_batch_fail",
        "Batches with one or more invalid signatures"
    )
    .unwrap()
});

pub static VERIFY_BATCH_DURATION: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_ledger_verify_batch_duration_seconds",
        "Time to verify a batch of consensus signatures"
    )
    .unwrap()
});

pub static SUPPLY_NATIVE_MINT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("supply_native_mint_total", "Total native mints (units)").unwrap()
});

pub static SUPPLY_BRIDGE_MINT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("supply_bridge_mint_total", "Total bridge mints (units)").unwrap()
});

pub static SUPPLY_BURN_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("supply_burn_total", "Total burns (units)").unwrap());

pub static SUPPLY_CIRCULATING: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("supply_circulating", "Circulating supply (units)").unwrap());

/// Observe a batch verify event (counts + duration timer).
pub fn observe_batch(ok: usize, fail: usize, _dur_ms: f64) {
    let _t = VERIFY_BATCH_DURATION.start_timer();
    VERIFY_BATCH_OK.inc_by(ok as u64);
    VERIFY_BATCH_FAIL.inc_by(fail as u64);
    drop(_t);
}

/// Update circulating supply gauge.
#[inline]
pub fn observe_supply(s: &crate::Supply) {
    let circ = s.circulating();
    SUPPLY_CIRCULATING.set(circ as i64);
}

//
// Block-level counters used by consensus.rs (T11)
//

/// Total number of blocks proposed by this node (or process).
pub static BLOCK_PROPOSED_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("block_proposed_total", "Blocks proposed").unwrap());

/// Total number of blocks successfully applied to state.
pub static BLOCK_APPLIED_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter!("block_applied_total", "Blocks applied").unwrap());

/// Total transactions included across all applied (or proposed) blocks.
pub static TXS_INCLUDED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("eezo_txs_included_total", "Transactions included in blocks").unwrap()
});

/// Transactions rejected during assembly/validation (ledger-side).
/// Kept separate from node/executor metrics to avoid name collisions.
pub static TXS_REJECTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_ledger_txs_rejected_total",
        "Transactions rejected during ledger assembly/validation"
    )
    .unwrap()
});

/// Sum of fees collected across all blocks (atoms / smallest unit).
pub static FEES_COLLECTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("fees_collected_total", "Total fees collected (atoms)").unwrap()
});

// NEW: block byte budget observability
pub static BLOCK_BYTES_USED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "block_bytes_used",
        "Total bytes of txs included in blocks (sum across all blocks)"
    )
    .unwrap()
});

pub static BLOCK_BYTES_WASTED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "block_bytes_wasted",
        "Total unutilized budget bytes across blocks (budget - used)"
    )
    .unwrap()
});

/// Current block transaction count (last assembled block).
pub static BLOCK_TX_COUNT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "eezo_block_tx_count",
        "Number of transactions included in the last built block"
    )
    .unwrap()
});

/// Convenience: call when a block has been assembled/proposed (before apply).
#[inline]
pub fn observe_block_proposed(tx_count: u32, fee_total_atoms: u64) {
    BLOCK_PROPOSED_TOTAL.inc();
    BLOCK_TX_COUNT.set(tx_count as i64);
    TXS_INCLUDED_TOTAL.inc_by(tx_count as u64);
    FEES_COLLECTED_TOTAL.inc_by(fee_total_atoms);
}

/// Convenience: bump rejected txs (call from assembly/validation paths as needed).
#[inline]
pub fn inc_txs_rejected(count: u64) {
    TXS_REJECTED_TOTAL.inc_by(count);
}

/// Convenience: call after a block has been successfully applied to state.
#[inline]
pub fn observe_block_applied() {
    BLOCK_APPLIED_TOTAL.inc();
}

//
// New latency histograms for PR#2
//

/// Buckets for latency histograms in milliseconds.
fn ms_buckets() -> Vec<f64> {
    vec![1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0]
}

/// Histogram for block proposal latency in milliseconds.
pub static BLOCK_PROPOSAL_DUR_MS: Lazy<Histogram> = Lazy::new(|| {
    let opts = HistogramOpts::new("block_proposal_duration_ms", "Proposal latency (ms)")
        .buckets(ms_buckets());
    register_histogram!(opts).unwrap()
});

/// Histogram for block validation latency in milliseconds.
pub static VALIDATION_DUR_MS: Lazy<Histogram> = Lazy::new(|| {
    let opts = HistogramOpts::new("validation_duration_ms", "Full validation latency (ms)")
        .buckets(ms_buckets());
    register_histogram!(opts).unwrap()
});

/// Histogram for state apply latency in milliseconds.
pub static STATE_APPLY_DUR_MS: Lazy<Histogram> = Lazy::new(|| {
    let opts = HistogramOpts::new("state_apply_duration_ms", "State apply latency (ms)")
        .buckets(ms_buckets());
    register_histogram!(opts).unwrap()
});

/// Start a timer for block proposal latency.
#[inline]
pub fn start_proposal_timer() -> impl Drop {
    BLOCK_PROPOSAL_DUR_MS.start_timer()
}

/// Start a timer for block validation latency.
#[inline]
pub fn start_validation_timer() -> impl Drop {
    VALIDATION_DUR_MS.start_timer()
}

/// Start a timer for state apply latency.
#[inline]
pub fn start_apply_timer() -> impl Drop {
    STATE_APPLY_DUR_MS.start_timer()
}

// NEW — persistence I/O timing
#[cfg(feature = "metrics")]
pub static PERSIST_WRITE_DUR_MS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "persistence_write_duration_ms",
        "Total ms spent persisting blocks/headers to storage"
    )
    .unwrap()
});

#[cfg(feature = "metrics")]
pub static PERSIST_READ_DUR_MS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "persistence_read_duration_ms",
        "Total ms spent reading blocks/headers from storage"
    )
    .unwrap()
});

#[cfg(feature = "metrics")]
pub static RECOVERY_DUR_MS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "recovery_duration_ms",
        "Total ms spent on cold-start recovery"
    )
    .unwrap()
});

// --- T15.2 metrics ---
#[cfg(feature = "metrics")]
pub static SNAPSHOT_COUNT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("snapshot_count_total", "Number of state snapshots taken").unwrap()
});

#[cfg(feature = "metrics")]
pub static REPLAY_BLOCKS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("replay_blocks_total", "Blocks replayed during recovery").unwrap()
});

#[cfg(feature = "metrics")]
pub static STATE_SIZE_BYTES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "state_size_bytes",
        "Serialized size of the latest state snapshot in bytes"
    )
    .unwrap()
});

// --- T17.1 additions ---
pub static HIGHEST_QC_HEIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "highest_qc_height",
        "Highest known justified/committed height"
    )
    .unwrap()
});

pub static COMMIT_LATENCY_MS: Lazy<Histogram> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "commit_latency_ms",
        "Time from block timestamp to commit (ms)",
    )
    .buckets(ms_buckets());
    register_histogram!(opts).unwrap()
});

pub static QC_VERIFY_DUR_MS: Lazy<Histogram> = Lazy::new(|| {
    let opts = HistogramOpts::new("qc_verify_duration_ms", "QC verification duration (ms)")
        .buckets(ms_buckets());
    register_histogram!(opts).unwrap()
});

// --- Checkpoint metrics ---
#[cfg(all(feature = "metrics", feature = "checkpoints"))]
static CHECKPOINT_CANDIDATES: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "checkpoint_candidates_total",
        "Heights that hit the checkpoint interval (candidates for QC emission)."
    )
    .expect("register checkpoint_candidates_total")
});

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
#[inline]
pub fn inc_checkpoint_candidate() {
    CHECKPOINT_CANDIDATES.inc();
}

#[cfg(feature = "metrics")]
pub fn set_highest_qc_height(h: u64) {
    HIGHEST_QC_HEIGHT.set(h as i64);
}

#[cfg(not(feature = "metrics"))]
pub fn set_highest_qc_height(_h: u64) {}

#[cfg(feature = "metrics")]
pub fn observe_commit_latency_ms(ms: u64) {
    COMMIT_LATENCY_MS.observe(ms as f64);
}

#[cfg(not(feature = "metrics"))]
pub fn observe_commit_latency_ms(_ms: u64) {}

#[cfg(feature = "metrics")]
pub fn observe_qc_verify_duration_ms(ms: u64) {
    QC_VERIFY_DUR_MS.observe(ms as f64);
}

#[cfg(not(feature = "metrics"))]
pub fn observe_qc_verify_duration_ms(_ms: u64) {}
// --- end T17.1 additions ---

// --- QC attached (stub) ---
#[cfg(all(feature = "metrics", feature = "checkpoints"))]
static QC_ATTACHED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "qc_attached_total",
        "Times we attached a (stub) QC hash to a committed block header."
    )
    .expect("register qc_attached_total")
});

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
#[inline]
pub fn inc_qc_attached() {
    QC_ATTACHED_TOTAL.inc();
}

// ── T41.3: qc_sidecar_v2 observability ─────────────────────────────────────
#[cfg(all(feature = "metrics", feature = "checkpoints"))]
pub static EEZO_QC_SIDECAR_V2_SEEN_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_seen_total",
        "qc_sidecar_v2 payloads encountered (any reason)"
    )
    .expect("register eezo_qc_sidecar_v2_seen_total")
});

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
pub static EEZO_QC_SIDECAR_V2_VALID_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_valid_total",
        "qc_sidecar_v2 payloads passing reader-side validation"
    )
    .expect("register eezo_qc_sidecar_v2_valid_total")
});

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
pub static EEZO_QC_SIDECAR_V2_INVALID_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_invalid_total",
        "qc_sidecar_v2 payloads failing reader-side validation"
    )
    .expect("register eezo_qc_sidecar_v2_invalid_total")
});

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
pub static EEZO_QC_SIDECAR_V2_MISSING_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_missing_total",
        "qc_sidecar_v2 payloads missing at required checkpoints (cutover+1)"
    )
    .expect("register eezo_qc_sidecar_v2_missing_total")
});

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
pub static EEZO_QC_SIDECAR_V2_REJECTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_qc_sidecar_v2_rejected_total",
        "checkpoints rejected because of qc_sidecar_v2 enforcement"
    )
    .expect("register eezo_qc_sidecar_v2_rejected_total")
});

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
#[inline]
pub fn inc_sidecar_seen() {
    EEZO_QC_SIDECAR_V2_SEEN_TOTAL.inc();
}

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
#[inline]
pub fn inc_sidecar_valid() {
    EEZO_QC_SIDECAR_V2_VALID_TOTAL.inc();
}

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
#[inline]
pub fn inc_sidecar_invalid() {
    EEZO_QC_SIDECAR_V2_INVALID_TOTAL.inc();
}

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
#[inline]
pub fn inc_sidecar_missing() {
    EEZO_QC_SIDECAR_V2_MISSING_TOTAL.inc();
}

#[cfg(all(feature = "metrics", feature = "checkpoints"))]
#[inline]
pub fn inc_sidecar_rejected() {
    EEZO_QC_SIDECAR_V2_REJECTED_TOTAL.inc();
}

// ── T85.0: HotStuff consensus metrics have been removed ──────────────────────
// EEZO's consensus is now DAG-only. The following HotStuff-specific metrics
// have been removed:
// - CONSENSUS_PROPOSALS_TOTAL
// - CONSENSUS_VOTES_PREPARE
// - CONSENSUS_VOTES_PRECOMMIT
// - CONSENSUS_VOTES_COMMIT
// - CONSENSUS_QC_FORMED_TOTAL
// - CONSENSUS_VIEW
// - CONSENSUS_COMMIT_HEIGHT
// See book/src/t81_consensus_history.md for historical context.

// ── T32: Unified SLO/observability schema (lowercase, works across crates) ─────────
// These are *additional* metrics; they do not replace your existing ones.
// We keep names lowercase to match your house style and Prometheus conventions.

/// End-to-end block latency segmented by stage (assemble|validate|commit).
pub static EEZO_BLOCK_E2E_LATENCY_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "eezo_block_e2e_latency_seconds",
        "End-to-end block latency segmented by stage",
        &["stage"]
    )
    .unwrap()
});

/// Per-transaction verification timings (decode|sig|apply).
pub static EEZO_TX_VERIFY_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "eezo_tx_verify_seconds",
        "Per-transaction verification timings",
        &["phase"]
    )
    .unwrap()
});

/// Total number of Quorum Certificates formed (aggregate).
pub static EEZO_QC_FORMED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("eezo_qc_formed_total", "Total quorum certificates formed").unwrap()
});

/// Current committed chain height (gauge form for dashboards).
pub static EEZO_CHAIN_HEIGHT_GAUGE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("eezo_chain_height_gauge", "Current committed chain height").unwrap()
});

/// Duration to apply one state-sync page.
pub static EEZO_STATE_SYNC_PAGE_APPLY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_state_sync_page_apply_seconds",
        "Duration to apply one state-sync page"
    )
    .unwrap()
});

/// Total bootstrap duration observed on the client.
pub static EEZO_STATE_BOOTSTRAP_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_state_bootstrap_seconds",
        "Total bootstrap duration (client side)"
    )
    .unwrap()
});

/// Number of state-sync pages applied (counter).
pub static EEZO_STATE_SYNC_PAGES_APPLIED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_state_sync_pages_applied_total",
        "Number of state-sync pages applied"
    )
    .unwrap()
});

/// Duration to apply a checkpoint.
pub static EEZO_CHECKPOINT_APPLY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "eezo_checkpoint_apply_seconds",
        "Duration to apply a checkpoint"
    )
    .unwrap()
});

/// Total checkpoints written to storage.
pub static EEZO_CHECKPOINTS_WRITTEN_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_checkpoints_written_total",
        "Total checkpoints written to storage"
    )
    .unwrap()
});

// =========================================================================
// T77.SAFE-3: Mempool TTL metrics
// =========================================================================

/// T77.SAFE-3: Counter for transactions expired due to TTL.
/// This metric tracks the number of transactions dropped from the mempool
/// because they exceeded the configured TTL (EEZO_MEMPOOL_TTL_SECS).
pub static EEZO_MEMPOOL_EXPIRED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "eezo_mempool_expired_total",
        "Number of transactions dropped from mempool due to TTL expiry (T77.SAFE-3)"
    )
    .unwrap()
});

/// T77.SAFE-3: Convenience function to increment the expired counter.
#[inline]
pub fn inc_mempool_expired(count: u64) {
    EEZO_MEMPOOL_EXPIRED_TOTAL.inc_by(count);
}

/// Force registration so names appear on /metrics even before first use.
pub fn register_t32_metrics() {
    // For HistogramVec we must create labeled children so families appear.
    // These labels match how we actually use them in consensus / tx paths.

    // block e2e latency: assemble | validate | commit
    let _ = EEZO_BLOCK_E2E_LATENCY_SECONDS.with_label_values(&["assemble"]);
    let _ = EEZO_BLOCK_E2E_LATENCY_SECONDS.with_label_values(&["validate"]);
    let _ = EEZO_BLOCK_E2E_LATENCY_SECONDS.with_label_values(&["commit"]);

    // tx verify timings: decode | sig | apply
    let _ = EEZO_TX_VERIFY_SECONDS.with_label_values(&["decode"]);
    let _ = EEZO_TX_VERIFY_SECONDS.with_label_values(&["sig"]);
    let _ = EEZO_TX_VERIFY_SECONDS.with_label_values(&["apply"]);

    // Simple, unlabeled metrics: touching the Lazy is enough.
    let _ = &*EEZO_QC_FORMED_TOTAL;
    let _ = &*EEZO_CHAIN_HEIGHT_GAUGE;
    let _ = &*EEZO_STATE_SYNC_PAGE_APPLY_SECONDS;
    let _ = &*EEZO_STATE_BOOTSTRAP_SECONDS;
    let _ = &*EEZO_STATE_SYNC_PAGES_APPLIED_TOTAL;
    let _ = &*EEZO_CHECKPOINT_APPLY_SECONDS;
    let _ = &*EEZO_CHECKPOINTS_WRITTEN_TOTAL;
    
    // T51 metrics: tx inclusion and block tx count
    let _ = &*TXS_INCLUDED_TOTAL;
	let _ = &*TXS_REJECTED_TOTAL;
    let _ = &*BLOCK_TX_COUNT;

    // T77.SAFE-3: mempool TTL expiry metric
    let _ = &*EEZO_MEMPOOL_EXPIRED_TOTAL;
}