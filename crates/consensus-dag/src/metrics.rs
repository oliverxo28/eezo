//! metrics.rs — Metrics for DAG consensus
//!
//! Prometheus metrics for monitoring DAG consensus performance.
//!
//! ## T74.3: Core DAG Metrics
//!
//! This module provides Prometheus-style metrics for observing DAG consensus behaviour:
//!
//! **Counters:**
//! - `eezo_dag_vertices_total` — total vertices seen/built
//! - `eezo_dag_vertices_ordered_total` — vertices that made it into an ordered batch
//! - `eezo_dag_round_advance_total` — number of times consensus advanced the round
//! - `eezo_dag_order_fail_total` — failed ordering attempts (if applicable)
//!
//! **Gauges:**
//! - `eezo_dag_current_round` — current consensus round
//! - `eezo_dag_pending_vertices` — vertices waiting to be ordered
//!
//! **Histograms:**
//! - `eezo_dag_vertices_per_round` — how many vertices per round
//! - `eezo_dag_order_latency_seconds` — time from vertex creation to inclusion in ordered batch

#[cfg(feature = "metrics")]
use lazy_static::lazy_static;

#[cfg(feature = "metrics")]
use prometheus::{IntCounter, IntGauge, Histogram, HistogramOpts, Registry, register_int_counter_with_registry, register_int_gauge_with_registry, register_histogram_with_registry};

#[cfg(feature = "metrics")]
lazy_static! {
    /// Global metrics registry
    pub static ref REGISTRY: Registry = Registry::new();

    // -------------------------------------------------------------------------
    // Core DAG Metrics (T74.3)
    // -------------------------------------------------------------------------

    /// DAG vertices stored/submitted (Counter)
    pub static ref DAG_VERTICES_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_dag_vertices_total",
        "Total DAG vertices seen/built",
        REGISTRY
    ).unwrap();

    /// DAG vertices ordered (Counter) - vertices that made it into an ordered batch
    pub static ref DAG_VERTICES_ORDERED_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_dag_vertices_ordered_total",
        "Total DAG vertices that made it into an ordered batch",
        REGISTRY
    ).unwrap();

    /// Round advance counter (Counter) - number of times consensus advanced the round
    pub static ref DAG_ROUND_ADVANCE_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_dag_round_advance_total",
        "Number of times consensus advanced the round",
        REGISTRY
    ).unwrap();

    /// Order fail counter (Counter) - failed ordering attempts
    pub static ref DAG_ORDER_FAIL_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_dag_order_fail_total",
        "Failed ordering attempts",
        REGISTRY
    ).unwrap();

    /// Current round number (Gauge)
    pub static ref DAG_CURRENT_ROUND: IntGauge = register_int_gauge_with_registry!(
        "eezo_dag_current_round",
        "Current DAG consensus round",
        REGISTRY
    ).unwrap();

    /// Pending vertices gauge (Gauge) - vertices waiting to be ordered
    pub static ref DAG_PENDING_VERTICES: IntGauge = register_int_gauge_with_registry!(
        "eezo_dag_pending_vertices",
        "DAG vertices waiting to be ordered",
        REGISTRY
    ).unwrap();

    /// Vertices per round histogram (Histogram)
    pub static ref DAG_VERTICES_PER_ROUND: Histogram = register_histogram_with_registry!(
        HistogramOpts::new(
            "eezo_dag_vertices_per_round",
            "Number of vertices per DAG round"
        ).buckets(vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0]),
        REGISTRY
    ).unwrap();

    /// Order latency histogram (Histogram) - time from vertex creation to ordered batch inclusion
    pub static ref DAG_ORDER_LATENCY_SECONDS: Histogram = register_histogram_with_registry!(
        HistogramOpts::new(
            "eezo_dag_order_latency_seconds",
            "Time from vertex creation to inclusion in an ordered batch"
        ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]),
        REGISTRY
    ).unwrap();

    // -------------------------------------------------------------------------
    // Legacy/Existing Metrics (kept for compatibility)
    // -------------------------------------------------------------------------

    /// Current round number (legacy, kept for backward compatibility)
    pub static ref DAG_ROUND: IntGauge = register_int_gauge_with_registry!(
        "eezo_dag_round",
        "Current DAG round number",
        REGISTRY
    ).unwrap();

    /// Ordered bundles emitted
    pub static ref DAG_BUNDLES_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_dag_bundles_total",
        "Total ordered bundles emitted",
        REGISTRY
    ).unwrap();

    /// Transactions in ordered bundles
    pub static ref DAG_BUNDLE_TXS: IntCounter = register_int_counter_with_registry!(
        "eezo_dag_bundle_txs_total",
        "Total transactions in ordered bundles",
        REGISTRY
    ).unwrap();

    /// Ordering latency (seconds) - legacy
    pub static ref DAG_ORDERING_LATENCY: Histogram = register_histogram_with_registry!(
        HistogramOpts::new(
            "eezo_dag_ordering_latency_seconds",
            "Time to order a round"
        ),
        REGISTRY
    ).unwrap();

    /// Payload cache size
    pub static ref DA_CACHE_SIZE: IntGauge = register_int_gauge_with_registry!(
        "eezo_da_cache_size",
        "Number of payloads in DA cache",
        REGISTRY
    ).unwrap();

    /// Payload requests sent
    pub static ref DA_REQUESTS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_da_requests_total",
        "Total payload requests sent",
        REGISTRY
    ).unwrap();

    /// Payload timeouts
    pub static ref DA_TIMEOUTS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_da_timeouts_total",
        "Total payload request timeouts",
        REGISTRY
    ).unwrap();

    /// Equivocations detected (A15)
    pub static ref DAG_EQUIVOCATIONS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_dag_equivocations_total",
        "Total equivocations detected (same author+round)",
        REGISTRY
    ).unwrap();
    
    /// Ordered bundles emitted (A17)
    pub static ref DAG_ORDER_BUNDLES_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_dag_order_bundles_total",
        "Total ordered bundles processed by executor",
        REGISTRY
    ).unwrap();
    
    /// Executor apply time (A17)
    pub static ref EXEC_APPLY_MS: Histogram = register_histogram_with_registry!(
        HistogramOpts::new(
            "eezo_exec_apply_ms",
            "Executor apply time in milliseconds"
        ),
        REGISTRY
    ).unwrap();
}

// ---------------------------------------------------------------------------
// T74.3 Core DAG Metrics Helper Functions
// ---------------------------------------------------------------------------

/// Increment the total vertices counter (called on vertex submit)
#[cfg(feature = "metrics")]
pub fn dag_vertices_inc() {
    DAG_VERTICES_TOTAL.inc();
}

/// Increment the vertices ordered counter by a given amount
#[cfg(feature = "metrics")]
pub fn dag_vertices_ordered_inc(count: u64) {
    DAG_VERTICES_ORDERED_TOTAL.inc_by(count);
}

/// Increment the round advance counter
#[cfg(feature = "metrics")]
pub fn dag_round_advance_inc() {
    DAG_ROUND_ADVANCE_TOTAL.inc();
}

/// Increment the order fail counter
#[cfg(feature = "metrics")]
pub fn dag_order_fail_inc() {
    DAG_ORDER_FAIL_TOTAL.inc();
}

/// Set the current round gauge
#[cfg(feature = "metrics")]
pub fn dag_current_round_set(round: u64) {
    DAG_CURRENT_ROUND.set(round as i64);
}

/// Increment the pending vertices gauge
#[cfg(feature = "metrics")]
pub fn dag_pending_vertices_inc() {
    DAG_PENDING_VERTICES.inc();
}

/// Decrement the pending vertices gauge by a given amount
#[cfg(feature = "metrics")]
pub fn dag_pending_vertices_dec(count: u64) {
    DAG_PENDING_VERTICES.sub(count as i64);
}

/// Observe the number of vertices in a round
#[cfg(feature = "metrics")]
pub fn observe_vertices_per_round(count: u64) {
    DAG_VERTICES_PER_ROUND.observe(count as f64);
}

/// Observe order latency in seconds
#[cfg(feature = "metrics")]
pub fn observe_order_latency_seconds(seconds: f64) {
    DAG_ORDER_LATENCY_SECONDS.observe(seconds);
}

// ---------------------------------------------------------------------------
// Legacy Helper Functions (kept for backward compatibility)
// ---------------------------------------------------------------------------

/// Helper function to increment vertex stored counter (legacy, use dag_vertices_inc)
#[cfg(feature = "metrics")]
pub fn dag_vertex_stored() {
    DAG_VERTICES_TOTAL.inc();
}

/// Helper function to increment equivocation counter
#[cfg(feature = "metrics")]
pub fn dag_equivocation_detected() {
    DAG_EQUIVOCATIONS_TOTAL.inc();
}

/// Helper function to increment bundle ordered counter (A17)
#[cfg(feature = "metrics")]
pub fn dag_bundle_ordered() {
    DAG_ORDER_BUNDLES_TOTAL.inc();
}

/// Helper function to observe executor apply time (A17)
#[cfg(feature = "metrics")]
pub fn exec_apply_observe(seconds: f64) {
    EXEC_APPLY_MS.observe(seconds * 1000.0); // Convert to milliseconds
}

// ---------------------------------------------------------------------------
// Registration Functions
// ---------------------------------------------------------------------------

/// Register all DAG metrics (T74.3)
/// 
/// Call this once at startup to force initialization of all metrics.
/// This is idempotent - calling it multiple times is safe.
#[cfg(feature = "metrics")]
pub fn register_dag_metrics() {
    lazy_static::initialize(&REGISTRY);
    // T74.3 Core Metrics
    lazy_static::initialize(&DAG_VERTICES_TOTAL);
    lazy_static::initialize(&DAG_VERTICES_ORDERED_TOTAL);
    lazy_static::initialize(&DAG_ROUND_ADVANCE_TOTAL);
    lazy_static::initialize(&DAG_ORDER_FAIL_TOTAL);
    lazy_static::initialize(&DAG_CURRENT_ROUND);
    lazy_static::initialize(&DAG_PENDING_VERTICES);
    lazy_static::initialize(&DAG_VERTICES_PER_ROUND);
    lazy_static::initialize(&DAG_ORDER_LATENCY_SECONDS);
    // Legacy metrics
    lazy_static::initialize(&DAG_ROUND);
    lazy_static::initialize(&DAG_BUNDLES_TOTAL);
    lazy_static::initialize(&DAG_BUNDLE_TXS);
    lazy_static::initialize(&DAG_ORDERING_LATENCY);
    lazy_static::initialize(&DA_CACHE_SIZE);
    lazy_static::initialize(&DA_REQUESTS_TOTAL);
    lazy_static::initialize(&DA_TIMEOUTS_TOTAL);
    lazy_static::initialize(&DAG_EQUIVOCATIONS_TOTAL);
    lazy_static::initialize(&DAG_ORDER_BUNDLES_TOTAL);
    lazy_static::initialize(&EXEC_APPLY_MS);
}

/// Register all metrics (legacy function, calls register_dag_metrics)
#[cfg(feature = "metrics")]
pub fn register_metrics() {
    register_dag_metrics();
}

// ---------------------------------------------------------------------------
// No-op stubs when metrics feature is disabled
// ---------------------------------------------------------------------------

// T74.3 Core Metrics Stubs
#[cfg(not(feature = "metrics"))]
pub fn dag_vertices_inc() {}

#[cfg(not(feature = "metrics"))]
pub fn dag_vertices_ordered_inc(_count: u64) {}

#[cfg(not(feature = "metrics"))]
pub fn dag_round_advance_inc() {}

#[cfg(not(feature = "metrics"))]
pub fn dag_order_fail_inc() {}

#[cfg(not(feature = "metrics"))]
pub fn dag_current_round_set(_round: u64) {}

#[cfg(not(feature = "metrics"))]
pub fn dag_pending_vertices_inc() {}

#[cfg(not(feature = "metrics"))]
pub fn dag_pending_vertices_dec(_count: u64) {}

#[cfg(not(feature = "metrics"))]
pub fn observe_vertices_per_round(_count: u64) {}

#[cfg(not(feature = "metrics"))]
pub fn observe_order_latency_seconds(_seconds: f64) {}

// Legacy Stubs
#[cfg(not(feature = "metrics"))]
pub fn dag_vertex_stored() {}

#[cfg(not(feature = "metrics"))]
pub fn dag_equivocation_detected() {}

#[cfg(not(feature = "metrics"))]
pub fn dag_bundle_ordered() {}

#[cfg(not(feature = "metrics"))]
pub fn exec_apply_observe(_seconds: f64) {}

#[cfg(not(feature = "metrics"))]
pub fn register_dag_metrics() {}

#[cfg(not(feature = "metrics"))]
pub fn register_metrics() {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that register_dag_metrics() is idempotent (calling twice should not panic)
    #[test]
    fn test_register_dag_metrics_is_idempotent() {
        // First call
        register_dag_metrics();
        // Second call - should not panic
        register_dag_metrics();
        // Third call for good measure
        register_dag_metrics();
    }

    /// Test that all metric helper functions can be called without panicking
    #[test]
    fn test_dag_metrics_helpers_no_panic() {
        // Ensure metrics are initialized
        register_dag_metrics();
        
        // Call all helper functions to verify they don't panic
        dag_vertices_inc();
        dag_vertices_ordered_inc(5);
        dag_round_advance_inc();
        dag_order_fail_inc();
        dag_current_round_set(10);
        dag_pending_vertices_inc();
        dag_pending_vertices_dec(1);
        observe_vertices_per_round(3);
        observe_order_latency_seconds(0.5);
        
        // Legacy helpers
        dag_vertex_stored();
        dag_equivocation_detected();
        dag_bundle_ordered();
        exec_apply_observe(0.1);
    }

    /// Test that metrics behave correctly when the metrics feature is enabled
    #[cfg(feature = "metrics")]
    #[test]
    fn test_dag_metrics_increment_on_submit_and_order() {
        // Initialize metrics
        register_dag_metrics();
        
        // Get initial values
        let initial_vertices = DAG_VERTICES_TOTAL.get();
        let initial_ordered = DAG_VERTICES_ORDERED_TOTAL.get();
        let initial_round_advances = DAG_ROUND_ADVANCE_TOTAL.get();
        
        // Simulate vertex submission
        dag_vertices_inc();
        dag_pending_vertices_inc();
        
        // Verify vertex counter incremented
        assert_eq!(DAG_VERTICES_TOTAL.get(), initial_vertices + 1);
        
        // Simulate ordering
        dag_vertices_ordered_inc(3);
        dag_pending_vertices_dec(1);
        dag_current_round_set(5);
        observe_vertices_per_round(3);
        
        // Verify ordered counter incremented
        assert_eq!(DAG_VERTICES_ORDERED_TOTAL.get(), initial_ordered + 3);
        assert_eq!(DAG_CURRENT_ROUND.get(), 5);
        
        // Simulate round advance
        dag_round_advance_inc();
        assert_eq!(DAG_ROUND_ADVANCE_TOTAL.get(), initial_round_advances + 1);
    }
}
