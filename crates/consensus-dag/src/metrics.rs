//! metrics.rs — Metrics for DAG consensus
//!
//! Prometheus metrics for monitoring DAG consensus performance.

#[cfg(feature = "metrics")]
use lazy_static::lazy_static;

#[cfg(feature = "metrics")]
use prometheus::{IntCounter, IntGauge, Histogram, HistogramOpts, Registry, register_int_counter_with_registry, register_int_gauge_with_registry, register_histogram_with_registry};

#[cfg(feature = "metrics")]
lazy_static! {
    /// Global metrics registry
    pub static ref REGISTRY: Registry = Registry::new();

    /// DAG vertices stored
    pub static ref DAG_VERTICES_TOTAL: IntCounter = register_int_counter_with_registry!(
        "eezo_dag_vertices_total",
        "Total DAG vertices stored",
        REGISTRY
    ).unwrap();

    /// Current round number
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

    /// Ordering latency (seconds)
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

/// Helper function to increment vertex stored counter
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

/// Register all metrics (call once at startup)
#[cfg(feature = "metrics")]
pub fn register_metrics() {
    lazy_static::initialize(&REGISTRY);
    lazy_static::initialize(&DAG_VERTICES_TOTAL);
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

/// No-op stubs when metrics are disabled
#[cfg(not(feature = "metrics"))]
pub fn dag_vertex_stored() {}

#[cfg(not(feature = "metrics"))]
pub fn dag_equivocation_detected() {}

#[cfg(not(feature = "metrics"))]
pub fn dag_bundle_ordered() {}

#[cfg(not(feature = "metrics"))]
pub fn exec_apply_observe(_seconds: f64) {}

/// No-op stubs when metrics are disabled
#[cfg(not(feature = "metrics"))]
pub fn register_metrics() {}
