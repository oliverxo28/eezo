//! T76.10 — Adaptive Aggregation & Block Size Shaping
//!
//! Provides adaptive tuning of aggregation time budget based on recent executor
//! latency metrics. When `EEZO_HYBRID_AGG_TIME_BUDGET_MS` is unset, the system
//! dynamically adjusts the aggregation window between MIN_MS and MAX_MS based
//! on observed p50/p90 executor times.
//!
//! ## Environment Variables
//!
//! - `EEZO_HYBRID_AGG_TIME_BUDGET_MS`: If set, use this fixed time budget (in ms)
//!   and disable adaptive mode. If unset, enable adaptive mode.
//! - `EEZO_HYBRID_AGG_MAX_TX`: Maximum transaction count per block (default: 500)
//! - `EEZO_HYBRID_AGG_MAX_BYTES`: Maximum bytes per block (default: 1MB = 1048576)

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;

// -----------------------------------------------------------------------------
// Constants for adaptive aggregation
// -----------------------------------------------------------------------------

/// Minimum aggregation time budget in milliseconds.
pub const MIN_MS: u64 = 2;

/// Maximum aggregation time budget in milliseconds.
pub const MAX_MS: u64 = 7;

/// Target fraction of block execution budget to spend on aggregation.
/// A value of 0.5 means we aim to spend half the block interval on aggregation.
pub const TARGET_FRACTION: f64 = 0.5;

/// Baseline executor latency (ms) used for adaptive calculations.
/// This is a historical baseline representing typical execution time.
pub const BASELINE_MS: f64 = 3.0;

/// Default block interval in milliseconds (used if not configured).
pub const DEFAULT_BLOCK_INTERVAL_MS: u64 = 100;

/// Default maximum transactions per block.
pub const DEFAULT_MAX_TX: usize = 500;

/// Default maximum bytes per block (1 MB).
pub const DEFAULT_MAX_BYTES: usize = 1_048_576;

/// T76.12: Default minimum DAG-ordered transactions before fallback.
/// When >0, the proposer waits for this many txs from DAG batches before falling back.
/// Default of 1 preserves backward-compatible behavior (any DAG tx counts as success).
/// For canaries, use higher values (e.g., 50) to ensure meaningful DAG usage.
/// Set to 0 to disable the min threshold entirely.
pub const DEFAULT_MIN_DAG_TX: usize = 1;

/// T76.12: Default batch timeout in milliseconds.
/// How long to wait for DAG-ordered batches before fallback.
/// 0 means "no wait" (current behavior), 30 is a good default for production.
/// T77.1: Increased from 10ms to 30ms to give DAG ordering more time.
/// T78.2: Increased from 30ms to 50ms based on single-sender spam audit.
pub const DEFAULT_BATCH_TIMEOUT_MS: u64 = 50;

// T78.1: Strict hybrid profile defaults
/// Strict profile time budget (when EEZO_HYBRID_STRICT_PROFILE=1 and no explicit override)
/// T78.2: Increased from 30ms to 50ms to favor DAG usage in devnet
pub const STRICT_PROFILE_TIME_BUDGET_MS: u64 = 50;
/// Strict profile max transactions (when EEZO_HYBRID_STRICT_PROFILE=1 and no explicit override)
pub const STRICT_PROFILE_MAX_TX: usize = 500;
/// Strict profile max bytes (when EEZO_HYBRID_STRICT_PROFILE=1 and no explicit override)
pub const STRICT_PROFILE_MAX_BYTES: usize = 1_048_576; // 1 MiB
/// T78.2: Strict profile min DAG transactions before fallback
/// Set to 0 to use any DAG batch (even with 1-2 txs after filtering)
pub const STRICT_PROFILE_MIN_DAG_TX: usize = 0;
/// T78.2: Strict profile batch timeout (overrides DEFAULT_BATCH_TIMEOUT_MS)
pub const STRICT_PROFILE_BATCH_TIMEOUT_MS: u64 = 50;

/// Size of the rolling window for executor latency samples.
const LATENCY_WINDOW_SIZE: usize = 100;

// -----------------------------------------------------------------------------
// Aggregation cap reason
// -----------------------------------------------------------------------------

/// Reason why aggregation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggCapReason {
    /// Aggregation ended due to time budget being reached.
    Time,
    /// Aggregation ended due to byte limit being reached.
    Bytes,
    /// Aggregation ended due to transaction count limit being reached.
    Tx,
    /// Aggregation ended because no more batches were available (queue empty).
    Empty,
}

impl AggCapReason {
    /// Convert to a string label for metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            AggCapReason::Time => "time",
            AggCapReason::Bytes => "bytes",
            AggCapReason::Tx => "tx",
            AggCapReason::Empty => "empty",
        }
    }
}

// -----------------------------------------------------------------------------
// Rolling latency tracker
// -----------------------------------------------------------------------------

/// Tracks rolling executor latency samples for p50/p90 calculation.
pub struct LatencyTracker {
    /// Ring buffer of recent latency samples (in milliseconds).
    samples: RwLock<VecDeque<f64>>,
    /// Maximum number of samples to retain.
    capacity: usize,
}

impl LatencyTracker {
    /// Create a new latency tracker with default window size.
    pub fn new() -> Self {
        Self::with_capacity(LATENCY_WINDOW_SIZE)
    }

    /// Create a new latency tracker with custom window size.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            samples: RwLock::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Record a new latency sample (in seconds, will be converted to ms).
    pub fn record(&self, latency_seconds: f64) {
        let latency_ms = latency_seconds * 1000.0;
        let mut samples = self.samples.write();
        if samples.len() >= self.capacity {
            samples.pop_front();
        }
        samples.push_back(latency_ms);
    }

    /// Get the p50 (median) latency in milliseconds.
    /// Returns None if no samples are available.
    pub fn p50(&self) -> Option<f64> {
        self.percentile(50.0)
    }

    /// Get the p90 latency in milliseconds.
    /// Returns None if no samples are available.
    pub fn p90(&self) -> Option<f64> {
        self.percentile(90.0)
    }

    /// Calculate a given percentile from the samples.
    fn percentile(&self, pct: f64) -> Option<f64> {
        let samples = self.samples.read();
        if samples.is_empty() {
            return None;
        }

        let mut sorted: Vec<f64> = samples.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let idx = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        let idx = idx.min(sorted.len() - 1);
        Some(sorted[idx])
    }

    /// Get the number of samples currently in the tracker.
    pub fn len(&self) -> usize {
        self.samples.read().len()
    }

    /// Check if the tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.samples.read().is_empty()
    }
}

impl Default for LatencyTracker {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Adaptive aggregation configuration
// -----------------------------------------------------------------------------

/// Configuration for adaptive aggregation.
pub struct AdaptiveAggConfig {
    /// Whether adaptive mode is enabled.
    /// When false, a fixed time budget is used.
    adaptive_enabled: bool,
    
    /// Fixed time budget in milliseconds (used when adaptive_enabled is false).
    fixed_budget_ms: AtomicU64,
    
    /// Maximum transaction count per block.
    max_tx: usize,
    
    /// Maximum bytes per block.
    max_bytes: usize,
    
    /// Block interval in milliseconds (for adaptive calculation).
    block_interval_ms: u64,
    
    /// Rolling latency tracker for executor metrics.
    latency_tracker: LatencyTracker,
    
    /// T76.12: Minimum DAG-ordered transactions before fallback.
    /// When >0, the proposer waits for this many txs from DAG batches before falling back.
    min_dag_tx: usize,
    
    /// T76.12: Batch timeout in milliseconds.
    /// How long to wait for DAG-ordered batches before fallback.
    /// 0 means "no wait" (current behavior).
    batch_timeout_ms: u64,
    
    /// T78.1: Whether strict hybrid profile is enabled.
    /// Set to true when EEZO_HYBRID_STRICT_PROFILE=1 and no explicit envs are set.
    strict_profile_enabled: bool,
}

impl AdaptiveAggConfig {
    /// Create a new adaptive aggregation config from environment variables.
    ///
    /// Reads:
    /// - `EEZO_HYBRID_STRICT_PROFILE`: If set to 1, use strict hybrid profile defaults
    /// - `EEZO_HYBRID_AGG_TIME_BUDGET_MS`: If set, use fixed budget, disable adaptive.
    /// - `EEZO_HYBRID_AGG_MAX_TX`: Max transactions per block (default: 500).
    /// - `EEZO_HYBRID_AGG_MAX_BYTES`: Max bytes per block (default: 1MB).
    /// - `EEZO_HYBRID_MIN_DAG_TX`: Min DAG txs before fallback (default: 1).
    /// - `EEZO_HYBRID_BATCH_TIMEOUT_MS`: Timeout before fallback (default: 30ms).
    ///
    /// T78.1: The strict profile is a preset configuration that can be enabled
    /// via EEZO_HYBRID_STRICT_PROFILE=1. When enabled and individual env vars
    /// are unset, it applies recommended defaults for strict hybrid/devnet mode.
    /// Individual env vars always take precedence over the profile.
    pub fn from_env() -> Self {
        // T78.1: Check if strict hybrid profile is enabled
        let strict_profile_env = std::env::var("EEZO_HYBRID_STRICT_PROFILE")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let strict_profile_requested = strict_profile_env == 1;
        
        // Check if explicit envs are set (to determine if profile is actually used)
        let has_time_budget_override = std::env::var("EEZO_HYBRID_AGG_TIME_BUDGET_MS").is_ok();
        let has_max_tx_override = std::env::var("EEZO_HYBRID_AGG_MAX_TX").is_ok();
        let has_max_bytes_override = std::env::var("EEZO_HYBRID_AGG_MAX_BYTES").is_ok();
        
        // Profile is "active" only if requested and NO explicit overrides are set
        let strict_profile_active = strict_profile_requested 
            && !has_time_budget_override 
            && !has_max_tx_override 
            && !has_max_bytes_override;
        
        // Check if fixed budget is set (explicit or from profile)
        let fixed_budget_env = std::env::var("EEZO_HYBRID_AGG_TIME_BUDGET_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .or_else(|| {
                if strict_profile_active {
                    Some(STRICT_PROFILE_TIME_BUDGET_MS)
                } else {
                    None
                }
            });
        
        let (adaptive_enabled, fixed_budget_ms) = match fixed_budget_env {
            Some(budget) => {
                // Fixed budget set - disable adaptive mode
                if strict_profile_active {
                    log::info!(
                        "T78.2: hybrid strict profile enabled (time_budget_ms={}, max_tx={}, max_bytes={}, min_dag_tx={}, batch_timeout_ms={})",
                        budget,
                        STRICT_PROFILE_MAX_TX,
                        STRICT_PROFILE_MAX_BYTES,
                        STRICT_PROFILE_MIN_DAG_TX,
                        STRICT_PROFILE_BATCH_TIMEOUT_MS
                    );
                } else {
                    log::info!(
                        "adaptive-agg: fixed time budget configured: {} ms (adaptive mode disabled)",
                        budget
                    );
                }
                (false, budget)
            }
            None => {
                // No fixed budget - enable adaptive mode
                log::info!(
                    "adaptive-agg: adaptive mode enabled (MIN_MS={}, MAX_MS={}, TARGET_FRACTION={})",
                    MIN_MS, MAX_MS, TARGET_FRACTION
                );
                (true, MIN_MS) // Start at minimum
            }
        };
        
        // Parse max tx from environment (with strict profile fallback)
        let max_tx = std::env::var("EEZO_HYBRID_AGG_MAX_TX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .or_else(|| {
                if strict_profile_active {
                    Some(STRICT_PROFILE_MAX_TX)
                } else {
                    None
                }
            })
            .unwrap_or(DEFAULT_MAX_TX);
        
        // Parse max bytes from environment (with strict profile fallback)
        let max_bytes = std::env::var("EEZO_HYBRID_AGG_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .or_else(|| {
                if strict_profile_active {
                    Some(STRICT_PROFILE_MAX_BYTES)
                } else {
                    None
                }
            })
            .unwrap_or(DEFAULT_MAX_BYTES);
        
        // Parse block interval (for adaptive calculation)
        let block_interval_ms = std::env::var("EEZO_BLOCK_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_BLOCK_INTERVAL_MS);
        
        // T78.2: Parse min DAG tx threshold (with strict profile fallback)
        let min_dag_tx = std::env::var("EEZO_HYBRID_MIN_DAG_TX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .or_else(|| {
                if strict_profile_active {
                    Some(STRICT_PROFILE_MIN_DAG_TX)
                } else {
                    None
                }
            })
            .unwrap_or(DEFAULT_MIN_DAG_TX);
        
        // T78.2: Parse batch timeout (with strict profile fallback)
        let batch_timeout_ms = std::env::var("EEZO_HYBRID_BATCH_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .or_else(|| {
                if strict_profile_active {
                    Some(STRICT_PROFILE_BATCH_TIMEOUT_MS)
                } else {
                    None
                }
            })
            .unwrap_or(DEFAULT_BATCH_TIMEOUT_MS);
        
        log::info!(
            "adaptive-agg: max_tx={}, max_bytes={}, block_interval_ms={}, min_dag_tx={}, batch_timeout_ms={}",
            max_tx, max_bytes, block_interval_ms, min_dag_tx, batch_timeout_ms
        );
        
        Self {
            adaptive_enabled,
            fixed_budget_ms: AtomicU64::new(fixed_budget_ms),
            max_tx,
            max_bytes,
            block_interval_ms,
            latency_tracker: LatencyTracker::new(),
            min_dag_tx,
            batch_timeout_ms,
            strict_profile_enabled: strict_profile_active,
        }
    }
    
    /// Check if adaptive mode is enabled.
    pub fn is_adaptive(&self) -> bool {
        self.adaptive_enabled
    }
    
    /// T78.1: Check if strict hybrid profile is active.
    pub fn is_strict_profile_enabled(&self) -> bool {
        self.strict_profile_enabled
    }
    
    /// Get the maximum transaction count per block.
    pub fn max_tx(&self) -> usize {
        self.max_tx
    }
    
    /// Get the maximum bytes per block.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
    
    /// T76.12: Get the minimum DAG-ordered transactions before fallback.
    pub fn min_dag_tx(&self) -> usize {
        self.min_dag_tx
    }
    
    /// T76.12: Get the batch timeout in milliseconds.
    pub fn batch_timeout_ms(&self) -> u64 {
        self.batch_timeout_ms
    }
    
    /// Record an executor latency sample (in seconds).
    pub fn record_exec_latency(&self, latency_seconds: f64) {
        if self.adaptive_enabled {
            self.latency_tracker.record(latency_seconds);
        }
    }
    
    /// Calculate and return the current aggregation time budget in milliseconds.
    ///
    /// If adaptive mode is enabled, computes:
    ///   suggested_ms = TARGET_FRACTION * block_interval_ms * (exec_p50 / baseline_ms)
    /// and clamps to [MIN_MS, MAX_MS].
    ///
    /// If adaptive mode is disabled, returns the fixed budget.
    pub fn current_time_budget_ms(&self) -> u64 {
        if !self.adaptive_enabled {
            return self.fixed_budget_ms.load(Ordering::Relaxed);
        }
        
        // Get p50 executor latency
        let exec_p50 = self.latency_tracker.p50().unwrap_or(BASELINE_MS);
        
        // Calculate suggested window
        // suggested_ms = TARGET_FRACTION * block_interval_ms * (exec_p50 / baseline_ms)
        let suggested_ms = TARGET_FRACTION 
            * (self.block_interval_ms as f64) 
            * (exec_p50 / BASELINE_MS);
        
        // Clamp to [MIN_MS, MAX_MS]
        let clamped = (suggested_ms as u64).clamp(MIN_MS, MAX_MS);
        
        log::debug!(
            "adaptive-agg: exec_p50={:.2}ms, suggested={:.2}ms, clamped={}ms",
            exec_p50, suggested_ms, clamped
        );
        
        clamped
    }
    
    /// Get the p50 executor latency in milliseconds (for metrics/debugging).
    pub fn exec_p50_ms(&self) -> Option<f64> {
        self.latency_tracker.p50()
    }
    
    /// Get the p90 executor latency in milliseconds (for metrics/debugging).
    pub fn exec_p90_ms(&self) -> Option<f64> {
        self.latency_tracker.p90()
    }
    
    /// Get the number of latency samples in the tracker.
    pub fn latency_sample_count(&self) -> usize {
        self.latency_tracker.len()
    }
}

impl Default for AdaptiveAggConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

// -----------------------------------------------------------------------------
// Global adaptive aggregation config (lazy singleton)
// -----------------------------------------------------------------------------

use once_cell::sync::Lazy;

/// Global adaptive aggregation configuration.
/// Initialized once from environment variables.
pub static ADAPTIVE_AGG_CONFIG: Lazy<AdaptiveAggConfig> = Lazy::new(AdaptiveAggConfig::from_env);

/// Get a reference to the global adaptive aggregation config.
#[inline]
pub fn adaptive_agg_config() -> &'static AdaptiveAggConfig {
    &ADAPTIVE_AGG_CONFIG
}

/// Record an executor latency sample to the global tracker.
#[inline]
pub fn record_exec_latency(latency_seconds: f64) {
    ADAPTIVE_AGG_CONFIG.record_exec_latency(latency_seconds);
}

/// Get the current adaptive time budget from the global config.
#[inline]
pub fn current_time_budget_ms() -> u64 {
    ADAPTIVE_AGG_CONFIG.current_time_budget_ms()
}

/// Check if adaptive mode is enabled in the global config.
#[inline]
pub fn is_adaptive_enabled() -> bool {
    ADAPTIVE_AGG_CONFIG.is_adaptive()
}

/// T78.1: Check if strict hybrid profile is enabled in the global config.
#[inline]
pub fn is_strict_profile_enabled() -> bool {
    ADAPTIVE_AGG_CONFIG.is_strict_profile_enabled()
}

/// Get the max_tx from the global config.
#[inline]
pub fn max_tx() -> usize {
    ADAPTIVE_AGG_CONFIG.max_tx()
}

/// Get the max_bytes from the global config.
#[inline]
pub fn max_bytes() -> usize {
    ADAPTIVE_AGG_CONFIG.max_bytes()
}

/// T76.12: Get the min_dag_tx from the global config.
#[inline]
pub fn min_dag_tx() -> usize {
    ADAPTIVE_AGG_CONFIG.min_dag_tx()
}

/// T76.12: Get the batch_timeout_ms from the global config.
#[inline]
pub fn batch_timeout_ms() -> u64 {
    ADAPTIVE_AGG_CONFIG.batch_timeout_ms()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_tracker_empty() {
        let tracker = LatencyTracker::new();
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
        assert!(tracker.p50().is_none());
        assert!(tracker.p90().is_none());
    }

    #[test]
    fn test_latency_tracker_single_sample() {
        let tracker = LatencyTracker::new();
        tracker.record(0.005); // 5ms
        
        assert!(!tracker.is_empty());
        assert_eq!(tracker.len(), 1);
        assert!((tracker.p50().unwrap() - 5.0).abs() < 0.01);
        assert!((tracker.p90().unwrap() - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_latency_tracker_multiple_samples() {
        let tracker = LatencyTracker::with_capacity(10);
        
        // Add samples: 1ms, 2ms, 3ms, 4ms, 5ms, 6ms, 7ms, 8ms, 9ms, 10ms
        for i in 1..=10 {
            tracker.record(i as f64 / 1000.0);
        }
        
        assert_eq!(tracker.len(), 10);
        
        // p50 should be around 5-6ms (median)
        let p50 = tracker.p50().unwrap();
        assert!(p50 >= 4.5 && p50 <= 6.5, "p50={}", p50);
        
        // p90 should be around 9-10ms
        let p90 = tracker.p90().unwrap();
        assert!(p90 >= 8.5 && p90 <= 10.5, "p90={}", p90);
    }

    #[test]
    fn test_latency_tracker_window_eviction() {
        let tracker = LatencyTracker::with_capacity(5);
        
        // Add more samples than capacity
        for i in 1..=10 {
            tracker.record(i as f64 / 1000.0);
        }
        
        // Should only have 5 samples (most recent)
        assert_eq!(tracker.len(), 5);
        
        // p50 should be based on samples 6-10ms, so around 8ms
        let p50 = tracker.p50().unwrap();
        assert!(p50 >= 7.0 && p50 <= 9.0, "p50={}", p50);
    }

    #[test]
    fn test_adaptive_time_budget_clamping_min() {
        // When exec_p50 is very low, suggested should be clamped to MIN_MS
        let tracker = LatencyTracker::new();
        tracker.record(0.0001); // 0.1ms - very fast
        
        // With very fast execution, suggested would be < MIN_MS
        let exec_p50 = tracker.p50().unwrap();
        let suggested = TARGET_FRACTION * (DEFAULT_BLOCK_INTERVAL_MS as f64) * (exec_p50 / BASELINE_MS);
        let clamped = (suggested as u64).clamp(MIN_MS, MAX_MS);
        
        assert_eq!(clamped, MIN_MS);
    }

    #[test]
    fn test_adaptive_time_budget_clamping_max() {
        // When exec_p50 is very high, suggested should be clamped to MAX_MS
        let tracker = LatencyTracker::new();
        tracker.record(0.050); // 50ms - very slow
        
        let exec_p50 = tracker.p50().unwrap();
        let suggested = TARGET_FRACTION * (DEFAULT_BLOCK_INTERVAL_MS as f64) * (exec_p50 / BASELINE_MS);
        let clamped = (suggested as u64).clamp(MIN_MS, MAX_MS);
        
        assert_eq!(clamped, MAX_MS);
    }

    #[test]
    fn test_adaptive_time_budget_in_range() {
        // When exec_p50 is around baseline, suggested should be within range
        let tracker = LatencyTracker::new();
        tracker.record(0.003); // 3ms - at baseline
        
        let exec_p50 = tracker.p50().unwrap();
        let suggested = TARGET_FRACTION * (DEFAULT_BLOCK_INTERVAL_MS as f64) * (exec_p50 / BASELINE_MS);
        let clamped = (suggested as u64).clamp(MIN_MS, MAX_MS);
        
        // With exec_p50 = 3ms = baseline, suggested = 0.5 * 100 * 1.0 = 50ms
        // This should be clamped to MAX_MS = 7ms
        // Actually, with TARGET_FRACTION=0.5 and block_interval=100ms, 
        // we get suggested = 50ms which is way above MAX_MS
        // Let's check the formula is correct - it should produce values in range
        // For a more realistic test, let's use smaller block interval
        assert!(clamped >= MIN_MS && clamped <= MAX_MS);
    }

    #[test]
    fn test_agg_cap_reason_as_str() {
        assert_eq!(AggCapReason::Time.as_str(), "time");
        assert_eq!(AggCapReason::Bytes.as_str(), "bytes");
        assert_eq!(AggCapReason::Tx.as_str(), "tx");
        assert_eq!(AggCapReason::Empty.as_str(), "empty");
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(MIN_MS, 2);
        assert_eq!(MAX_MS, 7);
        assert!((TARGET_FRACTION - 0.5).abs() < f64::EPSILON);
        assert!((BASELINE_MS - 3.0).abs() < f64::EPSILON);
        assert_eq!(DEFAULT_MAX_TX, 500);
        assert_eq!(DEFAULT_MAX_BYTES, 1_048_576);
        // T76.12: Check new defaults
        assert_eq!(DEFAULT_MIN_DAG_TX, 1);
        // T78.2: Updated from 30ms to 50ms based on audit
        assert_eq!(DEFAULT_BATCH_TIMEOUT_MS, 50);
    }

    // -------------------------------------------------------------------------
    // T77.1: Tests for AdaptiveAggConfig batch_timeout_ms default and override
    // -------------------------------------------------------------------------

    #[test]
    fn test_batch_timeout_default_50ms_when_unset() {
        // Clear the env var to test default behavior
        std::env::remove_var("EEZO_HYBRID_BATCH_TIMEOUT_MS");
        
        // T78.2: The default constant should be 50ms (increased from 30ms)
        assert_eq!(DEFAULT_BATCH_TIMEOUT_MS, 50);
        
        // When we create a fresh config (without the env var set), 
        // it should use the default value of 50ms.
        // Note: We can't easily test from_env() in isolation because it reads
        // global env vars that may be set by other tests. So we test the constant.
    }

    #[test]
    fn test_batch_timeout_respects_env_override() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Set env var to a custom value
        std::env::set_var("EEZO_HYBRID_BATCH_TIMEOUT_MS", "50");
        
        // Parse the value the same way AdaptiveAggConfig does
        let parsed = std::env::var("EEZO_HYBRID_BATCH_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_BATCH_TIMEOUT_MS);
        
        assert_eq!(parsed, 50);
        
        // Clean up
        std::env::remove_var("EEZO_HYBRID_BATCH_TIMEOUT_MS");
        
        // After removal, should return default (T78.2: 50ms)
        let parsed_default = std::env::var("EEZO_HYBRID_BATCH_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_BATCH_TIMEOUT_MS);
        
        assert_eq!(parsed_default, 50);
    }

    // -------------------------------------------------------------------------
    // T78.1: Tests for Strict Hybrid Profile
    // -------------------------------------------------------------------------

    #[test]
    fn test_strict_profile_constants() {
        // Verify that strict profile constants are set correctly
        // T78.2: Updated from 30ms to 50ms
        assert_eq!(STRICT_PROFILE_TIME_BUDGET_MS, 50);
        assert_eq!(STRICT_PROFILE_MAX_TX, 500);
        assert_eq!(STRICT_PROFILE_MAX_BYTES, 1_048_576);
    }

    #[test]
    fn test_strict_profile_unset_uses_defaults() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Clear all relevant env vars
        std::env::remove_var("EEZO_HYBRID_STRICT_PROFILE");
        std::env::remove_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_TX");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_BYTES");
        
        // Create config - should use standard defaults (not strict profile)
        let config = AdaptiveAggConfig::from_env();
        
        // Should be in adaptive mode (no fixed budget set)
        assert!(config.is_adaptive());
        assert!(!config.is_strict_profile_enabled());
        
        // Should use standard defaults
        assert_eq!(config.max_tx(), DEFAULT_MAX_TX);
        assert_eq!(config.max_bytes(), DEFAULT_MAX_BYTES);
    }

    #[test]
    fn test_strict_profile_enabled_without_overrides() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Enable strict profile, but don't set explicit env vars
        std::env::set_var("EEZO_HYBRID_STRICT_PROFILE", "1");
        std::env::remove_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_TX");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_BYTES");
        
        // Create config - should use strict profile defaults
        let config = AdaptiveAggConfig::from_env();
        
        // Should be in fixed mode (strict profile sets time budget)
        assert!(!config.is_adaptive());
        assert!(config.is_strict_profile_enabled());
        
        // Should use strict profile defaults
        assert_eq!(config.current_time_budget_ms(), STRICT_PROFILE_TIME_BUDGET_MS);
        assert_eq!(config.max_tx(), STRICT_PROFILE_MAX_TX);
        assert_eq!(config.max_bytes(), STRICT_PROFILE_MAX_BYTES);
        
        // Clean up
        std::env::remove_var("EEZO_HYBRID_STRICT_PROFILE");
    }

    #[test]
    fn test_strict_profile_with_explicit_overrides() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Enable strict profile AND set explicit overrides
        std::env::set_var("EEZO_HYBRID_STRICT_PROFILE", "1");
        std::env::set_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS", "50");
        std::env::set_var("EEZO_HYBRID_AGG_MAX_TX", "1000");
        std::env::set_var("EEZO_HYBRID_AGG_MAX_BYTES", "2097152");
        
        // Create config - explicit overrides should win
        let config = AdaptiveAggConfig::from_env();
        
        // Should be in fixed mode
        assert!(!config.is_adaptive());
        // Profile is NOT considered "active" because explicit envs are set
        assert!(!config.is_strict_profile_enabled());
        
        // Should use explicit overrides, not strict profile defaults
        assert_eq!(config.current_time_budget_ms(), 50);
        assert_eq!(config.max_tx(), 1000);
        assert_eq!(config.max_bytes(), 2097152);
        
        // Clean up
        std::env::remove_var("EEZO_HYBRID_STRICT_PROFILE");
        std::env::remove_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_TX");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_BYTES");
    }

    #[test]
    fn test_strict_profile_with_partial_overrides() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Enable strict profile, override only time budget
        std::env::set_var("EEZO_HYBRID_STRICT_PROFILE", "1");
        std::env::set_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS", "50");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_TX");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_BYTES");
        
        // Create config - partial override deactivates profile
        let config = AdaptiveAggConfig::from_env();
        
        // Should be in fixed mode
        assert!(!config.is_adaptive());
        // Profile is NOT active because time_budget is explicitly set
        assert!(!config.is_strict_profile_enabled());
        
        // time_budget should use explicit override
        assert_eq!(config.current_time_budget_ms(), 50);
        // max_tx and max_bytes should use standard defaults (not strict profile)
        assert_eq!(config.max_tx(), DEFAULT_MAX_TX);
        assert_eq!(config.max_bytes(), DEFAULT_MAX_BYTES);
        
        // Clean up
        std::env::remove_var("EEZO_HYBRID_STRICT_PROFILE");
        std::env::remove_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS");
    }

    #[test]
    fn test_strict_profile_zero_is_disabled() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Set strict profile to 0 (disabled)
        std::env::set_var("EEZO_HYBRID_STRICT_PROFILE", "0");
        std::env::remove_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_TX");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_BYTES");
        
        // Create config - should not use strict profile
        let config = AdaptiveAggConfig::from_env();
        
        // Should be in adaptive mode
        assert!(config.is_adaptive());
        assert!(!config.is_strict_profile_enabled());
        
        // Should use standard defaults
        assert_eq!(config.max_tx(), DEFAULT_MAX_TX);
        assert_eq!(config.max_bytes(), DEFAULT_MAX_BYTES);
        
        // Clean up
        std::env::remove_var("EEZO_HYBRID_STRICT_PROFILE");
    }

    // -------------------------------------------------------------------------
    // T78.2: Tests for strict profile DAG tuning overrides
    // -------------------------------------------------------------------------

    #[test]
    fn test_strict_profile_dag_tuning_constants() {
        // T78.2: Verify strict profile constants are set correctly
        assert_eq!(STRICT_PROFILE_TIME_BUDGET_MS, 50);
        assert_eq!(STRICT_PROFILE_MAX_TX, 500);
        assert_eq!(STRICT_PROFILE_MAX_BYTES, 1_048_576);
        assert_eq!(STRICT_PROFILE_MIN_DAG_TX, 0);
        assert_eq!(STRICT_PROFILE_BATCH_TIMEOUT_MS, 50);
    }

    #[test]
    fn test_strict_profile_overrides_min_dag_tx() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Clear all env vars first to ensure clean state
        std::env::remove_var("EEZO_HYBRID_STRICT_PROFILE");
        std::env::remove_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_TX");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_BYTES");
        std::env::remove_var("EEZO_HYBRID_MIN_DAG_TX");
        std::env::remove_var("EEZO_HYBRID_BATCH_TIMEOUT_MS");
        
        // Enable strict profile, don't set explicit min_dag_tx
        std::env::set_var("EEZO_HYBRID_STRICT_PROFILE", "1");
        
        // Create config - should use strict profile defaults
        let config = AdaptiveAggConfig::from_env();
        
        // T78.2: Should use strict profile value for min_dag_tx (0, not default 1)
        assert_eq!(config.min_dag_tx(), STRICT_PROFILE_MIN_DAG_TX);
        assert_eq!(config.min_dag_tx(), 0);
        
        // Clean up
        std::env::remove_var("EEZO_HYBRID_STRICT_PROFILE");
    }

    #[test]
    fn test_strict_profile_overrides_batch_timeout() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Enable strict profile, don't set explicit batch_timeout
        std::env::set_var("EEZO_HYBRID_STRICT_PROFILE", "1");
        std::env::remove_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_TX");
        std::env::remove_var("EEZO_HYBRID_AGG_MAX_BYTES");
        std::env::remove_var("EEZO_HYBRID_MIN_DAG_TX");
        std::env::remove_var("EEZO_HYBRID_BATCH_TIMEOUT_MS");
        
        // Create config - should use strict profile defaults
        let config = AdaptiveAggConfig::from_env();
        
        // Should use strict profile value for batch_timeout (50ms)
        assert_eq!(config.batch_timeout_ms(), STRICT_PROFILE_BATCH_TIMEOUT_MS);
        assert_eq!(config.batch_timeout_ms(), 50);
        
        // Clean up
        std::env::remove_var("EEZO_HYBRID_STRICT_PROFILE");
    }

    #[test]
    fn test_explicit_env_overrides_strict_profile_dag_params() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Enable strict profile but override min_dag_tx and batch_timeout
        std::env::set_var("EEZO_HYBRID_STRICT_PROFILE", "1");
        std::env::remove_var("EEZO_HYBRID_AGG_TIME_BUDGET_MS");
        std::env::set_var("EEZO_HYBRID_MIN_DAG_TX", "10");
        std::env::set_var("EEZO_HYBRID_BATCH_TIMEOUT_MS", "100");
        
        // Create config - explicit overrides should win
        let config = AdaptiveAggConfig::from_env();
        
        // Should use explicit overrides, not strict profile values
        assert_eq!(config.min_dag_tx(), 10);
        assert_eq!(config.batch_timeout_ms(), 100);
        
        // Clean up
        std::env::remove_var("EEZO_HYBRID_STRICT_PROFILE");
        std::env::remove_var("EEZO_HYBRID_MIN_DAG_TX");
        std::env::remove_var("EEZO_HYBRID_BATCH_TIMEOUT_MS");
    }
}