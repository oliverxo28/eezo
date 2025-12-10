//! T79.0: dag-primary health probe
//!
//! This module provides a health endpoint for dag-primary mode that checks:
//! - Consensus mode is dag-primary (eezo_consensus_mode_active == 3)
//! - Shadow checker is active (shadow_checks_total increased recently)
//! - Transactions are being included (txs_included_total increased recently)
//!
//! The health check is designed for k8s readiness/liveness probes.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};
use std::sync::Arc;
use serde::Serialize;

/// Default window in seconds for "activity must increase" checks.
pub const DEFAULT_WINDOW_SECS: u64 = 60;

/// Read window from env or use default.
fn get_window_secs() -> u64 {
    std::env::var("EEZO_DAG_PRIMARY_HEALTH_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WINDOW_SECS)
}

/// Snapshot of metric values with timestamp.
#[derive(Debug, Clone)]
struct MetricSnapshot {
    value: i64,
    timestamp: Instant,
}

impl Default for MetricSnapshot {
    fn default() -> Self {
        Self {
            value: 0,
            timestamp: Instant::now(),
        }
    }
}

/// In-memory state for tracking metric changes over time.
/// This is used to determine if metrics are increasing within the health window.
pub struct DagPrimaryHealthState {
    /// Last seen shadow_checks_total value.
    shadow_checks: parking_lot::RwLock<MetricSnapshot>,
    /// Last seen txs_included_total value.
    txs_included: parking_lot::RwLock<MetricSnapshot>,
    /// Window duration for activity checks.
    window: Duration,
}

impl Default for DagPrimaryHealthState {
    fn default() -> Self {
        Self::new()
    }
}

impl DagPrimaryHealthState {
    /// Create a new health state tracker with default window.
    pub fn new() -> Self {
        Self {
            shadow_checks: parking_lot::RwLock::new(MetricSnapshot::default()),
            txs_included: parking_lot::RwLock::new(MetricSnapshot::default()),
            window: Duration::from_secs(get_window_secs()),
        }
    }

    /// Create a new health state tracker with custom window.
    pub fn with_window(window_secs: u64) -> Self {
        Self {
            shadow_checks: parking_lot::RwLock::new(MetricSnapshot::default()),
            txs_included: parking_lot::RwLock::new(MetricSnapshot::default()),
            window: Duration::from_secs(window_secs),
        }
    }

    /// Update the shadow_checks snapshot if the value has changed.
    pub fn update_shadow_checks(&self, value: i64) {
        let mut guard = self.shadow_checks.write();
        if value != guard.value {
            guard.value = value;
            guard.timestamp = Instant::now();
        }
    }

    /// Update the txs_included snapshot if the value has changed.
    pub fn update_txs_included(&self, value: i64) {
        let mut guard = self.txs_included.write();
        if value != guard.value {
            guard.value = value;
            guard.timestamp = Instant::now();
        }
    }

    /// Check if shadow_checks has increased within the window.
    pub fn shadow_checks_active(&self) -> bool {
        let guard = self.shadow_checks.read();
        guard.value > 0 && guard.timestamp.elapsed() < self.window
    }

    /// Check if txs_included has increased within the window.
    pub fn txs_included_active(&self) -> bool {
        let guard = self.txs_included.read();
        guard.value > 0 && guard.timestamp.elapsed() < self.window
    }

    /// Get current shadow_checks value.
    pub fn shadow_checks_value(&self) -> i64 {
        self.shadow_checks.read().value
    }

    /// Get current txs_included value.
    pub fn txs_included_value(&self) -> i64 {
        self.txs_included.read().value
    }
}

/// Health status enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
}

/// Reason for degraded health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedReason {
    WrongMode,
    NoShadowChecksRecently,
    NoTxsRecently,
}

/// Health check result.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResult {
    pub status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<DegradedReason>,
    /// Current consensus mode value (0=hotstuff, 1=hybrid, 2=dag, 3=dag-primary).
    pub consensus_mode: i64,
    /// Current shadow_checks_total value.
    pub shadow_checks_total: i64,
    /// Current txs_included_total value.
    pub txs_included_total: i64,
    /// Health window in seconds.
    pub window_secs: u64,
}

impl HealthResult {
    /// Create a healthy result.
    pub fn healthy(consensus_mode: i64, shadow_checks: i64, txs_included: i64, window_secs: u64) -> Self {
        Self {
            status: HealthStatus::Healthy,
            reason: None,
            consensus_mode,
            shadow_checks_total: shadow_checks,
            txs_included_total: txs_included,
            window_secs,
        }
    }

    /// Create a degraded result with reason.
    pub fn degraded(
        reason: DegradedReason,
        consensus_mode: i64,
        shadow_checks: i64,
        txs_included: i64,
        window_secs: u64,
    ) -> Self {
        Self {
            status: HealthStatus::Degraded,
            reason: Some(reason),
            consensus_mode,
            shadow_checks_total: shadow_checks,
            txs_included_total: txs_included,
            window_secs,
        }
    }

    /// Is this result healthy?
    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }
}

/// Check dag-primary health by reading current metrics and comparing with state.
///
/// This function is the core health logic that can be unit tested.
///
/// # Arguments
/// * `consensus_mode` - Current eezo_consensus_mode_active gauge value
/// * `shadow_checks_total` - Current eezo_dag_primary_shadow_checks_total counter value
/// * `txs_included_total` - Current eezo_txs_included_total counter value
/// * `state` - The in-memory state tracker for detecting recent activity
///
/// # Returns
/// A `HealthResult` indicating healthy or degraded status with reason.
pub fn check_dag_primary_health(
    consensus_mode: i64,
    shadow_checks_total: i64,
    txs_included_total: i64,
    state: &DagPrimaryHealthState,
) -> HealthResult {
    let window_secs = state.window.as_secs();

    // Update state with current values
    state.update_shadow_checks(shadow_checks_total);
    state.update_txs_included(txs_included_total);

    // Check 1: Consensus mode must be dag-primary (3)
    if consensus_mode != 3 {
        return HealthResult::degraded(
            DegradedReason::WrongMode,
            consensus_mode,
            shadow_checks_total,
            txs_included_total,
            window_secs,
        );
    }

    // Check 2: Shadow checker must be active (value increased recently)
    if !state.shadow_checks_active() {
        return HealthResult::degraded(
            DegradedReason::NoShadowChecksRecently,
            consensus_mode,
            shadow_checks_total,
            txs_included_total,
            window_secs,
        );
    }

    // Check 3: Transactions must be included recently
    if !state.txs_included_active() {
        return HealthResult::degraded(
            DegradedReason::NoTxsRecently,
            consensus_mode,
            shadow_checks_total,
            txs_included_total,
            window_secs,
        );
    }

    // All checks passed
    HealthResult::healthy(
        consensus_mode,
        shadow_checks_total,
        txs_included_total,
        window_secs,
    )
}

/// Read current metric values from Prometheus registry.
///
/// Returns (consensus_mode, shadow_checks_total, txs_included_total).
#[cfg(feature = "metrics")]
pub fn read_dag_primary_metrics() -> (i64, i64, i64) {
    // Read consensus mode gauge
    let consensus_mode = crate::metrics::EEZO_CONSENSUS_MODE_ACTIVE.get();

    // Read shadow checks counter
    let shadow_checks = crate::metrics::EEZO_DAG_PRIMARY_SHADOW_CHECKS_TOTAL.get() as i64;

    // Read txs included counter (from ledger crate)
    let txs_included = eezo_ledger::metrics::TXS_INCLUDED_TOTAL.get() as i64;

    (consensus_mode, shadow_checks, txs_included)
}

/// Fallback when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub fn read_dag_primary_metrics() -> (i64, i64, i64) {
    // Without metrics, return zeros (will result in degraded status)
    (0, 0, 0)
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthy_when_all_conditions_met() {
        let state = DagPrimaryHealthState::with_window(60);
        
        // First update to set initial values
        state.update_shadow_checks(10);
        state.update_txs_included(100);
        
        let result = check_dag_primary_health(3, 10, 100, &state);
        
        assert!(result.is_healthy());
        assert_eq!(result.status, HealthStatus::Healthy);
        assert!(result.reason.is_none());
        assert_eq!(result.consensus_mode, 3);
    }

    #[test]
    fn test_degraded_wrong_mode() {
        let state = DagPrimaryHealthState::with_window(60);
        state.update_shadow_checks(10);
        state.update_txs_included(100);
        
        // Mode 1 = hybrid, not dag-primary
        let result = check_dag_primary_health(1, 10, 100, &state);
        
        assert!(!result.is_healthy());
        assert_eq!(result.status, HealthStatus::Degraded);
        assert_eq!(result.reason, Some(DegradedReason::WrongMode));
    }

    #[test]
    fn test_degraded_no_shadow_checks() {
        let state = DagPrimaryHealthState::with_window(60);
        
        // Shadow checks at 0
        let result = check_dag_primary_health(3, 0, 100, &state);
        
        assert!(!result.is_healthy());
        assert_eq!(result.reason, Some(DegradedReason::NoShadowChecksRecently));
    }

    #[test]
    fn test_degraded_no_txs() {
        let state = DagPrimaryHealthState::with_window(60);
        state.update_shadow_checks(10);
        
        // Txs at 0
        let result = check_dag_primary_health(3, 10, 0, &state);
        
        assert!(!result.is_healthy());
        assert_eq!(result.reason, Some(DegradedReason::NoTxsRecently));
    }

    #[test]
    fn test_state_tracks_updates() {
        let state = DagPrimaryHealthState::with_window(60);
        
        state.update_shadow_checks(5);
        assert_eq!(state.shadow_checks_value(), 5);
        
        state.update_shadow_checks(10);
        assert_eq!(state.shadow_checks_value(), 10);
        
        // Same value should not update timestamp
        let before = state.shadow_checks.read().timestamp;
        std::thread::sleep(std::time::Duration::from_millis(10));
        state.update_shadow_checks(10);
        let after = state.shadow_checks.read().timestamp;
        assert_eq!(before, after);
    }

    #[test]
    fn test_json_serialization() {
        let result = HealthResult::healthy(3, 100, 1000, 60);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(!json.contains("\"reason\"")); // reason is None, should be skipped

        let result = HealthResult::degraded(DegradedReason::WrongMode, 1, 100, 1000, 60);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"degraded\""));
        assert!(json.contains("\"reason\":\"wrong_mode\""));
    }
}
