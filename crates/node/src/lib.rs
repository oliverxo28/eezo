//! eezo-node library exports for testing and integration.
//!
//! This module re-exports public APIs from the node binary that are
//! needed for integration testing.

// T83.0: SigPool module
pub mod sigpool;

// Metrics module (when metrics feature is enabled)
#[cfg(feature = "metrics")]
pub mod metrics;
