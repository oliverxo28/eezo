//! executor/stm.rs — Block-STM executor scaffolding.
//!
//! T73.1: This module provides the `StmExecutor` struct that implements the
//! `Executor` trait for Block-STM parallel execution.
//!
//! This is scaffolding only. The actual STM logic (wave scheduling, conflict
//! detection, retry mechanism) will be implemented in T73.2+.
//!
//! For now, `execute_block` returns an unimplemented error to prevent
//! accidental use before the STM logic is ready.

use std::time::Instant;

use eezo_ledger::consensus::SingleNode;

use crate::executor::{ExecInput, ExecOutcome, Executor};

/// Block-STM executor configuration.
///
/// T73.1: Basic scaffolding. Additional config fields (max_retries,
/// wave_timeout, prefetch) will be added in T73.2+.
#[derive(Debug, Clone)]
pub struct StmConfig {
    /// Number of worker threads for parallel execution.
    pub threads: usize,
    /// Maximum retry attempts per transaction before abort.
    pub max_retries: usize,
    /// Wave timeout in milliseconds (safety bound).
    pub wave_timeout_ms: u64,
}

impl Default for StmConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            max_retries: 5,
            wave_timeout_ms: 1000,
        }
    }
}

impl StmConfig {
    /// Create a new config with the specified number of threads.
    pub fn with_threads(threads: usize) -> Self {
        Self {
            threads,
            ..Default::default()
        }
    }

    /// Load configuration from environment variables.
    ///
    /// - `EEZO_STM_MAX_RETRIES`: Max retry attempts (default: 5)
    /// - `EEZO_STM_WAVE_TIMEOUT_MS`: Wave timeout in ms (default: 1000)
    pub fn from_env(threads: usize) -> Self {
        let max_retries = std::env::var("EEZO_STM_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let wave_timeout_ms = std::env::var("EEZO_STM_WAVE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);

        Self {
            threads,
            max_retries,
            wave_timeout_ms,
        }
    }
}

/// Block-STM parallel executor.
///
/// This executor uses Software Transactional Memory (STM) principles to
/// execute transactions in parallel with optimistic concurrency control.
///
/// Key design principles:
/// - Transactions execute speculatively against a multi-version hashmap.
/// - Conflicts are detected at commit time.
/// - Conflicting transactions are retried in subsequent waves.
/// - Deterministic resolution: lower-index transactions always win.
///
/// T73.1: Scaffolding only. The full STM implementation will be added in T73.2+.
pub struct StmExecutor {
    /// Configuration for the STM executor.
    config: StmConfig,
}

impl StmExecutor {
    /// Create a new STM executor with the specified number of threads.
    pub fn new(threads: usize) -> Self {
        Self {
            config: StmConfig::with_threads(threads),
        }
    }

    /// Create a new STM executor with full configuration.
    pub fn with_config(config: StmConfig) -> Self {
        Self { config }
    }

    /// Create a new STM executor loading config from environment.
    pub fn from_env(threads: usize) -> Self {
        Self {
            config: StmConfig::from_env(threads),
        }
    }

    /// Get the number of threads configured.
    pub fn threads(&self) -> usize {
        self.config.threads
    }

    /// Get the configuration.
    pub fn config(&self) -> &StmConfig {
        &self.config
    }
}

impl Executor for StmExecutor {
    /// Execute a block using Block-STM parallel execution.
    ///
    /// T73.1: This is a stub implementation that panics to prevent accidental use.
    /// The actual STM logic will be implemented in T73.2+.
    ///
    /// The implementation will:
    /// 1. Initialize MVHashMap from current node state
    /// 2. Run STM scheduling loop (wave-based parallel execution)
    /// 3. Detect and resolve conflicts deterministically
    /// 4. Commit final state to node
    /// 5. Build and return the Block
    fn execute_block(
        &self,
        _node: &mut SingleNode,
        input: ExecInput,
    ) -> ExecOutcome {
        let start = Instant::now();

        // T73.1: Stub implementation - STM executor is not yet wired into the node.
        // This will only be called if someone explicitly selects STM mode,
        // which is not possible until T73.3 wires it into consensus_runner.
        //
        // For now, return an error to make it clear this is not implemented.
        log::warn!(
            "StmExecutor::execute_block called with {} txs at height {} - NOT IMPLEMENTED YET (T73.2+)",
            input.txs.len(),
            input.height
        );

        ExecOutcome::new(
            Err("StmExecutor not yet implemented (T73.2+)".to_string()),
            start.elapsed(),
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stm_executor_new() {
        let exec = StmExecutor::new(4);
        assert_eq!(exec.threads(), 4);
        assert_eq!(exec.config().max_retries, 5);
        assert_eq!(exec.config().wave_timeout_ms, 1000);
    }

    #[test]
    fn test_stm_config_default() {
        let config = StmConfig::default();
        assert!(config.threads > 0);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.wave_timeout_ms, 1000);
    }

    #[test]
    fn test_stm_executor_with_config() {
        let config = StmConfig {
            threads: 8,
            max_retries: 10,
            wave_timeout_ms: 500,
        };
        let exec = StmExecutor::with_config(config);
        assert_eq!(exec.threads(), 8);
        assert_eq!(exec.config().max_retries, 10);
        assert_eq!(exec.config().wave_timeout_ms, 500);
    }
}