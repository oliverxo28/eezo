//! block_pipeline.rs — T83.3: Block Execution Pipelining
//!
//! This module implements block execution pipelining for the DAG-primary path.
//! The goal is to overlap batch preparation with STM execution:
//!
//! ```text
//! Time →
//! Block N:    [Prepare N] [Execute N] [Commit N]
//! Block N+1:              [Prepare N+1]         [Execute N+1] [Commit N+1]
//! ```
//!
//! ## How It Works
//!
//! 1. While Block N is executing in STM, the pipeline prepares Block N+1's batch
//! 2. Preparation includes:
//!    - Consuming DAG ordered batches
//!    - Fetching bytes from shared mempool
//!    - Decoding and validating transactions
//!    - Applying nonce prefilter
//! 3. When Block N commits, Block N+1 is immediately ready to execute
//!
//! ## Integration Points
//!
//! - `MempoolActorHandle::prefetch()` - Request batch pre-building
//! - `HybridDagHandle::consume_ordered_batches()` - Get DAG-ordered tx hashes
//! - `CommittedMemHead` - Access latest committed state for nonce prefilter
//!
//! ## Configuration
//!
//! - `EEZO_PIPELINE_ENABLED=1` - Enable block pipelining (default: disabled)
//! - `EEZO_PIPELINE_PREFETCH_MS=50` - Time before commit to start prefetch
//!
//! ## Metrics
//!
//! - `eezo_pipeline_prepare_seconds` - Time to prepare next block
//! - `eezo_pipeline_wait_seconds` - Time waiting for prepared block
//! - `eezo_pipeline_hits_total` - Times pipeline had block ready
//! - `eezo_pipeline_misses_total` - Times pipeline wasn't ready

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::oneshot;

use eezo_ledger::{SignedTx, Address};

// =============================================================================
// Configuration
// =============================================================================

/// Check if block pipelining is enabled via environment variable.
pub fn is_pipeline_enabled() -> bool {
    std::env::var("EEZO_PIPELINE_ENABLED")
        .map(|v| {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Get prefetch lead time in milliseconds.
fn prefetch_lead_ms() -> u64 {
    std::env::var("EEZO_PIPELINE_PREFETCH_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50)
}

/// Log pipeline status at startup.
pub fn log_pipeline_status() {
    let enabled = is_pipeline_enabled();
    if enabled {
        log::info!(
            "block-pipeline: ENABLED (EEZO_PIPELINE_ENABLED=1, prefetch_lead_ms={})",
            prefetch_lead_ms()
        );
    } else {
        log::debug!("block-pipeline: disabled (set EEZO_PIPELINE_ENABLED=1 to enable)");
    }
}

// =============================================================================
// PreparedBlock — A block ready for execution
// =============================================================================

/// A block that has been prepared and is ready for execution.
///
/// Contains pre-assembled transactions from DAG + mempool, with all
/// decoding and validation already complete.
#[derive(Debug)]
pub struct PreparedBlock {
    /// Target height for this block
    pub height: u64,
    /// Pre-validated transactions ready for execution
    pub txs: Vec<SignedTx>,
    /// Time when preparation started
    pub prepare_start: Instant,
    /// Time when preparation completed
    pub prepare_end: Instant,
    /// Number of DAG batches consumed
    pub dag_batches_consumed: usize,
    /// Number of transactions from DAG ordering
    pub dag_tx_count: usize,
    /// Number of transactions from mempool fallback
    pub mempool_tx_count: usize,
    /// Total bytes of transactions
    pub total_bytes: usize,
}

impl PreparedBlock {
    /// Create a new prepared block.
    pub fn new(
        height: u64,
        txs: Vec<SignedTx>,
        prepare_start: Instant,
        dag_batches_consumed: usize,
        dag_tx_count: usize,
        mempool_tx_count: usize,
    ) -> Self {
        // Estimate total bytes based on tx count (rough estimate)
        let total_bytes = txs.len() * 256; // ~256 bytes per tx average
        Self {
            height,
            txs,
            prepare_start,
            prepare_end: Instant::now(),
            dag_batches_consumed,
            dag_tx_count,
            mempool_tx_count,
            total_bytes,
        }
    }

    /// Create a new prepared block with known total bytes.
    pub fn with_bytes(
        height: u64,
        txs: Vec<SignedTx>,
        prepare_start: Instant,
        dag_batches_consumed: usize,
        dag_tx_count: usize,
        mempool_tx_count: usize,
        total_bytes: usize,
    ) -> Self {
        Self {
            height,
            txs,
            prepare_start,
            prepare_end: Instant::now(),
            dag_batches_consumed,
            dag_tx_count,
            mempool_tx_count,
            total_bytes,
        }
    }

    /// Get preparation time in seconds.
    pub fn prepare_time_secs(&self) -> f64 {
        self.prepare_end.duration_since(self.prepare_start).as_secs_f64()
    }

    /// Get the total transaction count.
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }
}

// =============================================================================
// BlockPipelineState — Shared state for pipeline coordination
// =============================================================================

/// Shared state for block pipeline coordination.
///
/// This is accessed by:
/// - Main consensus loop: to check for and consume prepared blocks
/// - Background preparer: to store prepared blocks
pub struct BlockPipelineState {
    /// The next prepared block, if available
    prepared: Option<PreparedBlock>,
    /// Height of the last committed block
    last_committed_height: u64,
    /// Whether preparation is currently in progress
    preparing: bool,
    /// Channel to cancel in-progress preparation (if any)
    cancel_tx: Option<oneshot::Sender<()>>,
}

impl BlockPipelineState {
    /// Create a new empty pipeline state.
    pub fn new() -> Self {
        Self {
            prepared: None,
            last_committed_height: 0,
            preparing: false,
            cancel_tx: None,
        }
    }

    /// Check if a prepared block is available for the given height.
    pub fn has_prepared_for(&self, height: u64) -> bool {
        self.prepared.as_ref().map_or(false, |p| p.height == height)
    }

    /// Take the prepared block if it matches the expected height.
    pub fn take_prepared(&mut self, height: u64) -> Option<PreparedBlock> {
        if self.has_prepared_for(height) {
            self.prepared.take()
        } else {
            None
        }
    }

    /// Store a prepared block.
    pub fn set_prepared(&mut self, block: PreparedBlock) {
        self.prepared = Some(block);
        self.preparing = false;
    }

    /// Mark that block at this height has been committed.
    pub fn mark_committed(&mut self, height: u64) {
        self.last_committed_height = height;
        // If we have a stale prepared block, discard it
        if let Some(ref p) = self.prepared {
            if p.height <= height {
                log::debug!(
                    "pipeline: discarding stale prepared block h={} (committed={})",
                    p.height, height
                );
                self.prepared = None;
            }
        }
    }

    /// Check if preparation is in progress.
    pub fn is_preparing(&self) -> bool {
        self.preparing
    }

    /// Mark that preparation has started.
    pub fn start_preparing(&mut self) -> oneshot::Receiver<()> {
        self.preparing = true;
        let (tx, rx) = oneshot::channel();
        self.cancel_tx = Some(tx);
        rx
    }

    /// Cancel any in-progress preparation.
    pub fn cancel_preparation(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
        self.preparing = false;
    }

    /// Get the height of the last committed block.
    pub fn last_committed_height(&self) -> u64 {
        self.last_committed_height
    }
}

impl Default for BlockPipelineState {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// BlockPipeline — Main pipeline coordinator
// =============================================================================

/// Block execution pipeline coordinator.
///
/// Manages the preparation of the next block while the current block
/// is being executed. Uses a shared state protected by a mutex for
/// coordination between the main loop and background preparers.
pub struct BlockPipeline {
    /// Shared pipeline state
    state: Arc<Mutex<BlockPipelineState>>,
    /// Whether pipelining is enabled
    enabled: bool,
}

impl BlockPipeline {
    /// Create a new block pipeline.
    pub fn new() -> Self {
        let enabled = is_pipeline_enabled();
        if enabled {
            log_pipeline_status();
        }
        Self {
            state: Arc::new(Mutex::new(BlockPipelineState::new())),
            enabled,
        }
    }

    /// Check if pipelining is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get a clone of the shared state handle.
    pub fn state(&self) -> Arc<Mutex<BlockPipelineState>> {
        self.state.clone()
    }

    /// Check if a prepared block is available for the given height.
    pub fn has_prepared_for(&self, height: u64) -> bool {
        self.state.lock().has_prepared_for(height)
    }

    /// Take the prepared block if it matches the expected height.
    ///
    /// Returns Some(PreparedBlock) if available, None otherwise.
    /// Records pipeline hit/miss metrics.
    pub fn take_prepared(&self, height: u64) -> Option<PreparedBlock> {
        let mut state = self.state.lock();
        let result = state.take_prepared(height);
        
        #[cfg(feature = "metrics")]
        {
            if result.is_some() {
                pipeline_hits_inc();
            } else if self.enabled {
                pipeline_misses_inc();
            }
        }
        
        result
    }

    /// Mark that a block has been committed.
    pub fn mark_committed(&self, height: u64) {
        self.state.lock().mark_committed(height);
    }

    /// Store a prepared block.
    pub fn set_prepared(&self, block: PreparedBlock) {
        #[cfg(feature = "metrics")]
        pipeline_prepare_observe(block.prepare_time_secs());
        
        log::debug!(
            "pipeline: prepared block h={} with {} txs in {:.2}ms",
            block.height,
            block.tx_count(),
            block.prepare_time_secs() * 1000.0
        );
        
        self.state.lock().set_prepared(block);
    }

    /// Check if preparation should start for the next block.
    pub fn should_start_preparing(&self, current_height: u64) -> bool {
        if !self.enabled {
            return false;
        }
        
        let state = self.state.lock();
        let next_height = current_height + 1;
        
        // Don't prepare if we already have the next block ready
        if state.has_prepared_for(next_height) {
            return false;
        }
        
        // Don't prepare if already preparing
        if state.is_preparing() {
            return false;
        }
        
        true
    }

    /// Start preparation for the next block.
    ///
    /// Returns a cancellation receiver that will be triggered if preparation
    /// should be cancelled (e.g., if the block is no longer needed).
    pub fn start_preparing(&self) -> oneshot::Receiver<()> {
        self.state.lock().start_preparing()
    }
}

impl Default for BlockPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Metrics
// =============================================================================

#[cfg(feature = "metrics")]
mod pipeline_metrics {
    use lazy_static::lazy_static;
    use prometheus::{
        IntCounter, Histogram, register_int_counter, register_histogram
    };

    lazy_static! {
        /// Time to prepare next block.
        pub static ref EEZO_PIPELINE_PREPARE_SECONDS: Histogram = register_histogram!(
            "eezo_pipeline_prepare_seconds",
            "Time to prepare next block in pipeline",
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        ).unwrap();

        /// Time waiting for prepared block.
        pub static ref EEZO_PIPELINE_WAIT_SECONDS: Histogram = register_histogram!(
            "eezo_pipeline_wait_seconds",
            "Time waiting for pipeline to have block ready",
            vec![0.0, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1]
        ).unwrap();

        /// Pipeline hits (block was ready).
        pub static ref EEZO_PIPELINE_HITS: IntCounter = register_int_counter!(
            "eezo_pipeline_hits_total",
            "Number of times pipeline had block ready"
        ).unwrap();

        /// Pipeline misses (block was not ready).
        pub static ref EEZO_PIPELINE_MISSES: IntCounter = register_int_counter!(
            "eezo_pipeline_misses_total",
            "Number of times pipeline did not have block ready"
        ).unwrap();
    }
}

#[cfg(feature = "metrics")]
pub fn pipeline_prepare_observe(secs: f64) {
    pipeline_metrics::EEZO_PIPELINE_PREPARE_SECONDS.observe(secs);
}

#[cfg(feature = "metrics")]
pub fn pipeline_wait_observe(secs: f64) {
    pipeline_metrics::EEZO_PIPELINE_WAIT_SECONDS.observe(secs);
}

#[cfg(feature = "metrics")]
pub fn pipeline_hits_inc() {
    pipeline_metrics::EEZO_PIPELINE_HITS.inc();
}

#[cfg(feature = "metrics")]
pub fn pipeline_misses_inc() {
    pipeline_metrics::EEZO_PIPELINE_MISSES.inc();
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_disabled_by_default() {
        std::env::remove_var("EEZO_PIPELINE_ENABLED");
        assert!(!is_pipeline_enabled());
    }

    #[test]
    fn test_prepared_block_creation() {
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(1));
        
        let block = PreparedBlock::new(
            42,
            vec![],
            start,
            2, // dag_batches
            10, // dag_tx_count
            5, // mempool_tx_count
        );
        
        assert_eq!(block.height, 42);
        assert_eq!(block.dag_batches_consumed, 2);
        assert_eq!(block.dag_tx_count, 10);
        assert_eq!(block.mempool_tx_count, 5);
        assert!(block.prepare_time_secs() > 0.0);
    }

    #[test]
    fn test_pipeline_state_basic() {
        let mut state = BlockPipelineState::new();
        
        assert!(!state.has_prepared_for(1));
        assert_eq!(state.last_committed_height(), 0);
        
        // Simulate preparing block 1
        let start = Instant::now();
        let block = PreparedBlock::new(1, vec![], start, 0, 0, 0);
        state.set_prepared(block);
        
        assert!(state.has_prepared_for(1));
        assert!(!state.has_prepared_for(2));
        
        // Take the prepared block
        let taken = state.take_prepared(1);
        assert!(taken.is_some());
        assert!(!state.has_prepared_for(1));
    }

    #[test]
    fn test_pipeline_state_stale_discard() {
        let mut state = BlockPipelineState::new();
        
        // Prepare block 5
        let start = Instant::now();
        let block = PreparedBlock::new(5, vec![], start, 0, 0, 0);
        state.set_prepared(block);
        assert!(state.has_prepared_for(5));
        
        // Commit block 5 - prepared block should be discarded
        state.mark_committed(5);
        assert!(!state.has_prepared_for(5));
        assert_eq!(state.last_committed_height(), 5);
    }

    #[test]
    fn test_pipeline_state_future_block_preserved() {
        let mut state = BlockPipelineState::new();
        
        // Prepare block 6
        let start = Instant::now();
        let block = PreparedBlock::new(6, vec![], start, 0, 0, 0);
        state.set_prepared(block);
        
        // Commit block 5 - prepared block 6 should be preserved
        state.mark_committed(5);
        assert!(state.has_prepared_for(6));
    }

    #[test]
    fn test_pipeline_should_start_preparing() {
        std::env::set_var("EEZO_PIPELINE_ENABLED", "1");
        let pipeline = BlockPipeline::new();
        
        // Should prepare for block 2 after block 1
        assert!(pipeline.should_start_preparing(1));
        
        // Prepare block 2
        let start = Instant::now();
        let block = PreparedBlock::new(2, vec![], start, 0, 0, 0);
        pipeline.set_prepared(block);
        
        // Should not prepare again
        assert!(!pipeline.should_start_preparing(1));
        
        std::env::remove_var("EEZO_PIPELINE_ENABLED");
    }
}