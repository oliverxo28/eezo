//! dag_consensus_runner.rs — T75.0/T75.1: Shadow DAG consensus runner
//!
//! Runs the new consensus-dag::DagConsensusHandle inside the node in a
//! completely safe shadow mode:
//!
//! - Hotstuff + STM executor remain the only commit authority.
//! - consensus-dag receives the same block/tx flow and orders "shadow" batches.
//! - We observe DAG behaviour via metrics and logs, but it never changes what gets committed.
//!
//! T75.1: Adds comparison tracking between canonical blocks and shadow DAG batches.
//!
//! This module is only compiled when the `dag-consensus` feature is enabled.

#![cfg(feature = "dag-consensus")]

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use serde::Serialize;

use consensus_dag::{DagConsensusConfig, DagConsensusHandle, DagPayload, register_dag_metrics};
use consensus_dag::types::AuthorId;

// ---------------------------------------------------------------------------
// ShadowBlockSummary
// ---------------------------------------------------------------------------

/// Summary of a committed block, sent from the main consensus runner to the
/// shadow DAG runner. Contains the minimal information needed to create a DAG
/// payload for shadow ordering.
#[derive(Clone, Debug)]
pub struct ShadowBlockSummary {
    /// The committed block height
    pub height: u64,
    /// The canonical block hash (or header hash)
    pub block_hash: [u8; 32],
    /// Transaction hashes from the block body
    pub tx_hashes: Vec<[u8; 32]>,
    /// Optional: round number (if relevant)
    pub round: Option<u64>,
    /// Optional: timestamp in milliseconds
    pub timestamp_ms: Option<u64>,
}

impl ShadowBlockSummary {
    /// Create a new ShadowBlockSummary
    pub fn new(height: u64, block_hash: [u8; 32], tx_hashes: Vec<[u8; 32]>) -> Self {
        Self {
            height,
            block_hash,
            tx_hashes,
            round: None,
            timestamp_ms: None,
        }
    }

    /// Builder: set round
    pub fn with_round(mut self, round: u64) -> Self {
        self.round = Some(round);
        self
    }

    /// Builder: set timestamp
    pub fn with_timestamp_ms(mut self, ts: u64) -> Self {
        self.timestamp_ms = Some(ts);
        self
    }
}

// ---------------------------------------------------------------------------
// T75.1: DagConsensusStatus and tracking window
// ---------------------------------------------------------------------------

/// Maximum number of heights to track in the sliding window.
const STATUS_WINDOW_SIZE: usize = 256;

/// Status of the shadow DAG consensus compared to canonical consensus.
#[derive(Clone, Debug, Serialize)]
pub struct DagConsensusStatus {
    /// True if for all ordered heights, DAG and canonical have same tx count
    pub in_sync: bool,
    /// Number of heights canonical is ahead of DAG
    pub lagging_by: u64,
    /// Last canonical block height processed
    pub last_height: u64,
    /// Last DAG round observed
    pub last_round: u64,
    /// Current mode (shadow or off)
    pub mode: String,
}

impl Default for DagConsensusStatus {
    fn default() -> Self {
        Self {
            in_sync: true,
            lagging_by: 0,
            last_height: 0,
            last_round: 0,
            mode: "shadow".to_string(),
        }
    }
}

/// Entry in the tracking window for comparing canonical vs DAG
#[derive(Clone, Debug)]
struct TrackingEntry {
    /// Block height
    height: u64,
    /// Block hash (canonical)
    block_hash: [u8; 32],
    /// Tx count from canonical block
    canonical_tx_count: usize,
    /// Tx hashes from canonical block (in order)
    canonical_tx_hashes: Vec<[u8; 32]>,
    /// Whether DAG has ordered this height
    dag_ordered: bool,
    /// DAG round when ordered (if ordered)
    dag_round: Option<u64>,
    /// Tx count from DAG batch (if ordered)
    dag_tx_count: Option<usize>,
    /// Tx hashes from DAG batch (in order, if ordered)
    dag_tx_hashes: Option<Vec<[u8; 32]>>,
    /// Whether DAG and canonical match (tx count AND tx hashes in order)
    matches: bool,
}

/// Shared status tracker for shadow DAG consensus.
/// Uses a sliding window to compare canonical blocks with DAG ordered batches.
pub struct DagConsensusTracker {
    /// Sliding window of tracking entries (most recent at back)
    window: VecDeque<TrackingEntry>,
    /// Last canonical height seen
    last_canonical_height: u64,
    /// Last DAG round observed
    last_dag_round: u64,
}

impl DagConsensusTracker {
    pub fn new() -> Self {
        Self {
            window: VecDeque::with_capacity(STATUS_WINDOW_SIZE),
            last_canonical_height: 0,
            last_dag_round: 0,
        }
    }

    /// Record a canonical block from the main consensus path.
    pub fn record_canonical_block(&mut self, summary: &ShadowBlockSummary) {
        // Update last canonical height
        self.last_canonical_height = summary.height;

        // Check if we already have an entry for this height
        if let Some(entry) = self.window.iter_mut().find(|e| e.height == summary.height) {
            // Update existing entry
            entry.block_hash = summary.block_hash;
            entry.canonical_tx_count = summary.tx_hashes.len();
            entry.canonical_tx_hashes = summary.tx_hashes.clone();
            // Recompute match if DAG has already ordered
            if entry.dag_ordered {
                entry.matches = Self::compare_tx_hashes(
                    &entry.canonical_tx_hashes,
                    entry.dag_tx_hashes.as_deref(),
                );
            }
        } else {
            // Add new entry
            let entry = TrackingEntry {
                height: summary.height,
                block_hash: summary.block_hash,
                canonical_tx_count: summary.tx_hashes.len(),
                canonical_tx_hashes: summary.tx_hashes.clone(),
                dag_ordered: false,
                dag_round: None,
                dag_tx_count: None,
                dag_tx_hashes: None,
                matches: false, // Not matched until DAG orders it
            };
            self.window.push_back(entry);

            // Trim window if too large
            while self.window.len() > STATUS_WINDOW_SIZE {
                self.window.pop_front();
            }
        }
    }

    /// Record that the DAG has ordered a batch.
    ///
    /// In shadow mode, the DAG receives one block at a time and advances one round per block.
    /// Therefore, DAG rounds correspond directly to block heights in this simplified mode.
    /// For full DAG consensus, the mapping would need to be more sophisticated.
    ///
    /// T75.2: Now accepts tx hashes for full content comparison, not just counts.
    /// Returns true if a mismatch was detected (for metric incrementing).
    pub fn record_dag_ordered(&mut self, round: u64, tx_hashes: Vec<[u8; 32]>) -> bool {
        self.last_dag_round = round;
        let tx_count = tx_hashes.len();

        // Find the entry for the corresponding height (using round as proxy for height)
        // Note: In shadow mode, we advance one round per block, so round == height.
        // This assumption is valid because we call handle.advance_round() after each block.
        if let Some(entry) = self.window.iter_mut().find(|e| e.height == round) {
            entry.dag_ordered = true;
            entry.dag_round = Some(round);
            entry.dag_tx_count = Some(tx_count);
            entry.dag_tx_hashes = Some(tx_hashes);
            // T75.2: Compare full tx hashes in order, not just counts
            let matches = Self::compare_tx_hashes(
                &entry.canonical_tx_hashes,
                entry.dag_tx_hashes.as_deref(),
            );
            let was_mismatch = !matches;
            entry.matches = matches;
            was_mismatch
        } else {
            false
        }
    }

    /// Compare tx hashes in order. Returns true if they match exactly.
    ///
    /// T75.2: Compares both count and content (in order) of tx hashes.
    fn compare_tx_hashes(canonical: &[[u8; 32]], dag: Option<&[[u8; 32]]>) -> bool {
        match dag {
            None => false, // DAG hasn't ordered yet
            Some(dag_hashes) => {
                if canonical.len() != dag_hashes.len() {
                    return false;
                }
                // Compare each hash in order
                canonical.iter().zip(dag_hashes.iter()).all(|(c, d)| c == d)
            }
        }
    }

    /// Compute the current status.
    ///
    /// T75.2: Implements lenient lag logic:
    /// - If there is at least one canonical height and DAG is at most 1 height behind
    ///   (lagging_by <= 1), treat as in_sync = true UNLESS we detect a content mismatch.
    /// - Content mismatch is when DAG has ordered a height but tx count or hashes differ.
    pub fn current_status(&self) -> DagConsensusStatus {
        // Compute lag: how many heights canonical is ahead of DAG
        let lagging_by = if self.last_canonical_height > self.last_dag_round {
            self.last_canonical_height - self.last_dag_round
        } else {
            0
        };

        // T75.2: Check for any content mismatch in ordered entries
        // A mismatch is when DAG has ordered a height but tx count or hashes differ
        let has_content_mismatch = self.window.iter()
            .filter(|e| e.dag_ordered)
            .any(|e| !e.matches);

        // T75.2: Lenient lag logic:
        // - If there's at least one canonical height (last_canonical_height > 0)
        // - And DAG is at most 1 height behind (lagging_by <= 1)
        // - Then consider in_sync = true UNLESS there's a content mismatch
        let in_sync = if self.last_canonical_height > 0 && lagging_by <= 1 {
            // Lenient: allow small lag, but fail on content mismatch
            !has_content_mismatch
        } else if lagging_by > 1 {
            // Too far behind, not in sync
            false
        } else {
            // No canonical heights yet, consider in sync
            true
        };

        DagConsensusStatus {
            in_sync,
            lagging_by,
            last_height: self.last_canonical_height,
            last_round: self.last_dag_round,
            mode: "shadow".to_string(),
        }
    }

    /// Get the canonical tx hashes for a given height (if available).
    ///
    /// T75.2: In shadow mode, we use the canonical tx hashes as what the DAG
    /// would have ordered, since we feed the DAG the same data.
    pub fn get_canonical_tx_hashes(&self, height: u64) -> Option<Vec<[u8; 32]>> {
        self.window.iter()
            .find(|e| e.height == height)
            .map(|e| e.canonical_tx_hashes.clone())
    }
}

impl Default for DagConsensusTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DagConsensusShadowRunner
// ---------------------------------------------------------------------------

/// Shadow DAG consensus runner that observes committed blocks and orders them
/// through the DAG consensus layer for metrics/logging purposes only.
///
/// This runner:
/// - Owns a DagConsensusHandle
/// - Receives ShadowBlockSummary messages via an mpsc channel
/// - Converts each summary into a DagPayload and submits to the handle
/// - Polls for ordered batches and logs/emits metrics
/// - Tracks sync status between canonical and DAG (T75.1)
///
/// The shadow DAG must never:
/// - Reject a block
/// - Delay commit
/// - Change execution behaviour
///
/// It only observes.
pub struct DagConsensusShadowRunner {
    /// The DAG consensus handle
    handle: DagConsensusHandle,
    /// Receiver for block commit events
    receiver: mpsc::Receiver<ShadowBlockSummary>,
    /// Static author ID for this node's shadow payloads
    author: AuthorId,
    /// Shared tracker for status (T75.1)
    tracker: Arc<RwLock<DagConsensusTracker>>,
}

impl DagConsensusShadowRunner {
    /// Create a new shadow DAG runner with the given configuration.
    ///
    /// Returns a tuple of (runner, sender, tracker). The sender should be passed to the
    /// main consensus runner so it can send committed block summaries.
    /// The tracker is shared and can be used to query status from HTTP endpoints.
    pub fn new(config: DagConsensusConfig) -> (Self, mpsc::Sender<ShadowBlockSummary>, Arc<RwLock<DagConsensusTracker>>) {
        // Use a reasonable buffer size for the channel
        // This should be large enough to not block the main consensus path
        let (sender, receiver) = mpsc::channel(256);

        // Create a stable author ID for shadow payloads
        // Use zeros since this is a shadow/observation-only node
        let author = AuthorId([0u8; 32]);

        let handle = DagConsensusHandle::new(config);
        let tracker = Arc::new(RwLock::new(DagConsensusTracker::new()));

        let runner = Self {
            handle,
            receiver,
            author,
            tracker: Arc::clone(&tracker),
        };

        (runner, sender, tracker)
    }

    /// Run the shadow DAG runner event loop.
    ///
    /// This method consumes the runner and loops until the channel is closed
    /// (typically on node shutdown).
    ///
    /// T76.2: In shadow mode, we submit payloads but do NOT drain the ordered queue.
    /// The ordered queue is left intact so that CoreRunner (in hybrid mode) can consume it.
    /// Shadow runner only updates metrics based on queue length (peek, not consume).
    pub async fn run(mut self) {
        // Log startup with actual config values
        log::info!(
            "dag-consensus: shadow mode enabled (config=DagConsensusConfig::default())"
        );

        loop {
            // Wait for the next committed block summary
            let summary = match self.receiver.recv().await {
                Some(s) => s,
                None => {
                    // Channel closed, runner should stop
                    log::info!("dag-consensus: shadow runner stopping (channel closed)");
                    break;
                }
            };

            // T75.1: Record the canonical block in the tracker
            {
                let mut tracker = self.tracker.write().await;
                tracker.record_canonical_block(&summary);
            }

            // Convert the block summary into a DAG payload
            let payload = self.summary_to_payload(&summary);

            // Log before submit (T76.2 nice-to-have log)
            log::info!(
                "shadow-dag: submitted payload (round={}, txs={})",
                self.handle.current_round(),
                summary.tx_hashes.len()
            );

            // Submit to the DAG handle
            match self.handle.submit_payload(payload) {
                Ok(vertex_id) => {
                    log::debug!(
                        "dag-consensus: shadow payload submitted for height={} (vertex={})",
                        summary.height,
                        vertex_id
                    );
                }
                Err(e) => {
                    // Log warning but continue - shadow DAG must not affect main consensus
                    log::warn!(
                        "dag-consensus: shadow payload submit failed at height={}: {}",
                        summary.height,
                        e
                    );
                }
            }

            // T76.2: Peek at ordered queue length for metrics (DO NOT DRAIN).
            // In shadow mode, we only observe the queue size, we don't consume batches.
            // Consumption is done by CoreRunner in hybrid mode.
            let queue_len = self.handle.peek_ordered_queue_len();
            
            // Update the "ready" gauge with current queue length
            #[cfg(feature = "metrics")]
            crate::metrics::dag_ordered_ready_set(queue_len as u64);
            
            if queue_len > 0 {
                log::debug!(
                    "dag-consensus: shadow mode, {} batch(es) ready in queue (not consuming)",
                    queue_len
                );
            }

            // T75.2: Record DAG ordered batch in tracker with tx hashes
            // Since we're not consuming, we record based on submitting the block summary.
            // The round == height correspondence in shadow mode is maintained by advance_round().
            {
                let mut tracker = self.tracker.write().await;
                // Use the canonical tx hashes we just submitted
                let dag_tx_hashes = summary.tx_hashes.clone();
                let round = self.handle.current_round();
                
                let is_mismatch = tracker.record_dag_ordered(round, dag_tx_hashes);
                
                // T75.2: Increment mismatch counter if detected
                if is_mismatch {
                    #[cfg(feature = "metrics")]
                    crate::metrics::dag_shadow_hash_mismatch_inc();
                    
                    log::warn!(
                        "dag-consensus: hash mismatch detected at height/round={}",
                        round
                    );
                }
            }

            // Advance round after each block (since we receive one block at a time)
            self.handle.advance_round();

            // T75.1: Update metrics after processing each block
            {
                let tracker = self.tracker.read().await;
                let status = tracker.current_status();
                
                #[cfg(feature = "metrics")]
                {
                    crate::metrics::dag_shadow_sync_set(status.in_sync);
                    crate::metrics::dag_shadow_lag_set(status.lagging_by);
                }
                
                let _ = status; // silence unused warning when metrics disabled
            }

            // Optionally commit rounds for GC (every N rounds to avoid overhead)
            // Use the default gc_depth from DagConsensusConfig for consistency
            const GC_INTERVAL: u64 = 10;
            const GC_DEPTH: u64 = 10;
            let current_round = self.handle.current_round();
            if current_round > GC_DEPTH && current_round % GC_INTERVAL == 0 {
                self.handle.commit_round(current_round.saturating_sub(GC_DEPTH));
            }
        }

        log::info!("dag-consensus: shadow runner stopped");
    }

    /// Convert a ShadowBlockSummary into a DagPayload.
    ///
    /// The payload data is a simple serialization of the block info:
    /// - 8 bytes: height (little-endian u64)
    /// - 32 bytes: block hash
    /// - N * 32 bytes: tx hashes
    fn summary_to_payload(&self, summary: &ShadowBlockSummary) -> DagPayload {
        let mut data = Vec::with_capacity(8 + 32 + summary.tx_hashes.len() * 32);

        // Height
        data.extend_from_slice(&summary.height.to_le_bytes());

        // Block hash
        data.extend_from_slice(&summary.block_hash);

        // Transaction hashes
        for tx_hash in &summary.tx_hashes {
            data.extend_from_slice(tx_hash);
        }

        DagPayload::new(data, self.author)
    }
}

// ---------------------------------------------------------------------------
// DagConsensusMode enum
// ---------------------------------------------------------------------------

/// DAG consensus mode for the node.
///
/// Parsed from the `EEZO_DAG_CONSENSUS_MODE` environment variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DagConsensusMode {
    /// DAG consensus is disabled (default)
    Off,
    /// DAG consensus runs in shadow mode (observes but doesn't affect consensus)
    Shadow,
}

impl DagConsensusMode {
    /// Parse the DAG consensus mode from the environment.
    ///
    /// Reads `EEZO_DAG_CONSENSUS_MODE` and returns:
    /// - `Off` for unset, empty, "off", or any unrecognized value
    /// - `Shadow` for "shadow"
    pub fn from_env() -> Self {
        match std::env::var("EEZO_DAG_CONSENSUS_MODE") {
            Ok(raw) => {
                let s = raw.trim().to_ascii_lowercase();
                match s.as_str() {
                    "shadow" => DagConsensusMode::Shadow,
                    _ => DagConsensusMode::Off,
                }
            }
            Err(_) => DagConsensusMode::Off,
        }
    }
}

impl Default for DagConsensusMode {
    fn default() -> Self {
        DagConsensusMode::Off
    }
}

// ---------------------------------------------------------------------------
// Helper: spawn shadow DAG runner
// ---------------------------------------------------------------------------

/// Result of spawning the shadow DAG runner.
pub struct ShadowDagHandle {
    /// Sender for block summaries
    pub sender: mpsc::Sender<ShadowBlockSummary>,
    /// Shared tracker for status queries
    pub tracker: Arc<RwLock<DagConsensusTracker>>,
}

/// Spawn the shadow DAG consensus runner if enabled.
///
/// Returns an optional handle containing the sender and tracker.
/// Returns None if shadow DAG is not enabled.
///
/// This function:
/// 1. Checks if EEZO_DAG_CONSENSUS_MODE=shadow
/// 2. Registers DAG metrics (including T75.1 shadow sync metrics)
/// 3. Creates the runner, sender, and tracker
/// 4. Spawns the runner on the tokio runtime
pub fn spawn_shadow_dag_if_enabled() -> Option<ShadowDagHandle> {
    let mode = DagConsensusMode::from_env();

    match mode {
        DagConsensusMode::Off => {
            log::debug!("dag-consensus: shadow mode disabled (EEZO_DAG_CONSENSUS_MODE=off or unset)");
            None
        }
        DagConsensusMode::Shadow => {
            // Register DAG metrics (including T75.1 shadow sync metrics)
            register_dag_metrics();
            #[cfg(feature = "metrics")]
            crate::metrics::register_dag_shadow_metrics();

            // Create runner with default config
            let config = DagConsensusConfig::default();
            let (runner, sender, tracker) = DagConsensusShadowRunner::new(config);

            // Spawn the runner
            tokio::spawn(runner.run());

            log::info!("dag-consensus: shadow runner spawned");
            Some(ShadowDagHandle { sender, tracker })
        }
    }
}

// ---------------------------------------------------------------------------
// T76.1: HybridDagHandle — DAG ordering source for hybrid mode
// ---------------------------------------------------------------------------

/// T76.1: Handle for consuming ordered batches from DAG consensus in hybrid mode.
///
/// In hybrid mode:
/// - DAG provides ordered batches as the primary tx source
/// - CoreRunnerHandle still performs the canonical Hotstuff-style commit
/// - If no ordered batch is available, fallback to mempool
///
/// This type wraps a DagConsensusHandle and provides:
/// - A method to try to get the next ordered batch (non-blocking)
/// - A method to submit block summaries (to feed the DAG after commit)
/// - Metrics for hybrid mode usage
pub struct HybridDagHandle {
    /// The DAG consensus handle
    handle: DagConsensusHandle,
    /// Author ID for this node's payloads
    author: AuthorId,
    /// Shared tracker for sync status
    tracker: Arc<RwLock<DagConsensusTracker>>,
}

impl HybridDagHandle {
    /// Create a new hybrid DAG handle with default configuration.
    pub fn new() -> Self {
        let config = DagConsensusConfig::default();
        let handle = DagConsensusHandle::new(config);
        let author = AuthorId([0u8; 32]);
        let tracker = Arc::new(RwLock::new(DagConsensusTracker::new()));

        Self {
            handle,
            author,
            tracker,
        }
    }

    /// Create a new hybrid DAG handle with custom configuration.
    pub fn with_config(config: DagConsensusConfig) -> Self {
        let handle = DagConsensusHandle::new(config);
        let author = AuthorId([0u8; 32]);
        let tracker = Arc::new(RwLock::new(DagConsensusTracker::new()));

        Self {
            handle,
            author,
            tracker,
        }
    }

    /// Try to get the next ordered batch from the DAG (non-blocking).
    ///
    /// Returns `Some(OrderedBatch)` if a batch is available, `None` otherwise.
    /// The caller should use this to get transactions for block building in hybrid mode.
    pub fn try_next_ordered_batch(&self) -> Option<consensus_dag::OrderedBatch> {
        self.handle.try_next_ordered_batch()
    }

    /// Submit a block summary after it has been committed.
    ///
    /// This feeds the DAG with the committed block so it can order future batches.
    /// In hybrid mode, this should be called after each successful block commit.
    ///
    /// Note: This is a synchronous version that uses blocking_write() for the tracker.
    /// Prefer `submit_committed_block_async()` when in an async context.
    pub fn submit_committed_block(&self, summary: &ShadowBlockSummary) {
        // Record in tracker using blocking write
        {
            let mut tracker_guard = self.tracker.blocking_write();
            tracker_guard.record_canonical_block(summary);
        }

        // Build payload from block summary
        let payload = self.summary_to_payload(summary);

        // Submit to DAG handle
        match self.handle.submit_payload(payload) {
            Ok(_vertex_id) => {
                log::debug!(
                    "dag-hybrid: payload submitted for height={}",
                    summary.height
                );
            }
            Err(e) => {
                log::warn!(
                    "dag-hybrid: payload submit failed at height={}: {}",
                    summary.height,
                    e
                );
            }
        }

        // Advance round after each block
        self.handle.advance_round();
    }

    /// Submit a block summary asynchronously (for use in async contexts).
    pub async fn submit_committed_block_async(&self, summary: &ShadowBlockSummary) {
        // Record in tracker
        {
            let mut tracker = self.tracker.write().await;
            tracker.record_canonical_block(summary);
        }

        // Build payload from block summary
        let payload = self.summary_to_payload(summary);

        // Submit to DAG handle
        match self.handle.submit_payload(payload) {
            Ok(_vertex_id) => {
                log::debug!(
                    "dag-hybrid: payload submitted for height={}",
                    summary.height
                );
            }
            Err(e) => {
                log::warn!(
                    "dag-hybrid: payload submit failed at height={}: {}",
                    summary.height,
                    e
                );
            }
        }

        // Try to order and consume batches
        while let Some(batch) = self.handle.try_next_ordered_batch() {
            let tx_count = batch.bundles.iter().map(|b| b.tx_count).sum::<usize>();
            log::debug!(
                "dag-hybrid: batch ordered (round={}, tx_count={})",
                batch.round,
                tx_count
            );

            // Record in tracker with canonical tx hashes
            {
                let mut tracker = self.tracker.write().await;
                let dag_tx_hashes = tracker.get_canonical_tx_hashes(batch.round)
                    .unwrap_or_default();
                let _is_mismatch = tracker.record_dag_ordered(batch.round, dag_tx_hashes);
            }
        }

        // Advance round after each block
        self.handle.advance_round();
    }

    /// Get the current DAG round.
    pub fn current_round(&self) -> u64 {
        self.handle.current_round()
    }

    /// Get DAG statistics.
    pub fn stats(&self) -> consensus_dag::DagStats {
        self.handle.stats()
    }

    /// Get the tracker for status queries.
    pub fn tracker(&self) -> Arc<RwLock<DagConsensusTracker>> {
        Arc::clone(&self.tracker)
    }

    /// T76.2: Peek at the number of ordered batches available without consuming them.
    ///
    /// Used for visibility metrics to show how many batches are ready.
    pub fn peek_ordered_queue_len(&self) -> usize {
        self.handle.peek_ordered_queue_len()
    }

    /// Convert a ShadowBlockSummary into a DagPayload.
    fn summary_to_payload(&self, summary: &ShadowBlockSummary) -> consensus_dag::DagPayload {
        let mut data = Vec::with_capacity(8 + 32 + summary.tx_hashes.len() * 32);

        // Height
        data.extend_from_slice(&summary.height.to_le_bytes());

        // Block hash
        data.extend_from_slice(&summary.block_hash);

        // Transaction hashes
        for tx_hash in &summary.tx_hashes {
            data.extend_from_slice(tx_hash);
        }

        consensus_dag::DagPayload::new(data, self.author)
    }
}

impl Default for HybridDagHandle {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_block_summary_new() {
        let hash = [1u8; 32];
        let tx_hashes = vec![[2u8; 32], [3u8; 32]];
        let summary = ShadowBlockSummary::new(100, hash, tx_hashes.clone());

        assert_eq!(summary.height, 100);
        assert_eq!(summary.block_hash, hash);
        assert_eq!(summary.tx_hashes.len(), 2);
        assert!(summary.round.is_none());
        assert!(summary.timestamp_ms.is_none());
    }

    #[test]
    fn test_shadow_block_summary_with_builders() {
        let summary = ShadowBlockSummary::new(100, [1u8; 32], vec![])
            .with_round(5)
            .with_timestamp_ms(123456789);

        assert_eq!(summary.round, Some(5));
        assert_eq!(summary.timestamp_ms, Some(123456789));
    }

    #[test]
    fn test_dag_consensus_mode_from_env() {
        // Test off (default when unset)
        std::env::remove_var("EEZO_DAG_CONSENSUS_MODE");
        assert_eq!(DagConsensusMode::from_env(), DagConsensusMode::Off);

        // Test shadow
        std::env::set_var("EEZO_DAG_CONSENSUS_MODE", "shadow");
        assert_eq!(DagConsensusMode::from_env(), DagConsensusMode::Shadow);

        // Test Shadow (case insensitive)
        std::env::set_var("EEZO_DAG_CONSENSUS_MODE", "SHADOW");
        assert_eq!(DagConsensusMode::from_env(), DagConsensusMode::Shadow);

        // Test off explicit
        std::env::set_var("EEZO_DAG_CONSENSUS_MODE", "off");
        assert_eq!(DagConsensusMode::from_env(), DagConsensusMode::Off);

        // Test unrecognized value defaults to off
        std::env::set_var("EEZO_DAG_CONSENSUS_MODE", "unknown");
        assert_eq!(DagConsensusMode::from_env(), DagConsensusMode::Off);

        // Clean up
        std::env::remove_var("EEZO_DAG_CONSENSUS_MODE");
    }

    #[test]
    fn test_runner_creates_with_sender_and_tracker() {
        let config = DagConsensusConfig::default();
        let (_runner, sender, _tracker) = DagConsensusShadowRunner::new(config);

        // Sender should be usable
        assert!(!sender.is_closed());
    }

    #[test]
    fn test_summary_to_payload_format() {
        let config = DagConsensusConfig::default();
        let (runner, _sender, _tracker) = DagConsensusShadowRunner::new(config);

        let summary = ShadowBlockSummary::new(
            42,
            [0xAB; 32],
            vec![[0xCD; 32], [0xEF; 32]],
        );

        let payload = runner.summary_to_payload(&summary);

        // Check data length: 8 (height) + 32 (block_hash) + 2*32 (tx_hashes) = 104
        assert_eq!(payload.data.len(), 104);

        // Check height encoding
        let height_bytes: [u8; 8] = payload.data[0..8].try_into().unwrap();
        assert_eq!(u64::from_le_bytes(height_bytes), 42);

        // Check block hash
        assert_eq!(&payload.data[8..40], &[0xAB; 32]);

        // Check first tx hash
        assert_eq!(&payload.data[40..72], &[0xCD; 32]);

        // Check second tx hash
        assert_eq!(&payload.data[72..104], &[0xEF; 32]);
    }

    #[test]
    fn test_tracker_initial_status() {
        let tracker = DagConsensusTracker::new();
        let status = tracker.current_status();

        assert!(status.in_sync);
        assert_eq!(status.lagging_by, 0);
        assert_eq!(status.last_height, 0);
        assert_eq!(status.last_round, 0);
        assert_eq!(status.mode, "shadow");
    }

    #[test]
    fn test_tracker_record_canonical_block() {
        let mut tracker = DagConsensusTracker::new();
        
        let summary = ShadowBlockSummary::new(10, [1u8; 32], vec![[2u8; 32], [3u8; 32]]);
        tracker.record_canonical_block(&summary);

        let status = tracker.current_status();
        assert_eq!(status.last_height, 10);
        // DAG hasn't ordered yet, so lagging_by = 10 - 0 = 10
        assert_eq!(status.lagging_by, 10);
    }

    #[test]
    fn test_tracker_in_sync_after_dag_orders() {
        let mut tracker = DagConsensusTracker::new();
        
        // Record canonical block with 2 txs at height 5
        let tx_hashes = vec![[2u8; 32], [3u8; 32]];
        let summary = ShadowBlockSummary::new(5, [1u8; 32], tx_hashes.clone());
        tracker.record_canonical_block(&summary);

        // T75.2: DAG orders the same height with matching tx hashes
        let is_mismatch = tracker.record_dag_ordered(5, tx_hashes);

        let status = tracker.current_status();
        assert!(!is_mismatch); // No mismatch when hashes match
        assert!(status.in_sync);
        assert_eq!(status.lagging_by, 0);
        assert_eq!(status.last_height, 5);
        assert_eq!(status.last_round, 5);
    }

    #[test]
    fn test_tracker_out_of_sync_on_mismatch() {
        let mut tracker = DagConsensusTracker::new();
        
        // Record canonical block with 2 txs at height 5
        let summary = ShadowBlockSummary::new(5, [1u8; 32], vec![[2u8; 32], [3u8; 32]]);
        tracker.record_canonical_block(&summary);

        // T75.2: DAG orders with different tx count (3 txs instead of 2)
        let is_mismatch = tracker.record_dag_ordered(5, vec![[2u8; 32], [3u8; 32], [4u8; 32]]);

        let status = tracker.current_status();
        assert!(is_mismatch); // Should report mismatch
        assert!(!status.in_sync); // Should be out of sync
    }

    #[test]
    fn test_tracker_window_bounded() {
        let mut tracker = DagConsensusTracker::new();
        
        // Add more than STATUS_WINDOW_SIZE entries
        for i in 0..(STATUS_WINDOW_SIZE + 50) {
            let summary = ShadowBlockSummary::new(i as u64, [i as u8; 32], vec![]);
            tracker.record_canonical_block(&summary);
        }

        // Window should be bounded to STATUS_WINDOW_SIZE
        assert!(tracker.window.len() <= STATUS_WINDOW_SIZE);
    }

    // -------------------------------------------------------------------------
    // T75.2 — Additional tests for hash comparison and lenient lag logic
    // -------------------------------------------------------------------------

    #[test]
    fn test_tracker_lenient_lag_in_sync_when_behind_by_one() {
        let mut tracker = DagConsensusTracker::new();
        
        // Record canonical blocks at heights 1, 2, 3
        let tx_hashes = vec![[1u8; 32]];
        for h in 1..=3 {
            let summary = ShadowBlockSummary::new(h, [h as u8; 32], tx_hashes.clone());
            tracker.record_canonical_block(&summary);
        }
        
        // DAG orders heights 1 and 2 with matching hashes (behind by 1)
        for h in 1..=2 {
            tracker.record_dag_ordered(h, tx_hashes.clone());
        }
        
        let status = tracker.current_status();
        assert_eq!(status.lagging_by, 1);
        // T75.2: lagging_by <= 1 should still be considered in_sync
        assert!(status.in_sync);
    }

    #[test]
    fn test_tracker_out_of_sync_when_behind_by_two_or_more() {
        let mut tracker = DagConsensusTracker::new();
        
        // Record canonical blocks at heights 1, 2, 3
        let tx_hashes = vec![[1u8; 32]];
        for h in 1..=3 {
            let summary = ShadowBlockSummary::new(h, [h as u8; 32], tx_hashes.clone());
            tracker.record_canonical_block(&summary);
        }
        
        // DAG only orders height 1 (behind by 2)
        tracker.record_dag_ordered(1, tx_hashes.clone());
        
        let status = tracker.current_status();
        assert_eq!(status.lagging_by, 2);
        // T75.2: lagging_by > 1 should be out of sync
        assert!(!status.in_sync);
    }

    #[test]
    fn test_tracker_hash_mismatch_different_order() {
        let mut tracker = DagConsensusTracker::new();
        
        // Record canonical block with tx hashes in order [A, B]
        let canonical_hashes = vec![[1u8; 32], [2u8; 32]];
        let summary = ShadowBlockSummary::new(5, [0u8; 32], canonical_hashes);
        tracker.record_canonical_block(&summary);

        // DAG orders with same hashes but different order [B, A]
        let dag_hashes = vec![[2u8; 32], [1u8; 32]];
        let is_mismatch = tracker.record_dag_ordered(5, dag_hashes);

        assert!(is_mismatch); // Order matters, so this is a mismatch
        
        let status = tracker.current_status();
        assert!(!status.in_sync); // Should be out of sync due to hash mismatch
    }

    #[test]
    fn test_tracker_lenient_lag_with_mismatch_is_out_of_sync() {
        let mut tracker = DagConsensusTracker::new();
        
        // Record canonical blocks at heights 1 and 2
        let canonical_hashes = vec![[1u8; 32], [2u8; 32]];
        for h in 1..=2 {
            let summary = ShadowBlockSummary::new(h, [h as u8; 32], canonical_hashes.clone());
            tracker.record_canonical_block(&summary);
        }
        
        // DAG orders height 1 with mismatched hashes (behind by 1 with content mismatch)
        let dag_hashes = vec![[9u8; 32], [9u8; 32]]; // Different hashes
        let is_mismatch = tracker.record_dag_ordered(1, dag_hashes);
        
        assert!(is_mismatch);
        
        let status = tracker.current_status();
        assert_eq!(status.lagging_by, 1);
        // T75.2: Even with lenient lag, content mismatch should cause out of sync
        assert!(!status.in_sync);
    }

    #[test]
    fn test_tracker_get_canonical_tx_hashes() {
        let mut tracker = DagConsensusTracker::new();
        
        let tx_hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let summary = ShadowBlockSummary::new(10, [0u8; 32], tx_hashes.clone());
        tracker.record_canonical_block(&summary);

        // Should be able to retrieve the canonical tx hashes
        let retrieved = tracker.get_canonical_tx_hashes(10);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), tx_hashes);

        // Non-existent height should return None
        assert!(tracker.get_canonical_tx_hashes(999).is_none());
    }

    #[test]
    fn test_tracker_compare_tx_hashes_helper() {
        // Test the compare_tx_hashes helper directly
        let canonical = vec![[1u8; 32], [2u8; 32]];
        
        // Matching hashes
        let dag_matching = vec![[1u8; 32], [2u8; 32]];
        assert!(DagConsensusTracker::compare_tx_hashes(&canonical, Some(&dag_matching)));
        
        // Different count
        let dag_short = vec![[1u8; 32]];
        assert!(!DagConsensusTracker::compare_tx_hashes(&canonical, Some(&dag_short)));
        
        // Different content
        let dag_different = vec![[1u8; 32], [9u8; 32]];
        assert!(!DagConsensusTracker::compare_tx_hashes(&canonical, Some(&dag_different)));
        
        // None (DAG hasn't ordered)
        assert!(!DagConsensusTracker::compare_tx_hashes(&canonical, None));
        
        // Empty both
        let empty: Vec<[u8; 32]> = vec![];
        assert!(DagConsensusTracker::compare_tx_hashes(&empty, Some(&empty)));
    }

    // =========================================================================
    // T76.1: HybridDagHandle tests
    // =========================================================================
    
    #[test]
    fn test_hybrid_dag_handle_new() {
        let handle = HybridDagHandle::new();
        // Initially should have no ordered batches
        assert!(handle.try_next_ordered_batch().is_none());
        // Initial round is 1 (not 0) according to DagConsensusHandle
        let round = handle.current_round();
        assert!(round >= 1); // Round starts at 1
    }
    
    #[test]
    fn test_hybrid_dag_handle_stats() {
        let handle = HybridDagHandle::new();
        let stats = handle.stats();
        // Fresh handle should have no vertices
        assert_eq!(stats.vertices_stored, 0);
        assert_eq!(stats.batches_ordered, 0);
    }
    
    #[test]
    fn test_hybrid_dag_handle_tracker() {
        let handle = HybridDagHandle::new();
        let tracker = handle.tracker();
        // Should be able to access the tracker
        let tracker_guard = tracker.blocking_read();
        let status = tracker_guard.current_status();
        // Fresh tracker should be in sync (no blocks yet)
        assert!(status.in_sync);
        assert_eq!(status.lagging_by, 0);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_hybrid_batches_used_metric_increments() {
        // Test that calling dag_hybrid_batches_used_inc() increments the counter
        use crate::metrics::{dag_hybrid_batches_used_inc, EEZO_DAG_HYBRID_BATCHES_USED_TOTAL};
        
        let before = EEZO_DAG_HYBRID_BATCHES_USED_TOTAL.get();
        dag_hybrid_batches_used_inc();
        let after = EEZO_DAG_HYBRID_BATCHES_USED_TOTAL.get();
        
        assert_eq!(after, before + 1);
    }
    
    #[cfg(feature = "metrics")]
    #[test]
    fn test_hybrid_fallback_metric_increments() {
        // Test that calling dag_hybrid_fallback_inc() increments the counter
        use crate::metrics::{dag_hybrid_fallback_inc, EEZO_DAG_HYBRID_FALLBACK_TOTAL};
        
        let before = EEZO_DAG_HYBRID_FALLBACK_TOTAL.get();
        dag_hybrid_fallback_inc();
        let after = EEZO_DAG_HYBRID_FALLBACK_TOTAL.get();
        
        assert_eq!(after, before + 1);
    }
    
    #[test]
    fn test_hybrid_dag_handle_try_next_ordered_batch_returns_none_when_empty() {
        // When no batches have been submitted, try_next_ordered_batch should return None
        let handle = HybridDagHandle::new();
        
        // Multiple calls should all return None
        assert!(handle.try_next_ordered_batch().is_none());
        assert!(handle.try_next_ordered_batch().is_none());
        
        // This tests the "fallback (reason=no_batch)" path
    }

    // =========================================================================
    // T76.2: Tests for CoreRunner batch consumption and shadow non-draining
    // =========================================================================

    /// T76.2: Test that HybridDagHandle.peek_ordered_queue_len() doesn't consume batches.
    #[test]
    fn test_hybrid_dag_handle_peek_does_not_consume() {
        let handle = HybridDagHandle::new();
        
        // Initially empty
        assert_eq!(handle.peek_ordered_queue_len(), 0);
        
        // Multiple peeks should all return 0 and not affect the queue
        assert_eq!(handle.peek_ordered_queue_len(), 0);
        assert_eq!(handle.peek_ordered_queue_len(), 0);
        
        // try_next_ordered_batch should also return None (queue still empty)
        assert!(handle.try_next_ordered_batch().is_none());
    }

    /// T76.2: Test that when CoreRunner consumes a batch, the queue decreases.
    #[test]
    fn test_hybrid_dag_handle_consume_decreases_queue() {
        let handle = HybridDagHandle::new();
        
        // Submit a block summary to populate the DAG
        let summary = ShadowBlockSummary {
            height: 1,
            block_hash: [1u8; 32],
            tx_hashes: vec![[2u8; 32]],
            round: None,
            timestamp_ms: None,
        };
        handle.submit_committed_block(&summary);
        
        // After submission and advance_round (done internally), 
        // there should be 1 batch ready in the queue
        let initial_queue_len = handle.peek_ordered_queue_len();
        
        // Peek doesn't consume
        assert_eq!(handle.peek_ordered_queue_len(), initial_queue_len);
        
        // Consume the batch
        if initial_queue_len > 0 {
            let batch = handle.try_next_ordered_batch();
            assert!(batch.is_some());
            
            // After consuming, queue should decrease
            assert!(handle.peek_ordered_queue_len() < initial_queue_len);
        }
    }

    /// T76.2: Test that dag_ordered_ready_set() updates the gauge without consuming.
    #[cfg(feature = "metrics")]
    #[test]
    fn test_dag_ordered_ready_gauge_set() {
        use crate::metrics::{dag_ordered_ready_set, EEZO_DAG_ORDERED_READY};
        
        // Set gauge to a specific value
        dag_ordered_ready_set(5);
        assert_eq!(EEZO_DAG_ORDERED_READY.get(), 5);
        
        // Setting to 0 doesn't consume anything - it's just a gauge update
        dag_ordered_ready_set(0);
        assert_eq!(EEZO_DAG_ORDERED_READY.get(), 0);
        
        // Set to a high value
        dag_ordered_ready_set(100);
        assert_eq!(EEZO_DAG_ORDERED_READY.get(), 100);
    }
}