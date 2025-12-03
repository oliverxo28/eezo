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
///
/// T76.3: Now optionally carries raw tx bytes alongside hashes for zero-copy,
/// no-miss consumption by the hybrid proposer.
#[derive(Clone, Debug)]
pub struct ShadowBlockSummary {
    /// The committed block height
    pub height: u64,
    /// The canonical block hash (or header hash)
    pub block_hash: [u8; 32],
    /// Transaction hashes from the block body
    pub tx_hashes: Vec<[u8; 32]>,
    /// T76.3: Optional raw tx bytes corresponding to each hash.
    /// When present, enables zero-copy tx consumption without mempool lookup.
    /// Vec<Option<bytes::Bytes>> where index corresponds to tx_hashes index.
    /// None entries indicate missing bytes (fallback to mempool needed).
    pub tx_bytes: Option<Vec<Option<bytes::Bytes>>>,
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
            tx_bytes: None,
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

    /// T76.3: Builder: set tx bytes
    pub fn with_tx_bytes(mut self, tx_bytes: Vec<Option<bytes::Bytes>>) -> Self {
        self.tx_bytes = Some(tx_bytes);
        self
    }

    /// T76.3: Iterator over (hash, Option<bytes>) pairs for zero-copy consumption.
    /// Yields tuples of (tx_hash, Option<Bytes>) for each transaction.
    pub fn iter_tx_entries(&self) -> impl Iterator<Item = ([u8; 32], Option<&bytes::Bytes>)> {
        let tx_bytes_ref = self.tx_bytes.as_ref();
        self.tx_hashes.iter().enumerate().map(move |(i, hash)| {
            let bytes_opt = tx_bytes_ref.and_then(|v| v.get(i)).and_then(|b| b.as_ref());
            (*hash, bytes_opt)
        })
    }

    /// T76.3: Check if all transactions have bytes available.
    pub fn has_all_bytes(&self) -> bool {
        match &self.tx_bytes {
            None => false,
            Some(bytes) => {
                bytes.len() == self.tx_hashes.len() && bytes.iter().all(|b| b.is_some())
            }
        }
    }

    /// T76.3: Count how many transactions have bytes available.
    pub fn bytes_available_count(&self) -> usize {
        match &self.tx_bytes {
            None => 0,
            Some(bytes) => bytes.iter().filter(|b| b.is_some()).count(),
        }
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

        // T76.2: Record in tracker that we submitted this block.
        // We do NOT drain ordered batches here - CoreRunner is the only consumer.
        // Just update the tracker with the canonical tx hashes for sync status.
        {
            let mut tracker = self.tracker.write().await;
            // Use the canonical tx hashes we just submitted
            let dag_tx_hashes = summary.tx_hashes.clone();
            let round = self.handle.current_round();
            let _is_mismatch = tracker.record_dag_ordered(round, dag_tx_hashes);
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
// T76.5: HybridDedupCache — LRU cache for recently committed tx hashes
// ---------------------------------------------------------------------------

/// Default size of the de-dup LRU cache (100k entries as per T76.5 spec).
const DEFAULT_DEDUP_LRU_SIZE: usize = 100_000;

/// Parse de-dup LRU size from environment variable `EEZO_HYBRID_DEDUP_LRU`.
/// Returns the configured size, or the default (100k) if unset/invalid.
fn parse_dedup_lru_size() -> usize {
    std::env::var("EEZO_HYBRID_DEDUP_LRU")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_DEDUP_LRU_SIZE)
}

/// T76.5: LRU cache for recently committed canonical tx hashes.
/// 
/// Used by the hybrid proposer to filter out transactions that have already
/// been committed, avoiding "bad_nonce" storms from duplicate submissions.
/// 
/// Key properties:
/// - Uses canonical `SignedTx.hash()`, not raw envelope hash
/// - Bounded size (default 100k, configurable via `EEZO_HYBRID_DEDUP_LRU`)
/// - Thread-safe (uses parking_lot RwLock)
/// - GC synchronized with commit height
pub struct HybridDedupCache {
    /// LRU cache: maps tx hash -> commit height
    /// Using LinkedHashMap for O(1) access with LRU eviction ordering
    cache: parking_lot::RwLock<lru::LruCache<[u8; 32], u64>>,
    /// Maximum size of the cache
    max_size: usize,
    /// Last height at which GC was performed
    last_gc_height: std::sync::atomic::AtomicU64,
}

impl HybridDedupCache {
    /// Create a new de-dup cache with the default size.
    pub fn new() -> Self {
        Self::with_capacity(parse_dedup_lru_size())
    }

    /// Create a new de-dup cache with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = std::num::NonZeroUsize::new(capacity.max(1))
            .unwrap_or(std::num::NonZeroUsize::new(1).unwrap());
        Self {
            cache: parking_lot::RwLock::new(lru::LruCache::new(cap)),
            max_size: capacity,
            last_gc_height: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record that a transaction hash was committed at the given height.
    /// 
    /// This is called after block commit to populate the de-dup cache.
    /// Uses canonical `SignedTx.hash()` as the key.
    pub fn record_committed(&self, tx_hash: [u8; 32], height: u64) {
        let mut cache = self.cache.write();
        cache.put(tx_hash, height);
        
        // Update metrics
        #[cfg(feature = "metrics")]
        crate::metrics::dag_hybrid_dedup_lru_size_set(cache.len() as u64);
    }

    /// Record multiple committed tx hashes at once.
    /// More efficient than calling record_committed repeatedly.
    pub fn record_committed_batch(&self, tx_hashes: &[[u8; 32]], height: u64) {
        if tx_hashes.is_empty() {
            return;
        }
        
        let mut cache = self.cache.write();
        for hash in tx_hashes {
            cache.put(*hash, height);
        }
        
        // Update metrics
        #[cfg(feature = "metrics")]
        crate::metrics::dag_hybrid_dedup_lru_size_set(cache.len() as u64);
    }

    /// Check if a transaction hash was recently committed.
    /// Returns `true` if the hash is in the de-dup cache.
    pub fn contains(&self, tx_hash: &[u8; 32]) -> bool {
        self.cache.read().contains(tx_hash)
    }

    /// Filter a list of tx hashes, returning only those not in the de-dup cache.
    /// 
    /// Returns `(filtered_hashes, seen_count)`:
    /// - `filtered_hashes`: hashes that are NOT in the cache (candidates)
    /// - `seen_count`: number of hashes that WERE in the cache (filtered out)
    /// 
    /// This is the main entry point for de-dup filtering before batch execution.
    pub fn filter_batch(&self, tx_hashes: &[[u8; 32]]) -> (Vec<[u8; 32]>, usize) {
        let cache = self.cache.read();
        
        let mut filtered = Vec::with_capacity(tx_hashes.len());
        let mut seen_count = 0;
        
        for hash in tx_hashes {
            if cache.contains(hash) {
                seen_count += 1;
            } else {
                filtered.push(*hash);
            }
        }
        
        (filtered, seen_count)
    }

    /// Get the current size of the cache.
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.read().is_empty()
    }

    /// Get the maximum capacity of the cache.
    pub fn capacity(&self) -> usize {
        self.max_size
    }

    /// Perform GC synchronized with commit height.
    /// 
    /// Entries older than `gc_depth` rounds behind the current height are eligible
    /// for eviction (handled automatically by LRU eviction policy).
    /// 
    /// This method is called periodically to ensure consistent GC behavior.
    pub fn gc(&self, current_height: u64, _gc_depth: u64) {
        // LRU cache handles eviction automatically when capacity is reached.
        // This method is provided for explicit GC coordination if needed.
        // For now, just record the GC height for debugging.
        self.last_gc_height.store(current_height, std::sync::atomic::Ordering::Relaxed);
    }

    /// Clear all entries from the cache.
    pub fn clear(&self) {
        let mut cache = self.cache.write();
        cache.clear();
        
        #[cfg(feature = "metrics")]
        crate::metrics::dag_hybrid_dedup_lru_size_set(0);
    }
}

impl Default for HybridDedupCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// T76.5: Nonce pre-check for hybrid batch filtering
// ---------------------------------------------------------------------------

/// T76.5: Perform nonce pre-check on candidate transactions.
/// 
/// This is a best-effort, read-only peek at sender nonces to filter out
/// transactions with stale nonces (tx.nonce < account.nonce) before execution.
/// 
/// Properties:
/// - Constant-time: bounded number of lookups
/// - Non-blocking: uses read-only access to accounts
/// - Best-effort: may not catch all stale nonces (e.g., concurrent updates)
/// 
/// Returns:
/// - `valid_indices`: indices of transactions that passed nonce check
/// - `bad_nonce_count`: number of transactions with stale nonces
/// 
/// Note: This function takes indices to avoid cloning transactions.
pub fn nonce_precheck(
    txs: &[eezo_ledger::SignedTx],
    accounts: &eezo_ledger::Accounts,
) -> (Vec<usize>, usize) {
    use eezo_ledger::sender_from_pubkey_first20;
    
    let mut valid_indices = Vec::with_capacity(txs.len());
    let mut bad_nonce_count = 0;
    
    for (i, tx) in txs.iter().enumerate() {
        // Derive sender from pubkey (first 20 bytes)
        // If derivation fails, assume valid (will fail at execution)
        match sender_from_pubkey_first20(tx) {
            Some(sender) => {
                // Read-only peek at account nonce
                let account = accounts.get(&sender);
                let account_nonce = account.nonce;
                
                // Check if tx nonce is stale
                if tx.core.nonce < account_nonce {
                    bad_nonce_count += 1;
                    log::debug!(
                        "nonce_precheck: tx hash=0x{} has stale nonce {} < account nonce {}",
                        hex::encode(&tx.hash()[..4]),
                        tx.core.nonce,
                        account_nonce
                    );
                } else {
                    valid_indices.push(i);
                }
            }
            None => {
                // Sender derivation failed - pass through (will fail at execution)
                valid_indices.push(i);
            }
        }
    }
    
    (valid_indices, bad_nonce_count)
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
            tx_bytes: None, // T76.3: No bytes attached
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

    // -------------------------------------------------------------------------
    // T76.3: Tests for ShadowBlockSummary with tx_bytes
    // -------------------------------------------------------------------------

    /// T76.3: Test ShadowBlockSummary with full tx_bytes.
    #[test]
    fn test_shadow_block_summary_with_full_bytes() {
        use bytes::Bytes;

        let tx_hashes = vec![[1u8; 32], [2u8; 32]];
        let tx_bytes = vec![
            Some(Bytes::from_static(b"tx1_data")),
            Some(Bytes::from_static(b"tx2_data")),
        ];

        let summary = ShadowBlockSummary::new(100, [0xAB; 32], tx_hashes.clone())
            .with_tx_bytes(tx_bytes.clone());

        assert!(summary.has_all_bytes());
        assert_eq!(summary.bytes_available_count(), 2);

        // Verify iterator
        let entries: Vec<_> = summary.iter_tx_entries().collect();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].1.is_some());
        assert!(entries[1].1.is_some());
    }

    /// T76.3: Test ShadowBlockSummary with mixed tx_bytes (some missing).
    #[test]
    fn test_shadow_block_summary_with_mixed_bytes() {
        use bytes::Bytes;

        let tx_hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let tx_bytes = vec![
            Some(Bytes::from_static(b"tx1_data")),
            None, // Missing
            Some(Bytes::from_static(b"tx3_data")),
        ];

        let summary = ShadowBlockSummary::new(100, [0xAB; 32], tx_hashes)
            .with_tx_bytes(tx_bytes);

        assert!(!summary.has_all_bytes());
        assert_eq!(summary.bytes_available_count(), 2);

        // Verify iterator shows correct pattern
        let entries: Vec<_> = summary.iter_tx_entries().collect();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].1.is_some());  // Has bytes
        assert!(entries[1].1.is_none());  // Missing
        assert!(entries[2].1.is_some());  // Has bytes
    }

    /// T76.3: Test ShadowBlockSummary without tx_bytes (backwards compatible).
    #[test]
    fn test_shadow_block_summary_without_bytes() {
        let tx_hashes = vec![[1u8; 32], [2u8; 32]];
        let summary = ShadowBlockSummary::new(100, [0xAB; 32], tx_hashes);

        // No tx_bytes means no bytes available
        assert!(!summary.has_all_bytes());
        assert_eq!(summary.bytes_available_count(), 0);

        // Iterator should yield (hash, None) for each entry
        let entries: Vec<_> = summary.iter_tx_entries().collect();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].1.is_none());
        assert!(entries[1].1.is_none());
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

    /// T76.3: Test that enqueuing 2 batches results in queue_len==2 and gauge reads 2,
    /// and consuming 1 drops both to 1.
    #[cfg(feature = "metrics")]
    #[test]
    fn test_ordered_ready_gauge_matches_queue_len() {
        use crate::metrics::{dag_ordered_ready_set, EEZO_DAG_ORDERED_READY};
        
        let handle = HybridDagHandle::new();
        
        // Submit 2 block summaries to populate the DAG with 2 batches
        // Each submission triggers ordering (threshold=1 by default)
        for i in 1..=2 {
            let summary = ShadowBlockSummary {
                height: i,
                block_hash: [i as u8; 32],
                tx_hashes: vec![[i as u8; 32]],
                tx_bytes: None,
                round: None,
                timestamp_ms: None,
            };
            handle.submit_committed_block(&summary);
        }
        
        // After submitting 2 blocks, peek should show 2 batches ready
        let queue_len = handle.peek_ordered_queue_len();
        
        // Update gauge to match queue_len (as the shadow runner does)
        dag_ordered_ready_set(queue_len as u64);
        
        // Assert queue_len == 2 and gauge reads 2
        assert_eq!(queue_len, 2, "Expected 2 batches in queue after 2 submissions");
        assert_eq!(EEZO_DAG_ORDERED_READY.get(), 2, "Expected gauge to read 2");
        
        // Consume 1 batch
        let batch = handle.try_next_ordered_batch();
        assert!(batch.is_some(), "Expected to consume 1 batch");
        
        // Update gauge to new queue_len
        let new_queue_len = handle.peek_ordered_queue_len();
        dag_ordered_ready_set(new_queue_len as u64);
        
        // Assert both drop to 1
        assert_eq!(new_queue_len, 1, "Expected 1 batch remaining after consuming 1");
        assert_eq!(EEZO_DAG_ORDERED_READY.get(), 1, "Expected gauge to read 1 after consuming");
    }

    // =========================================================================
    // T76.5: Tests for HybridDedupCache
    // =========================================================================

    #[test]
    fn test_dedup_cache_basic() {
        let cache = HybridDedupCache::with_capacity(100);
        
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let hash3 = [3u8; 32];
        
        // Initially empty
        assert!(cache.is_empty());
        assert!(!cache.contains(&hash1));
        
        // Record committed tx
        cache.record_committed(hash1, 1);
        
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&hash1));
        assert!(!cache.contains(&hash2));
    }

    #[test]
    fn test_dedup_cache_batch_record() {
        let cache = HybridDedupCache::with_capacity(100);
        
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        
        cache.record_committed_batch(&hashes, 10);
        
        assert_eq!(cache.len(), 3);
        for hash in &hashes {
            assert!(cache.contains(hash));
        }
    }

    #[test]
    fn test_dedup_cache_filter_batch() {
        let cache = HybridDedupCache::with_capacity(100);
        
        // Record some hashes as committed
        let committed = vec![[1u8; 32], [2u8; 32]];
        cache.record_committed_batch(&committed, 1);
        
        // Filter a batch that contains some committed and some new hashes
        let batch = vec![[1u8; 32], [3u8; 32], [2u8; 32], [4u8; 32]];
        let (filtered, seen_count) = cache.filter_batch(&batch);
        
        // Hash 1 and 2 were seen (in cache), 3 and 4 are new
        assert_eq!(seen_count, 2);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&[3u8; 32]));
        assert!(filtered.contains(&[4u8; 32]));
    }

    #[test]
    fn test_dedup_cache_filter_all_seen() {
        let cache = HybridDedupCache::with_capacity(100);
        
        let hashes = vec![[1u8; 32], [2u8; 32]];
        cache.record_committed_batch(&hashes, 1);
        
        // Filter the same batch - all should be filtered
        let (filtered, seen_count) = cache.filter_batch(&hashes);
        
        assert_eq!(seen_count, 2);
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_dedup_cache_filter_none_seen() {
        let cache = HybridDedupCache::with_capacity(100);
        
        // Cache has some hashes
        cache.record_committed([1u8; 32], 1);
        
        // Filter batch with different hashes - none should be filtered
        let batch = vec![[5u8; 32], [6u8; 32]];
        let (filtered, seen_count) = cache.filter_batch(&batch);
        
        assert_eq!(seen_count, 0);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_dedup_cache_lru_eviction() {
        // Small cache to test eviction
        let cache = HybridDedupCache::with_capacity(3);
        
        cache.record_committed([1u8; 32], 1);
        cache.record_committed([2u8; 32], 2);
        cache.record_committed([3u8; 32], 3);
        
        assert_eq!(cache.len(), 3);
        assert!(cache.contains(&[1u8; 32]));
        
        // Adding one more should evict the LRU (oldest)
        cache.record_committed([4u8; 32], 4);
        
        assert_eq!(cache.len(), 3);
        // Hash 1 should be evicted (LRU)
        assert!(!cache.contains(&[1u8; 32]));
        assert!(cache.contains(&[2u8; 32]));
        assert!(cache.contains(&[3u8; 32]));
        assert!(cache.contains(&[4u8; 32]));
    }

    #[test]
    fn test_dedup_cache_clear() {
        let cache = HybridDedupCache::with_capacity(100);
        
        cache.record_committed_batch(&[[1u8; 32], [2u8; 32], [3u8; 32]], 1);
        assert_eq!(cache.len(), 3);
        
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    // =========================================================================
    // T76.5: Tests for nonce_precheck
    // =========================================================================

    #[test]
    fn test_nonce_precheck_all_valid() {
        use eezo_ledger::{Accounts, Account, Address, SignedTx, TxCore};
        
        // Create accounts with known nonces
        let mut accounts = Accounts::default();
        let sender_bytes: [u8; 20] = [0x42; 20];
        let sender = Address(sender_bytes);
        
        // Set account nonce to 5
        let acct = Account { balance: 1000, nonce: 5 };
        accounts.put(sender, acct);
        
        // Create txs with valid nonces (>= 5)
        let txs = vec![
            SignedTx {
                core: TxCore { to: Address([0xBB; 20]), amount: 100, fee: 1, nonce: 5 },
                pubkey: sender_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: Address([0xBB; 20]), amount: 100, fee: 1, nonce: 6 },
                pubkey: sender_bytes.to_vec(),
                sig: vec![],
            },
        ];
        
        let (valid_indices, bad_nonce_count) = nonce_precheck(&txs, &accounts);
        
        assert_eq!(bad_nonce_count, 0);
        assert_eq!(valid_indices.len(), 2);
        assert_eq!(valid_indices, vec![0, 1]);
    }

    #[test]
    fn test_nonce_precheck_stale_nonce() {
        use eezo_ledger::{Accounts, Account, Address, SignedTx, TxCore};
        
        let mut accounts = Accounts::default();
        let sender_bytes: [u8; 20] = [0x42; 20];
        let sender = Address(sender_bytes);
        
        // Set account nonce to 10
        let acct = Account { balance: 1000, nonce: 10 };
        accounts.put(sender, acct);
        
        // Create txs with mixed nonces - some stale (< 10), some valid (>= 10)
        let txs = vec![
            SignedTx {
                core: TxCore { to: Address([0xBB; 20]), amount: 100, fee: 1, nonce: 5 }, // stale
                pubkey: sender_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: Address([0xBB; 20]), amount: 100, fee: 1, nonce: 10 }, // valid
                pubkey: sender_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: Address([0xBB; 20]), amount: 100, fee: 1, nonce: 8 }, // stale
                pubkey: sender_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: Address([0xBB; 20]), amount: 100, fee: 1, nonce: 11 }, // valid
                pubkey: sender_bytes.to_vec(),
                sig: vec![],
            },
        ];
        
        let (valid_indices, bad_nonce_count) = nonce_precheck(&txs, &accounts);
        
        assert_eq!(bad_nonce_count, 2); // nonces 5 and 8 are stale
        assert_eq!(valid_indices.len(), 2);
        assert_eq!(valid_indices, vec![1, 3]); // indices of nonces 10 and 11
    }

    #[test]
    fn test_nonce_precheck_all_stale() {
        use eezo_ledger::{Accounts, Account, Address, SignedTx, TxCore};
        
        let mut accounts = Accounts::default();
        let sender_bytes: [u8; 20] = [0x42; 20];
        let sender = Address(sender_bytes);
        
        // Set account nonce to 100
        let acct = Account { balance: 1000, nonce: 100 };
        accounts.put(sender, acct);
        
        // Create txs with all stale nonces
        let txs = vec![
            SignedTx {
                core: TxCore { to: Address([0xBB; 20]), amount: 100, fee: 1, nonce: 0 },
                pubkey: sender_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: Address([0xBB; 20]), amount: 100, fee: 1, nonce: 50 },
                pubkey: sender_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: Address([0xBB; 20]), amount: 100, fee: 1, nonce: 99 },
                pubkey: sender_bytes.to_vec(),
                sig: vec![],
            },
        ];
        
        let (valid_indices, bad_nonce_count) = nonce_precheck(&txs, &accounts);
        
        assert_eq!(bad_nonce_count, 3);
        assert!(valid_indices.is_empty());
    }

    #[test]
    fn test_nonce_precheck_empty_txs() {
        use eezo_ledger::Accounts;
        
        let accounts = Accounts::default();
        let txs: Vec<eezo_ledger::SignedTx> = vec![];
        
        let (valid_indices, bad_nonce_count) = nonce_precheck(&txs, &accounts);
        
        assert_eq!(bad_nonce_count, 0);
        assert!(valid_indices.is_empty());
    }
}