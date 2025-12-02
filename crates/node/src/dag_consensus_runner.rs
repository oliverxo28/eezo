//! dag_consensus_runner.rs — T75.0: Shadow DAG consensus runner
//!
//! Runs the new consensus-dag::DagConsensusHandle inside the node in a
//! completely safe shadow mode:
//!
//! - Hotstuff + STM executor remain the only commit authority.
//! - consensus-dag receives the same block/tx flow and orders "shadow" batches.
//! - We observe DAG behaviour via metrics and logs, but it never changes what gets committed.
//!
//! This module is only compiled when the `dag-consensus` feature is enabled.

#![cfg(feature = "dag-consensus")]

use std::sync::Arc;
use tokio::sync::mpsc;

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
}

impl DagConsensusShadowRunner {
    /// Create a new shadow DAG runner with the given configuration.
    ///
    /// Returns a tuple of (runner, sender). The sender should be passed to the
    /// main consensus runner so it can send committed block summaries.
    pub fn new(config: DagConsensusConfig) -> (Self, mpsc::Sender<ShadowBlockSummary>) {
        // Use a reasonable buffer size for the channel
        // This should be large enough to not block the main consensus path
        let (sender, receiver) = mpsc::channel(256);

        // Create a stable author ID for shadow payloads
        // Use zeros since this is a shadow/observation-only node
        let author = AuthorId([0u8; 32]);

        let handle = DagConsensusHandle::new(config);

        let runner = Self {
            handle,
            receiver,
            author,
        };

        (runner, sender)
    }

    /// Run the shadow DAG runner event loop.
    ///
    /// This method consumes the runner and loops until the channel is closed
    /// (typically on node shutdown).
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

            // Convert the block summary into a DAG payload
            let payload = self.summary_to_payload(&summary);

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

            // Poll for ordered batches and log them
            while let Some(batch) = self.handle.try_next_ordered_batch() {
                log::debug!(
                    "dag-consensus: shadow batch ordered (round={}, blocks={}, total_vertices={})",
                    batch.round,
                    batch.bundles.len(),
                    batch.vertex_count()
                );
            }

            // Advance round after each block (since we receive one block at a time)
            self.handle.advance_round();

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

/// Spawn the shadow DAG consensus runner if enabled.
///
/// Returns an optional sender that the main consensus runner can use to send
/// committed block summaries. Returns None if shadow DAG is not enabled.
///
/// This function:
/// 1. Checks if EEZO_DAG_CONSENSUS_MODE=shadow
/// 2. Registers DAG metrics
/// 3. Creates the runner and sender
/// 4. Spawns the runner on the tokio runtime
pub fn spawn_shadow_dag_if_enabled() -> Option<mpsc::Sender<ShadowBlockSummary>> {
    let mode = DagConsensusMode::from_env();

    match mode {
        DagConsensusMode::Off => {
            log::debug!("dag-consensus: shadow mode disabled (EEZO_DAG_CONSENSUS_MODE=off or unset)");
            None
        }
        DagConsensusMode::Shadow => {
            // Register DAG metrics
            register_dag_metrics();

            // Create runner with default config
            let config = DagConsensusConfig::default();
            let (runner, sender) = DagConsensusShadowRunner::new(config);

            // Spawn the runner
            tokio::spawn(runner.run());

            log::info!("dag-consensus: shadow runner spawned");
            Some(sender)
        }
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
    fn test_runner_creates_with_sender() {
        let config = DagConsensusConfig::default();
        let (_runner, sender) = DagConsensusShadowRunner::new(config);

        // Sender should be usable
        assert!(!sender.is_closed());
    }

    #[test]
    fn test_summary_to_payload_format() {
        let config = DagConsensusConfig::default();
        let (runner, _sender) = DagConsensusShadowRunner::new(config);

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
}