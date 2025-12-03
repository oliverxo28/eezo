//! handle.rs — DagConsensusHandle façade
//!
//! Public façade for running DAG consensus. This type hides the internal
//! builder/order/store wiring behind a small, stable API that crates/node
//! can call later.
//!
//! ## Design
//!
//! - **DagConsensusHandle**: Main entry point, owns store/builder/orderer
//! - **DagPayload**: Wrapper for transaction payload data
//! - **OrderedBatch**: Batch of ordered blocks ready for execution
//! - **DagStats**: Statistics for monitoring/testing
//! - **DagError**: Error type for handle operations

use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::builder::PayloadBuilder;
use crate::metrics;
use crate::order::OrderingEngine;
use crate::store::DagStore;
use crate::types::{AuthorId, DagConsensusConfig, DagNode, OrderedBundle, PayloadId, Round, VertexId};

// ---------------------------------------------------------------------------
// Supporting Types
// ---------------------------------------------------------------------------

/// Wrapper for a transaction payload to be included in a DAG vertex.
///
/// Contains raw transaction bytes that will be hashed to form the payload digest.
#[derive(Clone, Debug)]
pub struct DagPayload {
    /// Raw transaction bytes (serialized transactions)
    pub data: Vec<u8>,

    /// Author (node) submitting this payload
    pub author: AuthorId,
}

impl DagPayload {
    /// Create a new payload from raw bytes and author.
    pub fn new(data: Vec<u8>, author: AuthorId) -> Self {
        Self { data, author }
    }

    /// Compute the payload digest (blake3 hash).
    pub fn digest(&self) -> PayloadId {
        PayloadId::compute(&self.data)
    }
}

/// A batch of ordered blocks ready for execution.
///
/// Wraps one or more `OrderedBundle` values that have been finalized
/// and are ready to be passed to the executor.
#[derive(Clone, Debug)]
pub struct OrderedBatch {
    /// The round that was finalized
    pub round: u64,

    /// Ordered bundles in this batch (usually one per round)
    pub bundles: Vec<OrderedBundle>,
}

impl OrderedBatch {
    /// Create a new ordered batch from a single bundle.
    pub fn from_bundle(bundle: OrderedBundle) -> Self {
        let round = bundle.round.as_u64();
        Self {
            round,
            bundles: vec![bundle],
        }
    }

    /// Total number of vertices across all bundles.
    pub fn vertex_count(&self) -> usize {
        self.bundles.iter().map(|b| b.vertices.len()).sum()
    }

    /// Total transaction count estimate across all bundles.
    pub fn tx_count(&self) -> usize {
        self.bundles.iter().map(|b| b.tx_count).sum()
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty() || self.bundles.iter().all(|b| b.is_empty())
    }
}

/// Statistics for the DAG consensus handle.
///
/// Used for monitoring and testing purposes.
#[derive(Clone, Debug, Default)]
pub struct DagStats {
    /// Total vertices stored in the DAG
    pub vertices_stored: usize,

    /// Current round being processed
    pub current_round: u64,

    /// Number of ordered batches emitted
    pub batches_ordered: u64,

    /// Committed round (for GC tracking)
    pub committed_round: Option<u64>,
}

/// Error type for DAG consensus handle operations.
#[derive(Debug, Clone)]
pub enum DagError {
    /// Payload exceeds configured limits
    PayloadTooLarge { size: usize, max: usize },

    /// Invalid vertex structure
    InvalidVertex(String),

    /// Internal error
    Internal(String),
}

impl std::fmt::Display for DagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DagError::PayloadTooLarge { size, max } => {
                write!(f, "payload too large: {} bytes (max: {})", size, max)
            }
            DagError::InvalidVertex(msg) => write!(f, "invalid vertex: {}", msg),
            DagError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for DagError {}

// ---------------------------------------------------------------------------
// DagConsensusHandle
// ---------------------------------------------------------------------------

/// Public façade for running DAG consensus.
///
/// This type is what the node will eventually hold. It hides the internal
/// builder/order/store wiring behind a small, stable API.
///
/// ## Example
///
/// ```rust,ignore
/// use consensus_dag::{DagConsensusConfig, DagConsensusHandle, DagPayload};
/// use consensus_dag::types::AuthorId;
///
/// let handle = DagConsensusHandle::new(DagConsensusConfig::default());
/// let payload = DagPayload::new(vec![1, 2, 3], AuthorId([0u8; 32]));
/// handle.submit_payload(payload).unwrap();
///
/// if let Some(batch) = handle.try_next_ordered_batch() {
///     println!("Ordered batch: round={}", batch.round);
/// }
/// ```
pub struct DagConsensusHandle {
    /// Configuration for this handle
    config: DagConsensusConfig,

    /// DAG vertex storage
    store: Arc<DagStore>,

    /// Payload builder for digest computation.
    /// Currently not used directly (payloads compute their own digest),
    /// but reserved for future integration with mempool peek operations.
    #[allow(dead_code)]
    builder: Arc<PayloadBuilder>,

    /// Ordering engine
    orderer: Arc<OrderingEngine>,

    /// Current round for new vertices
    current_round: Arc<RwLock<Round>>,

    /// Queue of ordered batches ready to be consumed
    ordered_queue: Arc<RwLock<VecDeque<OrderedBatch>>>,

    /// Statistics
    stats: Arc<RwLock<DagStats>>,

    /// Last ordered round (to avoid re-ordering)
    last_ordered_round: Arc<RwLock<Option<Round>>>,
}

impl DagConsensusHandle {
    /// Construct a new DAG consensus instance with the given config.
    pub fn new(config: DagConsensusConfig) -> Self {
        let store = Arc::new(DagStore::new());
        let builder = Arc::new(PayloadBuilder::new());

        // Create ordering engine with threshold from config
        let mut orderer = OrderingEngine::new();
        orderer.threshold = config.ordering_threshold;
        let orderer = Arc::new(orderer);

        Self {
            config,
            store,
            builder,
            orderer,
            current_round: Arc::new(RwLock::new(Round(1))),
            ordered_queue: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(DagStats::default())),
            last_ordered_round: Arc::new(RwLock::new(None)),
        }
    }

    /// Submit a new vertex payload (e.g., tx hashes) for the local node.
    ///
    /// This corresponds roughly to "propose a vertex" from the node's point of view.
    /// The payload is stored in the DAG and will be ordered when enough vertices
    /// from the current round are available.
    ///
    /// Returns the VertexId of the created vertex on success.
    pub fn submit_payload(&self, payload: DagPayload) -> Result<VertexId, DagError> {
        // Validate payload size (target_payload_bytes used as maximum limit)
        if payload.data.len() > self.config.target_payload_bytes {
            return Err(DagError::PayloadTooLarge {
                size: payload.data.len(),
                max: self.config.target_payload_bytes,
            });
        }

        // Compute payload digest
        let payload_digest = payload.digest();

        // Get current round and parent vertices
        let current_round = *self.current_round.read();
        let parents = self.get_parent_vertices(current_round);

        // Create the DAG node
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let node = DagNode::new(current_round, parents, payload_digest, payload.author, timestamp);

        let vertex_id = node.id;

        // Store in DAG
        self.store.put_node(&node);

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.vertices_stored = self.store.node_count();
            stats.current_round = current_round.as_u64();
        }

        // T74.3: Update metrics on vertex submit
        metrics::dag_vertices_inc();
        metrics::dag_pending_vertices_inc();
        metrics::dag_current_round_set(current_round.as_u64());

        // Try to order current round
        self.try_order_current_round();

        Ok(vertex_id)
    }

    /// Try to read the next batch of ordered blocks (if any).
    ///
    /// Non-blocking: returns `None` if there is currently nothing ordered.
    pub fn try_next_ordered_batch(&self) -> Option<OrderedBatch> {
        self.ordered_queue.write().pop_front()
    }

    /// Peek at the number of ordered batches available without consuming them.
    ///
    /// T76.2: Used for visibility metrics - returns the current queue length.
    pub fn peek_ordered_queue_len(&self) -> usize {
        self.ordered_queue.read().len()
    }

    /// Get statistics about the DAG consensus state.
    pub fn stats(&self) -> DagStats {
        let mut stats = self.stats.read().clone();
        stats.vertices_stored = self.store.node_count();
        stats.committed_round = self.store.committed_round().map(|r| r.as_u64());
        stats
    }

    /// Advance to the next round.
    ///
    /// This is typically called after a round has been ordered and committed.
    pub fn advance_round(&self) {
        let mut round = self.current_round.write();
        *round = round.next();

        let mut stats = self.stats.write();
        stats.current_round = round.as_u64();

        // T74.3: Update metrics on round advance
        metrics::dag_round_advance_inc();
        metrics::dag_current_round_set(round.as_u64());
    }

    /// Get the current round number.
    pub fn current_round(&self) -> u64 {
        self.current_round.read().as_u64()
    }

    /// Commit a round (triggers GC if appropriate).
    pub fn commit_round(&self, round: u64) {
        self.store.gc(Round(round));

        let mut stats = self.stats.write();
        stats.committed_round = Some(round);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Get parent vertices from the previous round.
    fn get_parent_vertices(&self, current_round: Round) -> Vec<VertexId> {
        if current_round.as_u64() <= 1 {
            return vec![];
        }

        let prev_round = current_round.prev().unwrap_or(Round(0));
        let parents = self.store.get_ready_round(prev_round);

        // Limit to max_parents
        parents
            .iter()
            .take(self.config.max_parents)
            .map(|n| n.id)
            .collect()
    }

    /// Try to order the current round if conditions are met.
    fn try_order_current_round(&self) {
        let current_round = *self.current_round.read();

        // Check if we already ordered this round
        {
            let last_ordered = self.last_ordered_round.read();
            if let Some(last) = *last_ordered {
                if last >= current_round {
                    return;
                }
            }
        }

        // Try to order
        if let Some(bundle) = self.orderer.try_order_round(&self.store, current_round) {
            // Create batch and enqueue
            let batch = OrderedBatch::from_bundle(bundle);
            
            // T74.3: Get vertex count from the batch for metrics (after batch creation)
            let vertex_count = batch.vertex_count() as u64;

            {
                let mut queue = self.ordered_queue.write();
                queue.push_back(batch);
            }

            // Update last ordered round
            {
                let mut last_ordered = self.last_ordered_round.write();
                *last_ordered = Some(current_round);
            }

            // Update stats
            {
                let mut stats = self.stats.write();
                stats.batches_ordered += 1;
            }

            // T74.3: Update metrics on successful ordering
            metrics::dag_vertices_ordered_inc(vertex_count);
            metrics::dag_pending_vertices_dec(vertex_count);
            metrics::observe_vertices_per_round(vertex_count);
            metrics::dag_current_round_set(current_round.as_u64());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that handle builds and orders a simple chain of vertices.
    #[test]
    fn test_handle_builds_and_orders_simple_chain() {
        let config = DagConsensusConfig::default();
        let handle = DagConsensusHandle::new(config);

        let author = AuthorId([1u8; 32]);

        // Submit payloads for round 1
        let payload1 = DagPayload::new(vec![1, 2, 3], author);
        let vertex1 = handle.submit_payload(payload1).unwrap();

        // With threshold=1, a single vertex should trigger ordering
        let batch = handle.try_next_ordered_batch();
        assert!(batch.is_some(), "Expected batch to be ordered");

        let batch = batch.unwrap();
        assert_eq!(batch.round, 1);
        assert_eq!(batch.vertex_count(), 1);
        assert!(batch.bundles[0].vertices.contains(&vertex1));

        // Stats should reflect the ordering
        let stats = handle.stats();
        assert_eq!(stats.vertices_stored, 1);
        assert_eq!(stats.batches_ordered, 1);
        assert_eq!(stats.current_round, 1);
    }

    /// Test that handle is deterministic for the same input sequence.
    #[test]
    fn test_handle_is_deterministic_for_same_input() {
        let config = DagConsensusConfig::default();

        // Create two handles with same config
        let handle1 = DagConsensusHandle::new(config.clone());
        let handle2 = DagConsensusHandle::new(config);

        let author = AuthorId([42u8; 32]);

        // Submit identical payloads to both handles
        let payloads: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        let mut vertices1 = Vec::new();
        let mut vertices2 = Vec::new();

        for data in &payloads {
            let p1 = DagPayload::new(data.clone(), author);
            let p2 = DagPayload::new(data.clone(), author);

            vertices1.push(handle1.submit_payload(p1).unwrap());
            vertices2.push(handle2.submit_payload(p2).unwrap());
        }

        // Both should produce identical vertex IDs
        assert_eq!(vertices1, vertices2, "Vertex IDs should be identical");

        // Get ordered batches from both
        let batch1 = handle1.try_next_ordered_batch();
        let batch2 = handle2.try_next_ordered_batch();

        assert!(batch1.is_some() && batch2.is_some());

        let batch1 = batch1.unwrap();
        let batch2 = batch2.unwrap();

        // Batches should be identical
        assert_eq!(batch1.round, batch2.round, "Rounds should match");
        assert_eq!(
            batch1.vertex_count(),
            batch2.vertex_count(),
            "Vertex counts should match"
        );
        assert_eq!(batch1.tx_count(), batch2.tx_count(), "Tx counts should match");

        // The vertex ordering within bundles should be identical
        for (b1, b2) in batch1.bundles.iter().zip(batch2.bundles.iter()) {
            assert_eq!(b1.vertices, b2.vertices, "Bundle vertices should be identical");
        }
    }

    /// Test payload validation.
    #[test]
    fn test_handle_rejects_oversized_payload() {
        let mut config = DagConsensusConfig::default();
        config.target_payload_bytes = 100; // Small limit for testing

        let handle = DagConsensusHandle::new(config);
        let author = AuthorId([1u8; 32]);

        // Payload larger than limit should be rejected
        let large_payload = DagPayload::new(vec![0u8; 200], author);
        let result = handle.submit_payload(large_payload);

        assert!(result.is_err());
        match result.unwrap_err() {
            DagError::PayloadTooLarge { size, max } => {
                assert_eq!(size, 200);
                assert_eq!(max, 100);
            }
            _ => panic!("Expected PayloadTooLarge error"),
        }
    }

    /// Test round advancement.
    #[test]
    fn test_handle_round_advancement() {
        let config = DagConsensusConfig::default();
        let handle = DagConsensusHandle::new(config);

        assert_eq!(handle.current_round(), 1);

        handle.advance_round();
        assert_eq!(handle.current_round(), 2);

        handle.advance_round();
        assert_eq!(handle.current_round(), 3);
    }

    /// Test stats tracking.
    #[test]
    fn test_handle_stats() {
        let config = DagConsensusConfig::default();
        let handle = DagConsensusHandle::new(config);

        let initial_stats = handle.stats();
        assert_eq!(initial_stats.vertices_stored, 0);
        assert_eq!(initial_stats.batches_ordered, 0);
        // Stats current_round is 0 initially (from DagStats::default),
        // updated to actual round (1) on first submit_payload
        assert_eq!(initial_stats.current_round, 0);

        // Submit a payload
        let author = AuthorId([1u8; 32]);
        let payload = DagPayload::new(vec![1, 2, 3], author);
        handle.submit_payload(payload).unwrap();

        let stats = handle.stats();
        assert_eq!(stats.vertices_stored, 1);
        assert_eq!(stats.current_round, 1);
    }

    /// Test empty batch behavior.
    #[test]
    fn test_handle_empty_queue() {
        let config = DagConsensusConfig::default();
        let handle = DagConsensusHandle::new(config);

        // No payloads submitted, queue should be empty
        assert!(handle.try_next_ordered_batch().is_none());
    }

    /// T76.2: Test peek_ordered_queue_len does not consume batches.
    #[test]
    fn test_handle_peek_queue_len_non_consuming() {
        let config = DagConsensusConfig::default();
        let handle = DagConsensusHandle::new(config);

        // Initially empty
        assert_eq!(handle.peek_ordered_queue_len(), 0);

        // Submit a payload that triggers ordering
        let author = AuthorId([1u8; 32]);
        let payload = DagPayload::new(vec![1, 2, 3], author);
        handle.submit_payload(payload).unwrap();

        // Should have 1 batch ready now (threshold=1 by default)
        assert_eq!(handle.peek_ordered_queue_len(), 1);

        // Peek again - should still be 1 (non-consuming)
        assert_eq!(handle.peek_ordered_queue_len(), 1);

        // Now consume it
        let batch = handle.try_next_ordered_batch();
        assert!(batch.is_some());

        // After consuming, peek should show 0
        assert_eq!(handle.peek_ordered_queue_len(), 0);
    }

    /// Test multi-round ordering.
    #[test]
    fn test_handle_multi_round() {
        let config = DagConsensusConfig::default();
        let handle = DagConsensusHandle::new(config);

        let author = AuthorId([1u8; 32]);

        // Round 1
        let payload1 = DagPayload::new(vec![1], author);
        handle.submit_payload(payload1).unwrap();

        let batch1 = handle.try_next_ordered_batch();
        assert!(batch1.is_some());
        assert_eq!(batch1.unwrap().round, 1);

        // Advance to round 2
        handle.advance_round();
        assert_eq!(handle.current_round(), 2);

        // Round 2
        let payload2 = DagPayload::new(vec![2], author);
        handle.submit_payload(payload2).unwrap();

        let batch2 = handle.try_next_ordered_batch();
        assert!(batch2.is_some());
        assert_eq!(batch2.unwrap().round, 2);

        // Stats should reflect both rounds
        let stats = handle.stats();
        assert_eq!(stats.vertices_stored, 2);
        assert_eq!(stats.batches_ordered, 2);
    }

    /// T74.3: Test that metrics are updated on submit and order.
    /// This test calls the metrics helper functions and verifies no panics occur.
    #[test]
    fn test_dag_metrics_increment_on_submit_and_order() {
        use crate::metrics;

        // Initialize metrics
        metrics::register_dag_metrics();

        let config = DagConsensusConfig::default();
        let handle = DagConsensusHandle::new(config);

        // Use different authors to avoid equivocation detection
        let author1 = AuthorId([1u8; 32]);
        let author2 = AuthorId([2u8; 32]);
        let author3 = AuthorId([3u8; 32]);

        // Submit payloads from different authors - this should increment vertices counter
        let payload1 = DagPayload::new(vec![1, 2, 3], author1);
        let _vertex1 = handle.submit_payload(payload1).unwrap();

        let payload2 = DagPayload::new(vec![4, 5, 6], author2);
        let _vertex2 = handle.submit_payload(payload2).unwrap();

        // Try to get ordered batch - this should update ordered vertices counter
        let batch = handle.try_next_ordered_batch();
        assert!(batch.is_some(), "Expected batch to be ordered");

        // Advance round - this should increment round advance counter
        handle.advance_round();

        // Submit another payload in new round
        let payload3 = DagPayload::new(vec![7, 8, 9], author3);
        let _vertex3 = handle.submit_payload(payload3).unwrap();

        // Stats verification
        let stats = handle.stats();
        assert_eq!(stats.vertices_stored, 3);
        assert_eq!(stats.current_round, 2);
    }
}