//! order.rs — DAG Ordering Layer (Bullshark-style)
//!
//! Deterministic ordering of DAG vertices into bundles.
//! Ensures all nodes see the same transaction order.

use crate::store::DagStore;
use crate::types::{DagNode, OrderedBundle, Round, VertexId};
use std::collections::HashSet;
use std::env;

/// Get the threshold for distinct producers required to finalize a round
fn ordering_threshold() -> usize {
    env::var("EEZO_DAG_ORDERING_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1) // Default: single node (for initial testing)
}

/// OrderingEngine: Deterministically orders DAG vertices.
pub struct OrderingEngine {
    threshold: usize,
}

impl OrderingEngine {
    pub fn new() -> Self {
        Self {
            threshold: ordering_threshold(),
        }
    }

    /// Check if a round is ready to be ordered.
    /// 
    /// ParentsReady rule:
    /// - A vertex is ready if ALL its parents exist and are in rounds < current round
    ///
    /// Order rule:
    /// - For each round r, if distinct producers >= threshold, emit OrderedBundle
    ///
    /// CRITICAL: Must be deterministic - same DAG state produces same ordering.
    pub fn try_order_round(&self, store: &DagStore, round: Round) -> Option<OrderedBundle> {
        // Get all ready nodes in this round
        let ready_nodes = store.get_ready_round(round);
        
        if ready_nodes.is_empty() {
            return None;
        }

        // Count distinct authors (producers)
        let distinct_authors: HashSet<_> = ready_nodes.iter().map(|n| n.author).collect();
        
        if distinct_authors.len() < self.threshold {
            log::debug!(
                "order: round {} has {} distinct authors, need {}",
                round.as_u64(),
                distinct_authors.len(),
                self.threshold
            );
            return None;
        }

        // Round is ready - create ordered bundle
        let vertices: Vec<VertexId> = ready_nodes.iter().map(|n| n.id).collect();
        let tx_count = self.estimate_tx_count(&ready_nodes);

        log::info!(
            "order: finalized round {} with {} vertices, {} txs",
            round.as_u64(),
            vertices.len(),
            tx_count
        );

        Some(OrderedBundle::new(round, vertices, tx_count))
    }

    /// Estimate total transaction count across vertices
    fn estimate_tx_count(&self, nodes: &[DagNode]) -> usize {
        // TODO(A5): Implement accurate tx counting
        // For now, estimate based on vertex count
        nodes.len()
    }

    /// Verify ordering is deterministic
    /// (For testing - verify two runs produce same result)
    #[cfg(test)]
    pub fn verify_determinism(
        &self,
        store1: &DagStore,
        store2: &DagStore,
        round: Round,
    ) -> bool {
        let bundle1 = self.try_order_round(store1, round);
        let bundle2 = self.try_order_round(store2, round);
        
        match (bundle1, bundle2) {
            (Some(b1), Some(b2)) => {
                b1.round == b2.round && b1.vertices == b2.vertices
            }
            (None, None) => true,
            _ => false,
        }
    }
}

impl Default for OrderingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthorId, PayloadId};

    fn make_test_node(
        round: u64,
        parents: Vec<VertexId>,
        author: u8,
        seed: u8,
    ) -> DagNode {
        DagNode::new(
            Round(round),
            parents,
            PayloadId([seed; 32]),
            AuthorId([author; 32]),
            1234567890,
        )
    }

    #[test]
    fn test_single_node_ordering() {
        let engine = OrderingEngine::new();
        let mut store = DagStore::new();
        
        let node = make_test_node(1, vec![], 1, 1);
        store.put_node(&node);
        
        // With threshold=1, single node should be ordered
        let bundle = engine.try_order_round(&store, Round(1));
        assert!(bundle.is_some());
        
        let bundle = bundle.unwrap();
        assert_eq!(bundle.round, Round(1));
        assert_eq!(bundle.vertices.len(), 1);
    }

    #[test]
    fn test_multi_author_ordering() {
        let mut engine = OrderingEngine::new();
        engine.threshold = 2; // Require 2 distinct authors
        
        let mut store = DagStore::new();
        
        // Add node from author 1
        let n1 = make_test_node(1, vec![], 1, 1);
        store.put_node(&n1);
        
        // Should NOT order (only 1 author)
        assert!(engine.try_order_round(&store, Round(1)).is_none());
        
        // Add nodes from author 2 and 3
        let n2 = make_test_node(1, vec![], 2, 2);
        let n3 = make_test_node(1, vec![], 3, 3);
        store.put_node(&n2);
        store.put_node(&n3);
        
        // Now should order (3 distinct authors)
        let bundle = engine.try_order_round(&store, Round(1));
        assert!(bundle.is_some());
        assert_eq!(bundle.unwrap().vertices.len(), 3);
    }

    #[test]
    fn test_deterministic_ordering() {
        let engine = OrderingEngine::new();
        
        // Create two identical stores
        let mut store1 = DagStore::new();
        let mut store2 = DagStore::new();
        
        // Add same nodes in different order
        let n1 = make_test_node(1, vec![], 1, 1);
        let n2 = make_test_node(1, vec![], 2, 2);
        let n3 = make_test_node(1, vec![], 3, 3);
        
        // Store 1: order 1, 2, 3
        store1.put_node(&n1);
        store1.put_node(&n2);
        store1.put_node(&n3);
        
        // Store 2: order 3, 2, 1
        store2.put_node(&n3);
        store2.put_node(&n2);
        store2.put_node(&n1);
        
        // Ordering should be deterministic
        assert!(engine.verify_determinism(&store1, &store2, Round(1)));
    }
}
