//! store.rs — DAG Store (persistence + GC)
//!
//! Provides deterministic storage for DAG vertices with:
//! - Node storage and retrieval
//! - Parent dependency tracking
//! - Ready-round queries
//! - Garbage collection above committed rounds
//! - Equivocation detection (A15)

use crate::types::{DagNode, Round, VertexId, AuthorId};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;

/// Result of equivocation check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EquivocationResult {
    /// No conflict - accept the vertex
    Accept,
    
    /// New vertex ID is larger - reject it
    Reject { existing: VertexId },
    
    /// Multiple vertices detected from same (author, round)
    Equivocation {
        existing: VertexId,
        rejected: VertexId,
    },
}

/// DagStore: Thread-safe, deterministic storage for DAG vertices.
///
/// Key properties:
/// - Deterministic: Same sequence of puts produces same state
/// - Never drops uncommitted nodes
/// - GC only above the last committed round
/// - Equivocation detection: same (author, round) → keep smallest ID
/// - Thread-safe via DashMap for concurrent access
#[derive(Clone)]
pub struct DagStore {
    /// Main storage: VertexId -> DagNode
    nodes: Arc<DashMap<VertexId, DagNode>>,
    
    /// Index by round for efficient queries
    /// Round -> Set of VertexIds
    by_round: Arc<DashMap<Round, HashSet<VertexId>>>,
    
    /// Track the highest committed round for GC
    committed_round: Arc<RwLock<Option<Round>>>,
    
    /// Equivocation tracking: (AuthorId, Round) -> VertexId
    /// Used to detect when same author produces multiple vertices in same round
    author_round_map: Arc<DashMap<(AuthorId, Round), VertexId>>,
}

impl DagStore {
    /// Create a new empty DagStore
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(DashMap::new()),
            by_round: Arc::new(DashMap::new()),
            committed_round: Arc::new(RwLock::new(None)),
            author_round_map: Arc::new(DashMap::new()),
        }
    }

    /// Check for equivocation before accepting a vertex.
    /// 
    /// Rule: If the same author produces multiple vertices in the same round,
    /// keep only the lexicographically smallest vertex ID.
    /// 
    /// Returns:
    /// - `Accept` if no conflict or this is the first vertex from this author/round
    /// - `Reject` if an existing vertex has smaller ID
    /// - `Equivocation` if this causes an equivocation (existing has larger ID)
    pub fn check_equivocation(&self, node: &DagNode) -> EquivocationResult {
        let key = (node.author, node.round);
        
        if let Some(existing_entry) = self.author_round_map.get(&key) {
            let existing_id = *existing_entry;
            
            // Compare lexicographically (by bytes)
            if node.id.0 < existing_id.0 {
                // New vertex has smaller ID - it should replace existing
                EquivocationResult::Equivocation {
                    existing: existing_id,
                    rejected: node.id,
                }
            } else if node.id.0 > existing_id.0 {
                // Existing vertex has smaller ID - reject new one
                EquivocationResult::Reject {
                    existing: existing_id,
                }
            } else {
                // Same ID - duplicate, treat as accept (idempotent)
                EquivocationResult::Accept
            }
        } else {
            // No existing vertex from this author/round
            EquivocationResult::Accept
        }
    }

    /// Store a DAG node with equivocation detection.
    /// MUST be deterministic: same node inserted produces same state.
    /// 
    /// If equivocation is detected, the vertex with the lexicographically 
    /// smallest ID is kept.
    /// 
    /// NOTE: Uses interior mutability (DashMap) so &self is sufficient.
    pub fn put_node(&self, node: &DagNode) -> EquivocationResult {
        let id = node.id;
        let round = node.round;
        let key = (node.author, node.round);
        
        // Check for equivocation
        let result = self.check_equivocation(node);
        
        match result {
            EquivocationResult::Accept => {
                // Insert into main storage
                self.nodes.insert(id, node.clone());
                
                // Update round index
                self.by_round
                    .entry(round)
                    .or_insert_with(HashSet::new)
                    .insert(id);
                
                // Track in author_round_map
                self.author_round_map.insert(key, id);
                
                #[cfg(feature = "metrics")]
                crate::metrics::dag_vertex_stored();
            }
            EquivocationResult::Reject { existing } => {
                // Reject - existing vertex has smaller ID
                log::warn!(
                    "Rejecting vertex {:?} from {:?} round {}: existing {:?} has smaller ID",
                    id, node.author, round.0, existing
                );
                
                #[cfg(feature = "metrics")]
                crate::metrics::dag_equivocation_detected();
            }
            EquivocationResult::Equivocation { existing, rejected: _ } => {
                // Equivocation detected - new vertex has smaller ID
                // Remove existing and insert new one
                log::warn!(
                    "Equivocation from {:?} round {}: replacing {:?} with {:?}",
                    node.author, round.0, existing, id
                );
                
                // Remove existing vertex
                self.nodes.remove(&existing);
                if let Some(mut round_set) = self.by_round.get_mut(&round) {
                    round_set.remove(&existing);
                }
                
                // Insert new vertex
                self.nodes.insert(id, node.clone());
                self.by_round
                    .entry(round)
                    .or_insert_with(HashSet::new)
                    .insert(id);
                
                // Update author_round_map
                self.author_round_map.insert(key, id);
                
                #[cfg(feature = "metrics")]
                {
                    crate::metrics::dag_equivocation_detected();
                    crate::metrics::dag_vertex_stored();
                }
            }
        }
        
        result
    }

    /// Check if a node exists in the store
    pub fn have_node(&self, id: &VertexId) -> bool {
        self.nodes.contains_key(id)
    }

    /// Get a node by ID
    pub fn get_node(&self, id: &VertexId) -> Option<DagNode> {
        self.nodes.get(id).map(|n| n.clone())
    }

    /// Find missing parents for a given vertex.
    /// Returns list of parent IDs that are not yet in the store.
    pub fn missing_parents(&self, id: &VertexId) -> Vec<VertexId> {
        let Some(node) = self.get_node(id) else {
            return Vec::new();
        };
        
        node.parents
            .iter()
            .filter(|parent_id| !self.have_node(parent_id))
            .copied()
            .collect()
    }

    /// Get all nodes that are ready in the given round.
    /// A node is "ready" if all its parents exist in the store.
    ///
    /// CRITICAL: Must be deterministic - returns nodes in sorted order by ID.
    pub fn get_ready_round(&self, round: Round) -> Vec<DagNode> {
        let Some(ids_in_round) = self.by_round.get(&round) else {
            return Vec::new();
        };
        
        let mut ready_nodes = Vec::new();
        
        for id in ids_in_round.iter() {
            if let Some(node) = self.get_node(id) {
                // Check if all parents are available
                let all_parents_ready = node.parents.iter().all(|parent_id| {
                    self.have_node(parent_id)
                });
                
                if all_parents_ready {
                    ready_nodes.push(node);
                }
            }
        }
        
        // Sort by VertexId for determinism
        ready_nodes.sort_by_key(|n| n.id.0);
        ready_nodes
    }

    /// Get all nodes in a round (regardless of readiness)
    pub fn get_round_nodes(&self, round: Round) -> Vec<DagNode> {
        let Some(ids) = self.by_round.get(&round) else {
            return Vec::new();
        };
        
        let mut nodes: Vec<DagNode> = ids
            .iter()
            .filter_map(|id| self.get_node(id))
            .collect();
        
        // Sort for determinism
        nodes.sort_by_key(|n| n.id.0);
        nodes
    }

    /// Garbage collect nodes at or below the committed round.
    ///
    /// CRITICAL RULES:
    /// - Only GC rounds <= committed_round
    /// - Never drop uncommitted nodes
    /// - Must be deterministic
    ///
    /// Typically called after a round is finalized and applied to ledger.
    /// NOTE: Uses interior mutability (DashMap) so &self is sufficient.
    pub fn gc(&self, committed_round: Round) {
        // Update the committed round tracker
        {
            let mut cr = self.committed_round.write();
            *cr = Some(committed_round);
        }
        
        // Collect rounds to GC (all rounds < committed_round - safety_margin)
        // Keep a safety margin to avoid premature GC
        let safety_margin = 10u64;
        let gc_below = if committed_round.as_u64() > safety_margin {
            Round(committed_round.as_u64() - safety_margin)
        } else {
            return; // Too early to GC
        };
        
        let mut rounds_to_remove = Vec::new();
        
        // Find old rounds
        for entry in self.by_round.iter() {
            if *entry.key() < gc_below {
                rounds_to_remove.push(*entry.key());
            }
        }
        
        // Remove nodes and round indices
        for round in rounds_to_remove {
            if let Some((_, ids)) = self.by_round.remove(&round) {
                for id in ids {
                    self.nodes.remove(&id);
                }
            }
        }
        
        log::debug!("gc: removed rounds < {}, committed at {}", 
                    gc_below.as_u64(), committed_round.as_u64());
    }

    /// Count total nodes in store
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Count nodes in a specific round
    pub fn round_count(&self, round: Round) -> usize {
        self.by_round
            .get(&round)
            .map(|ids| ids.len())
            .unwrap_or(0)
    }

    /// Get the current committed round (if any)
    pub fn committed_round(&self) -> Option<Round> {
        *self.committed_round.read()
    }
}

impl Default for DagStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthorId, PayloadId};

    fn make_test_node(round: u64, parents: Vec<VertexId>, seed: u8) -> DagNode {
        DagNode::new(
            Round(round),
            parents,
            PayloadId([seed; 32]),
            AuthorId([seed; 32]),
            1234567890,
        )
    }

    #[test]
    fn test_put_and_get_node() {
        let mut store = DagStore::new();
        let node = make_test_node(1, vec![], 1);
        
        store.put_node(&node);
        assert!(store.have_node(&node.id));
        
        let retrieved = store.get_node(&node.id).unwrap();
        assert_eq!(retrieved.id, node.id);
    }

    #[test]
    fn test_missing_parents() {
        let mut store = DagStore::new();
        
        let parent1 = make_test_node(1, vec![], 1);
        let parent2 = make_test_node(1, vec![], 2);
        let child = make_test_node(2, vec![parent1.id, parent2.id], 3);
        
        // Only add child, not parents
        store.put_node(&child);
        
        let missing = store.missing_parents(&child.id);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&parent1.id));
        assert!(missing.contains(&parent2.id));
        
        // Add one parent
        store.put_node(&parent1);
        let missing = store.missing_parents(&child.id);
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&parent2.id));
        
        // Add second parent
        store.put_node(&parent2);
        let missing = store.missing_parents(&child.id);
        assert_eq!(missing.len(), 0);
    }

    #[test]
    fn test_get_ready_round() {
        let mut store = DagStore::new();
        
        // Create round 1 nodes
        let r1_n1 = make_test_node(1, vec![], 1);
        let r1_n2 = make_test_node(1, vec![], 2);
        
        // Create round 2 nodes with r1 parents
        let r2_n1 = make_test_node(2, vec![r1_n1.id, r1_n2.id], 3);
        let r2_n2 = make_test_node(2, vec![r1_n1.id], 4);
        
        // Add all round 1 nodes
        store.put_node(&r1_n1);
        store.put_node(&r1_n2);
        
        // Add round 2 nodes
        store.put_node(&r2_n1);
        store.put_node(&r2_n2);
        
        // Round 1 should be fully ready (no parents)
        let ready_r1 = store.get_ready_round(Round(1));
        assert_eq!(ready_r1.len(), 2);
        
        // Round 2 should be fully ready (all parents present)
        let ready_r2 = store.get_ready_round(Round(2));
        assert_eq!(ready_r2.len(), 2);
    }

    #[test]
    fn test_gc() {
        let mut store = DagStore::new();
        
        // Add nodes for rounds 1-20
        for round in 1..=20 {
            let node = make_test_node(round, vec![], (round % 256) as u8);
            store.put_node(&node);
        }
        
        assert_eq!(store.node_count(), 20);
        
        // Commit round 15 and GC
        store.gc(Round(15));
        
        // Nodes below round 5 (15 - 10 safety margin) should be GCed
        // Nodes >= 5 should remain
        let remaining = store.node_count();
        assert!(remaining < 20);
        assert!(remaining > 10); // Should have rounds 5-20
    }

    #[test]
    fn test_deterministic_ordering() {
        let mut store = DagStore::new();
        
        // Add nodes in random order
        let n3 = make_test_node(1, vec![], 3);
        let n1 = make_test_node(1, vec![], 1);
        let n2 = make_test_node(1, vec![], 2);
        
        store.put_node(&n3);
        store.put_node(&n1);
        store.put_node(&n2);
        
        // get_ready_round should return in deterministic order
        let ready = store.get_ready_round(Round(1));
        assert_eq!(ready.len(), 3);
        
        // Should be sorted by VertexId
        assert!(ready[0].id.0 <= ready[1].id.0);
        assert!(ready[1].id.0 <= ready[2].id.0);
    }

    /// A15 requirement: Test equivocation detection
    #[test]
    fn equivocation_detected_ok() {
        let mut store = DagStore::new();
        let author = AuthorId([42u8; 32]);
        let round = Round(5);
        
        // Create two different vertices from same author in same round
        // vertex1 has smaller ID (all zeros except last byte = 1)
        let mut vertex1_id = [0u8; 32];
        vertex1_id[31] = 1;
        let vertex1 = DagNode {
            id: VertexId(vertex1_id),
            round,
            parents: vec![],
            payload_digest: PayloadId([10u8; 32]),
            author,
            ts: 1000,
        };
        
        // vertex2 has larger ID (all zeros except last byte = 2)
        let mut vertex2_id = [0u8; 32];
        vertex2_id[31] = 2;
        let vertex2 = DagNode {
            id: VertexId(vertex2_id),
            round,
            parents: vec![],
            payload_digest: PayloadId([20u8; 32]),
            author,
            ts: 1001,
        };
        
        // Insert vertex2 first (larger ID)
        let result1 = store.put_node(&vertex2);
        assert_eq!(result1, EquivocationResult::Accept);
        assert!(store.have_node(&vertex2.id));
        
        // Try to insert vertex1 (smaller ID) - should cause equivocation
        let result2 = store.put_node(&vertex1);
        match result2 {
            EquivocationResult::Equivocation { existing, rejected } => {
                assert_eq!(existing, vertex2.id);
                assert_eq!(rejected, vertex1.id);
            }
            _ => panic!("Expected Equivocation result"),
        }
        
        // vertex1 (smaller ID) should now be in store
        assert!(store.have_node(&vertex1.id));
        // vertex2 (larger ID) should be removed
        assert!(!store.have_node(&vertex2.id));
        
        // Try to insert vertex2 again - should be rejected
        let result3 = store.put_node(&vertex2);
        match result3 {
            EquivocationResult::Reject { existing } => {
                assert_eq!(existing, vertex1.id);
            }
            _ => panic!("Expected Reject result"),
        }
        
        // vertex1 should still be in store
        assert!(store.have_node(&vertex1.id));
        // vertex2 should still not be in store
        assert!(!store.have_node(&vertex2.id));
        
        // Verify final ordering still produces identical result
        let ready = store.get_ready_round(round);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, vertex1.id);
        
        println!("✅ equivocation_detected_ok: Equivocation detection validated");
        println!("   - Lexicographically smallest ID kept: {:?}", vertex1.id);
        println!("   - Larger ID rejected: {:?}", vertex2.id);
        println!("   - Final ordering deterministic and consistent");
    }

    #[test]
    fn test_equivocation_same_id_idempotent() {
        let mut store = DagStore::new();
        let node = make_test_node(1, vec![], 42);
        
        // Insert same node twice
        let result1 = store.put_node(&node);
        assert_eq!(result1, EquivocationResult::Accept);
        
        let result2 = store.put_node(&node);
        assert_eq!(result2, EquivocationResult::Accept); // Idempotent
        
        // Should only have one copy
        assert_eq!(store.node_count(), 1);
    }
}