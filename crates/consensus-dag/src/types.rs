//! types.rs — Core DAG consensus types for EEZO v2
//!
//! Defines the fundamental data structures for DAG-backed BFT:
//! - VertexId: Unique identifier for DAG vertices
//! - PayloadId: Content-addressed payload identifier
//! - Round: Monotonic consensus round number
//! - AuthorId: Node/validator identifier
//! - DagNode: Core DAG vertex with parents and payload
//! - OrderedBundle: Deterministically ordered transaction batch

use serde::{Deserialize, Serialize};
use std::fmt;

/// VertexId: Unique 32-byte identifier for a DAG vertex.
/// Typically computed as blake3(vertex_data).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VertexId(pub [u8; 32]);

impl VertexId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for VertexId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VertexId({}..)", hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for VertexId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// PayloadId: Content-addressed identifier for transaction payloads.
/// Computed as blake3(payload_bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayloadId(pub [u8; 32]);

impl PayloadId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compute PayloadId from raw bytes using blake3
    pub fn compute(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }
}

impl fmt::Debug for PayloadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PayloadId({}..)", hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for PayloadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// Round: Monotonic consensus round number.
/// Used to establish causal ordering in the DAG.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Round(pub u64);

impl Round {
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn next(&self) -> Self {
        Round(self.0 + 1)
    }

    pub fn prev(&self) -> Option<Self> {
        if self.0 > 0 {
            Some(Round(self.0 - 1))
        } else {
            None
        }
    }
}

impl fmt::Debug for Round {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Round({})", self.0)
    }
}

impl fmt::Display for Round {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Round {
    fn from(n: u64) -> Self {
        Round(n)
    }
}

/// AuthorId: Unique identifier for a node/validator.
/// Could be derived from the node's public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthorId(pub [u8; 32]);

impl AuthorId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthorId({}..)", hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// DagNode: Core vertex in the DAG.
/// Contains:
/// - Unique ID (content hash)
/// - Round number
/// - Parent vertices (from previous rounds)
/// - Payload digest (transactions)
/// - Author (creator node)
/// - Timestamp
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DagNode {
    /// Unique identifier for this vertex (blake3 of serialized node)
    pub id: VertexId,
    
    /// Round number (monotonic)
    pub round: Round,
    
    /// Parent vertices from previous rounds
    pub parents: Vec<VertexId>,
    
    /// Content-addressed payload identifier
    pub payload_digest: PayloadId,
    
    /// Node that created this vertex
    pub author: AuthorId,
    
    /// Unix timestamp in seconds
    pub ts: u64,
}

impl DagNode {
    /// Create a new DagNode and compute its ID
    pub fn new(
        round: Round,
        parents: Vec<VertexId>,
        payload_digest: PayloadId,
        author: AuthorId,
        ts: u64,
    ) -> Self {
        let mut node = Self {
            id: VertexId([0u8; 32]),
            round,
            parents,
            payload_digest,
            author,
            ts,
        };
        node.id = node.compute_id();
        node
    }

    /// Compute the vertex ID deterministically from node contents
    fn compute_id(&self) -> VertexId {
        // Serialize node fields (excluding id itself) and hash
        let mut hasher = blake3::Hasher::new();
        
        // Round
        hasher.update(&self.round.0.to_le_bytes());
        
        // Parents (sorted for determinism)
        let mut sorted_parents = self.parents.clone();
        sorted_parents.sort_by_key(|p| p.0);
        for parent in &sorted_parents {
            hasher.update(&parent.0);
        }
        
        // Payload digest
        hasher.update(&self.payload_digest.0);
        
        // Author
        hasher.update(&self.author.0);
        
        // Timestamp
        hasher.update(&self.ts.to_le_bytes());
        
        let hash = hasher.finalize();
        VertexId(*hash.as_bytes())
    }

    /// Verify that the stored ID matches the computed ID
    pub fn verify_id(&self) -> bool {
        self.id == self.compute_id()
    }
}

/// OrderedBundle: A deterministically ordered batch of vertices.
/// Emitted by the ordering layer when a round is ready.
/// Contains all transactions from the ordered vertices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderedBundle {
    /// Round that was finalized
    pub round: Round,
    
    /// Ordered list of vertex IDs in this bundle
    pub vertices: Vec<VertexId>,
    
    /// Total transaction count across all vertices
    pub tx_count: usize,
}

impl OrderedBundle {
    pub fn new(round: Round, vertices: Vec<VertexId>, tx_count: usize) -> Self {
        Self {
            round,
            vertices,
            tx_count,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }
}

// Simple hex encoding helper (can use hex crate in dependencies if needed)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vertex_id_roundtrip() {
        let bytes = [42u8; 32];
        let id = VertexId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_payload_id_compute() {
        let data = b"test payload";
        let id = PayloadId::compute(data);
        
        // Computing again should give same result (deterministic)
        let id2 = PayloadId::compute(data);
        assert_eq!(id, id2);
    }

    #[test]
    fn test_round_ordering() {
        let r1 = Round(1);
        let r2 = Round(2);
        assert!(r1 < r2);
        assert_eq!(r1.next(), r2);
        assert_eq!(r2.prev(), Some(r1));
    }

    #[test]
    fn test_dag_node_id_determinism() {
        let round = Round(1);
        let parents = vec![VertexId([1u8; 32]), VertexId([2u8; 32])];
        let payload = PayloadId([3u8; 32]);
        let author = AuthorId([4u8; 32]);
        let ts = 123456789;

        let node1 = DagNode::new(round, parents.clone(), payload, author, ts);
        let node2 = DagNode::new(round, parents, payload, author, ts);

        // Same inputs should produce same ID
        assert_eq!(node1.id, node2.id);
        assert!(node1.verify_id());
    }

    #[test]
    fn test_ordered_bundle() {
        let bundle = OrderedBundle::new(
            Round(5),
            vec![VertexId([1u8; 32]), VertexId([2u8; 32])],
            10,
        );
        
        assert_eq!(bundle.round.as_u64(), 5);
        assert_eq!(bundle.vertices.len(), 2);
        assert_eq!(bundle.tx_count, 10);
        assert!(!bundle.is_empty());
    }
}