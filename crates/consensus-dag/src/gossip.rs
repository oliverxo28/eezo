//! gossip.rs — DAG Gossip protocol
//!
//! Network message types for DAG vertex propagation:
//! - VertexAnn: Announce new vertices
//! - PayloadReq/Resp: Request/response for transaction payloads
//! - ParentsReq/Resp: Request/response for missing parents

use crate::types::{PayloadId, VertexId, Round};
use serde::{Deserialize, Serialize};

/// VertexAnn: Announce a new DAG vertex to peers.
/// Contains minimal metadata - peers can request full data separately.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VertexAnn {
    /// Unique vertex identifier
    pub id: VertexId,
    
    /// Round number
    pub round: Round,
    
    /// Parent vertex IDs (for dependency checking)
    pub parent_ids: Vec<VertexId>,
}

impl VertexAnn {
    pub fn new(id: VertexId, round: Round, parent_ids: Vec<VertexId>) -> Self {
        Self { id, round, parent_ids }
    }
}

/// PayloadReq: Request transaction payload data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadReq {
    /// Content hash of the requested payload
    pub payload_id: PayloadId,
}

impl PayloadReq {
    pub fn new(payload_id: PayloadId) -> Self {
        Self { payload_id }
    }
}

/// PayloadResp: Response containing transaction payload chunks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadResp {
    /// Content hash (matches request)
    pub payload_id: PayloadId,
    
    /// Payload data in chunks
    pub chunks: Vec<Vec<u8>>,
}

impl PayloadResp {
    pub fn new(payload_id: PayloadId, chunks: Vec<Vec<u8>>) -> Self {
        Self { payload_id, chunks }
    }

    /// Reconstruct full payload from chunks
    pub fn to_bytes(&self) -> Vec<u8> {
        self.chunks.concat()
    }

    /// Verify that payload matches its ID
    pub fn verify(&self) -> bool {
        let data = self.to_bytes();
        PayloadId::compute(&data) == self.payload_id
    }
}

/// ParentsReq: Request missing parent vertices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParentsReq {
    /// Vertex ID whose parents we need
    pub id: VertexId,
}

impl ParentsReq {
    pub fn new(id: VertexId) -> Self {
        Self { id }
    }
}

/// ParentsResp: Response containing parent vertex IDs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParentsResp {
    /// Vertex ID (matches request)
    pub id: VertexId,
    
    /// List of parent vertex IDs
    pub parents: Vec<VertexId>,
}

impl ParentsResp {
    pub fn new(id: VertexId, parents: Vec<VertexId>) -> Self {
        Self { id, parents }
    }
}

/// GossipMessage: Union type for all DAG gossip messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    VertexAnn(VertexAnn),
    PayloadReq(PayloadReq),
    PayloadResp(PayloadResp),
    ParentsReq(ParentsReq),
    ParentsResp(ParentsResp),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vertex_ann() {
        let id = VertexId([1u8; 32]);
        let round = Round(5);
        let parents = vec![VertexId([2u8; 32]), VertexId([3u8; 32])];
        
        let ann = VertexAnn::new(id, round, parents.clone());
        assert_eq!(ann.id, id);
        assert_eq!(ann.round, round);
        assert_eq!(ann.parent_ids, parents);
    }

    #[test]
    fn test_payload_resp_verify() {
        let data = b"test payload data";
        let payload_id = PayloadId::compute(data);
        
        let resp = PayloadResp::new(
            payload_id,
            vec![data[..10].to_vec(), data[10..].to_vec()],
        );
        
        assert!(resp.verify());
        assert_eq!(resp.to_bytes(), data);
    }

    #[test]
    fn test_payload_resp_invalid() {
        let data = b"test payload";
        let wrong_id = PayloadId([42u8; 32]);
        
        let resp = PayloadResp::new(wrong_id, vec![data.to_vec()]);
        assert!(!resp.verify());
    }
}