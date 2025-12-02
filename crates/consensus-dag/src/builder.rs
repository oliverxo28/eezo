//! builder.rs — DAG Payload Builder
//!
//! Responsible for constructing transaction payloads for DAG vertices.
//! Uses non-destructive peek from mempool to avoid draining transactions.

use crate::types::PayloadId;
use std::env;

/// Target payload size in bytes (configurable via env)
pub fn target_payload_bytes() -> usize {
    env::var("EEZO_DAG_BATCH_TARGET_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_048_576) // 1MB default
}

/// Trait for mempool peek operations (A16 requirement)
pub trait MempoolPeek {
    /// Non-destructively peek at transactions up to target_bytes.
    /// Returns clones of transactions without modifying mempool state.
    fn peek_by_bytes(&self, target_bytes: usize) -> Vec<SignedTx>;
}

// Use SignedTx from eezo-ledger
pub use eezo_ledger::SignedTx;

/// PayloadBuilder: Constructs transaction batches for DAG vertices.
pub struct PayloadBuilder {
    target_bytes: usize,
}

impl PayloadBuilder {
    pub fn new() -> Self {
        Self {
            target_bytes: target_payload_bytes(),
        }
    }

    /// Build a payload from mempool using non-destructive peek.
    /// 
    /// **A16 Implementation:**
    /// - Uses mempool.peek_by_bytes() (non-destructive)
    /// - Forms ~1MB payloads (target_bytes)
    /// - Serializes transactions to bytes
    /// - Computes blake3 payload_digest
    ///
    /// Returns (payload_bytes, payload_id)
    pub fn build_payload_from_mempool<M: MempoolPeek>(
        &self,
        mempool: &M,
    ) -> (Vec<u8>, PayloadId) {
        // Non-destructively peek at transactions
        let txs = mempool.peek_by_bytes(self.target_bytes);
        
        log::debug!(
            "builder: peeked {} transactions from mempool (target: {} bytes)",
            txs.len(),
            self.target_bytes
        );

        // Serialize transactions to payload bytes
        let payload = self.serialize_txs(&txs);
        
        // Compute payload digest (blake3)
        let payload_id = PayloadId::compute(&payload);
        
        log::info!(
            "builder: built payload with {} txs, {} bytes, digest={:?}",
            txs.len(),
            payload.len(),
            payload_id
        );

        (payload, payload_id)
    }

    /// Build a payload from a pre-selected list of transactions.
    /// 
    /// This is used when transactions are already selected (e.g., for testing).
    ///
    /// Returns (payload_bytes, payload_id)
    pub fn build_payload(&self, txs: &[Vec<u8>]) -> (Vec<u8>, PayloadId) {
        // Simple concatenation for now
        // In production, this would use proper serialization (SSZ, etc.)
        let mut payload = Vec::new();
        
        // Encode transaction count (u32)
        let count = txs.len() as u32;
        payload.extend_from_slice(&count.to_le_bytes());
        
        // Encode each transaction
        for tx in txs {
            // Length prefix (u32)
            let len = tx.len() as u32;
            payload.extend_from_slice(&len.to_le_bytes());
            
            // Transaction bytes
            payload.extend_from_slice(tx);
        }
        
        let payload_id = PayloadId::compute(&payload);
        (payload, payload_id)
    }

    /// Serialize transactions to bytes (must match executor_shim.rs)
    ///
    /// Encoding:
    ///   u32 count
    ///   repeat count times: u32 len | [len] bytes = bincode(SignedTx)
    fn serialize_txs(&self, txs: &[SignedTx]) -> Vec<u8> {
        // hard caps (keep in sync with executor_shim.rs)
        const MAX_TXS_PER_PAYLOAD: usize = 50_000;
        const MAX_TX_BYTES: usize = 1 << 20; // 1 MiB

        let safe_count = txs.len().min(MAX_TXS_PER_PAYLOAD);

        // conservative reserve; avoid huge allocations
        let mut out = Vec::with_capacity(4 + safe_count.saturating_mul(64));
        out.extend_from_slice(&(safe_count as u32).to_le_bytes());

        for tx in txs.iter().take(safe_count) {
            let bytes = bincode::serialize(tx).expect("serialize SignedTx");
            if bytes.len() > MAX_TX_BYTES {
                // refuse single oversized tx; (future: split/skip with metric)
                continue;
            }
            let len = bytes.len() as u32;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        out
    }

    /// Compute payload digest without building full payload
    pub fn compute_digest(&self, payload: &[u8]) -> PayloadId {
        PayloadId::compute(payload)
    }
}

impl Default for PayloadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_builder() {
        let builder = PayloadBuilder::new();
        assert!(builder.target_bytes > 0);
    }

    #[test]
    fn test_compute_digest() {
        let builder = PayloadBuilder::new();
        let data = b"test transaction batch";
        
        let digest1 = builder.compute_digest(data);
        let digest2 = builder.compute_digest(data);
        
        // Should be deterministic
        assert_eq!(digest1, digest2);
    }

    /// A16 Test: build_payload with pre-selected transactions
    #[test]
    fn test_build_payload() {
        let builder = PayloadBuilder::new();
        
        // Create some test transactions
        let tx1 = vec![1, 2, 3];
        let tx2 = vec![4, 5, 6, 7];
        let txs = vec![tx1, tx2];
        
        let (payload, payload_id) = builder.build_payload(&txs);
        
        // Payload should contain encoded transactions
        assert!(payload.len() > 0);
        
        // Payload ID should be deterministic
        let (_, payload_id2) = builder.build_payload(&txs);
        assert_eq!(payload_id, payload_id2);
        
        // Different transactions should produce different payload ID
        let tx3 = vec![8, 9, 10];
        let txs2 = vec![tx3];
        let (_, payload_id3) = builder.build_payload(&txs2);
        assert_ne!(payload_id, payload_id3);
        
        println!("✅ test_build_payload: Payload construction validated");
    }

    /// A16 Test: MempoolPeek trait with mock implementation
    #[test]
    fn test_mempool_peek_integration() {
        use eezo_ledger::{Address, tx_types::TxCore};
        
        // Mock mempool for testing
        struct MockMempool {
            txs: Vec<SignedTx>,
        }
        
        impl MempoolPeek for MockMempool {
            fn peek_by_bytes(&self, _target_bytes: usize) -> Vec<SignedTx> {
                self.txs.clone()
            }
        }
        
        let mock_mempool = MockMempool {
            txs: vec![
                SignedTx {
                    core: TxCore {
                        to: Address([0u8; 20]),
                        amount: 100,
                        fee: 1,
                        nonce: 0,
                    },
                    pubkey: vec![0u8; 32],
                    sig: vec![0u8; 64],
                },
                SignedTx {
                    core: TxCore {
                        to: Address([1u8; 20]),
                        amount: 200,
                        fee: 2,
                        nonce: 1,
                    },
                    pubkey: vec![0u8; 32],
                    sig: vec![0u8; 64],
                },
            ],
        };
        
        let builder = PayloadBuilder::new();
        let (payload, payload_id) = builder.build_payload_from_mempool(&mock_mempool);

        // Should produce a non-empty payload now that serialize_txs is implemented
        assert!(payload.len() >= 4, "payload must at least contain count");
        // quick decode to confirm count = 2
        let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        assert_eq!(count, 2, "encoded tx count must match");
        
        // Payload ID should be computed
        assert_eq!(payload_id.0.len(), 32); // blake3 hash is 32 bytes
        
        println!("✅ test_mempool_peek_integration: Non-destructive peek validated");
    }
}