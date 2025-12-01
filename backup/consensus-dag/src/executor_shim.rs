//! executor_shim.rs — DAG OrderedBundle → Executor integration (A17)
//!
//! This module connects the DAG ordering layer to the existing serial executor.
//! It provides a bridge that:
//! 1. Waits for DA worker to fetch all payloads
//! 2. Deserializes transactions from payloads
//! 3. Executes via the current serial executor
//! 4. Updates block headers with DAG metadata
//! 5. Maintains checkpoint compatibility
//!
//! This is a temporary shim - Block-STM parallel executor will arrive in T54.1.3.

use std::sync::Arc;
use std::time::{Duration, Instant};
use crate::da_worker::DAWorker;
use crate::order::OrderingEngine;
use crate::store::DagStore;
use crate::types::{OrderedBundle, PayloadId, VertexId};

#[cfg(feature = "metrics")]
use crate::metrics::{dag_bundle_ordered, exec_apply_observe};

use eezo_ledger::{Block, BlockHeader, SignedTx};

/// DagExecutorShim: Bridge between DAG ordering and executor.
/// 
/// **A17 Architecture:**
/// ```text
/// OrderedBundle -> wait_for_payloads -> deserialize -> execute -> finalize
/// ```
pub struct DagExecutorShim {
    /// DAG store for vertex lookup
    store: Arc<DagStore>,
    
    /// Ordering engine (for metrics)
    #[allow(dead_code)] // Added attribute to silence unused-var warning
    ordering: Arc<OrderingEngine>,
    
    /// DA worker for payload fetching
    da_worker: Arc<DAWorker>,
    
    /// Maximum time to wait for payloads (seconds)
    payload_timeout_secs: u64,
    
    /// Current height (incremented per block)
    current_height: u64,
	
    /// Optional execution hook supplied by the node.
    /// Signature: (height, &txs) -> Result<(), String>
    /// Node will point this to its STM facade (apply_block_stm).
    exec_hook: Option<std::sync::Arc<dyn Fn(u64, &[SignedTx]) -> Result<(), String> + Send + Sync>>,
}

impl DagExecutorShim {
    /// Create new executor shim (A21-A22: simplified - height starts at 0)
    pub fn new(
        store: Arc<DagStore>,
        ordering: Arc<OrderingEngine>,
        da_worker: Arc<DAWorker>,
        payload_timeout_secs: u64,
    ) -> Self {
        Self {
            store,
            ordering,
            da_worker,
            payload_timeout_secs,
            current_height: 0,
			exec_hook: None,
        }
    }
    /// Provide the node-side execution hook (e.g., STM apply).
    pub fn set_exec_hook(
        &mut self,
        hook: std::sync::Arc<dyn Fn(u64, &[SignedTx]) -> Result<(), String> + Send + Sync>,
    ) {
        self.exec_hook = Some(hook);
    }	
    
    /// Process an OrderedBundle: wait for payloads, execute, finalize.
    /// 
    /// **A17 Requirements:**
    /// - Wait for DA worker to fetch all payloads
    /// - Execute using current serial executor
    /// - Update header with DAG metadata
    /// - Return finalized block
    #[allow(unused_variables)]
    pub async fn process_bundle(
        &mut self,
        bundle: OrderedBundle,
        prev_hash: [u8; 32],
    ) -> Result<Block, ExecutorShimError> {
        let start = Instant::now();
        
        // Increment height for this bundle
        self.current_height += 1;
        let height = self.current_height;
        
        // 1. Wait for all payloads to be available
        let payload_ids = self.collect_payload_ids(&bundle)?;
        self.wait_for_payloads(&payload_ids).await?;
        
        // 2. Deserialize all transactions from payloads
        let all_txs = self.deserialize_payloads(&payload_ids)?;
        
        // 3. Execute transactions via serial executor
        let exec_start = Instant::now();
        let (header, txs) = self.execute_txs(
            height,
            prev_hash,
            all_txs,
            &bundle,
        )?;
        let exec_elapsed = exec_start.elapsed();
        
        // 4. Record metrics
        #[cfg(feature = "metrics")]
        {
            dag_bundle_ordered();
            exec_apply_observe(exec_elapsed.as_secs_f64());
        }
        
        let block = Block { header, txs };
        
        log::info!(
            "DagExecutorShim: Processed bundle round={} height={} txs={} elapsed={:?}",
            bundle.round.as_u64(),
            height,
            block.txs.len(),
            start.elapsed()
        );
        
        Ok(block)
    }
    
    /// Collect payload IDs from all vertices in bundle
    fn collect_payload_ids(&self, bundle: &OrderedBundle) -> Result<Vec<PayloadId>, ExecutorShimError> {
        let mut payload_ids = Vec::with_capacity(bundle.vertices.len());
        
        for vertex_id in &bundle.vertices {
            let node = self.store.get_node(vertex_id)
                .ok_or_else(|| ExecutorShimError::VertexNotFound(*vertex_id))?;
            
            payload_ids.push(node.payload_digest);
        }
        
        Ok(payload_ids)
    }
    
    /// Wait for all payloads to be available in DA worker cache
    async fn wait_for_payloads(&self, payload_ids: &[PayloadId]) -> Result<(), ExecutorShimError> {
        let timeout = Duration::from_secs(self.payload_timeout_secs);
        let start = Instant::now();
        
        loop {
            // Check if all payloads are ready
            let all_ready = payload_ids.iter().all(|id| self.da_worker.have_payload(id));
            
            if all_ready {
                return Ok(());
            }
            
            // Check timeout
            if start.elapsed() >= timeout {
                let missing: Vec<PayloadId> = payload_ids.iter()
                    .filter(|id| !self.da_worker.have_payload(id))
                    .copied()
                    .collect();
                
                return Err(ExecutorShimError::PayloadTimeout {
                    total: payload_ids.len(),
                    missing: missing.len(),
                });
            }
            
            // Wait a bit before checking again
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    
    /// Deserialize transactions from all payloads
    fn deserialize_payloads(&self, payload_ids: &[PayloadId]) -> Result<Vec<SignedTx>, ExecutorShimError> {
        let mut all_txs = Vec::new();
        
        for payload_id in payload_ids {
            let payload_bytes = self.da_worker.get_payload(payload_id)
                .ok_or_else(|| ExecutorShimError::PayloadNotFound(*payload_id))?;
            
            // Deserialize transactions from payload
            // For now, assume payload is a simple concatenation of serialized SignedTx
            // TODO: Use proper serialization format (bincode, postcard, etc.)
            let txs = self.deserialize_tx_payload(&payload_bytes)?;
            all_txs.extend(txs);
        }
        
        Ok(all_txs)
    }
    
    /// Deserialize a single payload into transactions.
    ///
    /// **Format (interim, deterministic, self-delimiting):**
    ///   u32 count
    ///   repeat count times:
    ///     u32 len
    ///     [len] bytes = bincode(SignedTx)
    ///
    /// This keeps decoding simple and unambiguous for A16–A18. The builder
    /// MUST emit this exact format. (We'll stabilize later if needed.)
    fn deserialize_tx_payload(&self, payload: &[u8]) -> Result<Vec<SignedTx>, ExecutorShimError> {
        use std::convert::TryInto;

        // hard caps: keep in sync with builder
        const MAX_TXS_PER_PAYLOAD: usize = 50_000;
        const MAX_TX_BYTES: usize = 1 << 20; // 1 MiB

        let mut off = 0usize;
        if payload.len() < 4 {
            return Err(ExecutorShimError::DeserializationError("payload too small".into()));
        }
        let count = u32::from_le_bytes(payload[off..off + 4].try_into().unwrap()) as usize;
        off += 4;

        if count == 0 {
            return Ok(Vec::new());
        }
        if count > MAX_TXS_PER_PAYLOAD {
            return Err(ExecutorShimError::DeserializationError("tx count exceeds max".into()));
        }

        let mut out = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            if off + 4 > payload.len() {
                return Err(ExecutorShimError::DeserializationError("truncated len".into()));
            }
            let len = u32::from_le_bytes(payload[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if len > MAX_TX_BYTES {
                return Err(ExecutorShimError::DeserializationError("single tx too large".into()));
            }
            if off + len > payload.len() {
                return Err(ExecutorShimError::DeserializationError("truncated tx bytes".into()));
            }
            let tx_bytes = &payload[off..off + len];
            off += len;

            // Use standard bincode::deserialize to match bincode::serialize used in tx handler
            let tx: SignedTx = bincode::deserialize(tx_bytes)
                .map_err(|e| ExecutorShimError::DeserializationError(format!("bincode: {e}")))?;
            out.push(tx);
        }
        Ok(out)
    }
    
    /// Execute transactions and build block header
    /// 
    /// **Temporary:** Uses simplified execution for testing.
    /// Will integrate with actual executor in full implementation.
    fn execute_txs(
        &self,
        height: u64,
        prev_hash: [u8; 32],
        txs: Vec<SignedTx>,
        _bundle: &OrderedBundle, // underscore to silence unused-var warning
    ) -> Result<(BlockHeader, Vec<SignedTx>), ExecutorShimError> {
        // If the node provided an execution hook (STM), invoke it now.
        if let Some(hook) = &self.exec_hook {
            (hook)(height, &txs)
                .map_err(|e| ExecutorShimError::ExecutionError(format!("exec hook failed: {e}")))?;
        }

        // Build header in line with ledger expectations (tx_root, fee_total, tx_count, timestamp).
        // This aligns with `txs_root(..)` and header fields used by validate/apply.
        let tx_root = {
            if txs.is_empty() { [0u8; 32] } else {
                let mut cat = Vec::with_capacity(txs.len() * 32);
                for tx in &txs {
                    let h = blake3::hash(&bincode::serialize(tx).unwrap_or_default());
                    cat.extend_from_slice(h.as_bytes());
                }
                let digest = blake3::hash(&cat);
                *digest.as_bytes()
            }
        };
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let fee_total: u128 = txs.iter().map(|t| t.core.fee).sum(); // aligns with validate_block's fee check
        
        let header = BlockHeader {
            height,
            prev_hash,
            tx_root,
            #[cfg(feature = "eth-ssz")]
            tx_root_v2: [0u8; 32], // TODO: Compute proper SSZ root
            fee_total,
            tx_count: txs.len() as u32, // validate_block checks this too
            timestamp_ms,
            #[cfg(feature = "checkpoints")]
            qc_hash: self.compute_dag_qc_hash(_bundle), // Use _bundle if feature is enabled
            #[cfg(not(feature = "checkpoints"))]
            qc_hash: [0u8; 32],
        };
        
        Ok((header, txs))
    }
    
    /// Compute DAG metadata hash for checkpoint compatibility
    /// 
    /// **A17 Requirement:** Include DAG metadata in header extension.
    /// This allows deterministic replay while maintaining checkpoint format.
    #[cfg(feature = "checkpoints")]
    fn compute_dag_qc_hash(&self, bundle: &OrderedBundle) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        
        // Round number
        hasher.update(&bundle.round.as_u64().to_le_bytes());
        
        // All vertex IDs in order
        for vertex_id in &bundle.vertices {
            hasher.update(vertex_id.as_bytes());
        }
        
        // Transaction count
        hasher.update(&bundle.tx_count.to_le_bytes());
        
        *hasher.finalize().as_bytes()
    }
}

/// Errors that can occur during executor shim processing
#[derive(Debug)]
pub enum ExecutorShimError {
    /// Vertex referenced in bundle not found in store
    VertexNotFound(VertexId),
    
    /// Payload not found in DA worker cache
    PayloadNotFound(PayloadId),
    
    /// Timeout waiting for payloads
    PayloadTimeout {
        total: usize,
        missing: usize,
    },
    
    /// Deserialization error
    DeserializationError(String),
    
    /// Execution error
    ExecutionError(String),
}

impl std::fmt::Display for ExecutorShimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutorShimError::VertexNotFound(id) => {
                write!(f, "Vertex not found: {:?}", id)
            }
            ExecutorShimError::PayloadNotFound(id) => {
                write!(f, "Payload not found: {:?}", id)
            }
            ExecutorShimError::PayloadTimeout { total, missing } => {
                write!(f, "Payload timeout: {}/{} missing", missing, total)
            }
            ExecutorShimError::DeserializationError(msg) => {
                write!(f, "Deserialization error: {}", msg)
            }
            ExecutorShimError::ExecutionError(msg) => {
                write!(f, "Execution error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ExecutorShimError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthorId, DagNode, PayloadId, Round};
    use eezo_ledger::{tx_types::TxCore, Address}; // Correct TxCore path and Address import
    use bincode::Options; // kept for bounded bincode in other test helpers if needed
    
    #[tokio::test]
    async fn test_shim_basic_flow() {
        // --- T54.1.3 FIX: Create a valid, correctly encoded transaction payload ---
        
        // 1. Create a minimal valid SignedTx with corrected field names and required TxCore fields
        let tx = SignedTx {
            core: TxCore {
                nonce: 1,
                fee: 100,
                amount: 1,                     // minimal non-zero amount for test
                to: Address([0u8; 20]),        // valid 20-byte address wrapper
                // Removed `..Default::default()` because TxCore does not implement Default
            },
            // field name is `sig`, not `signature`
            sig: vec![0u8; 64],
            // `pubkey` is a Vec<u8>, not a fixed array
            pubkey: vec![0u8; 32],
        };
        
        // 2. Serialize the transaction using bincode
        let bytes = bincode::serialize(&tx).unwrap();
        
        // 3. Construct the payload using the DagBuilder format: u32 count | u32 len | [bytes]
        let mut payload_data = Vec::new();
        payload_data.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        payload_data.extend_from_slice(&(bytes.len() as u32).to_le_bytes()); // len
        payload_data.extend_from_slice(&bytes); // serialized SignedTx
        
        let payload_id = PayloadId::compute(&payload_data);
        // --- End of FIX ---

        let vertex = DagNode::new(
            Round(1),
            vec![],
            payload_id,
            AuthorId([1u8; 32]),
            1234567890,
        );
        
        // Create store and add vertex before wrapping in Arc
        let mut store_inner = DagStore::new();
        store_inner.put_node(&vertex);
        let store = Arc::new(store_inner);
        
        let ordering = Arc::new(OrderingEngine::new()); // Default threshold
        let da_worker = Arc::new(DAWorker::new());
        
        // Store payload in DA worker
        da_worker.store_payload(payload_id, payload_data);
        
        let mut shim = DagExecutorShim::new(
            store.clone(),
            ordering,
            da_worker.clone(),
            10, // 10 sec timeout
        );
        
        // Create bundle
        let bundle = OrderedBundle::new(
            Round(1),
            vec![vertex.id],
            1, // Updated tx_count to reflect payload
        );
        
        // Process bundle
        let prev_hash = [0u8; 32];
        let result = shim.process_bundle(bundle, prev_hash).await;
        
        match &result {
            Ok(block) => {
                assert_eq!(block.header.height, 1);
                assert_eq!(block.header.prev_hash, prev_hash);
                assert_eq!(block.txs.len(), 1);
                assert_eq!(block.header.tx_count, 1);
                assert_eq!(block.header.fee_total, 100);
            }
            Err(e) => {
                panic!("Shim should process bundle successfully, got error: {}", e);
            }
        }
    }
    
    #[tokio::test]
    async fn test_shim_payload_timeout() {
        // Create vertex with payload that's NOT in DA worker
        let payload_id = PayloadId::compute(b"missing payload");
        let vertex = DagNode::new(
            Round(1),
            vec![],
            payload_id,
            AuthorId([1u8; 32]),
            1234567890,
        );
        
        // Create components and store vertex before wrapping in Arc
        let mut store_inner = DagStore::new();
        store_inner.put_node(&vertex);
        let store = Arc::new(store_inner);
        
        let ordering = Arc::new(OrderingEngine::new());
        let da_worker = Arc::new(DAWorker::new());
        // NOTE: Not storing payload in DA worker - should timeout
        
        let mut shim = DagExecutorShim::new(
            store,
            ordering,
            da_worker.clone(),
            1, // 1 sec timeout (will expire)
        );
        
        // Create bundle
        let bundle = OrderedBundle::new(
            Round(1),
            vec![vertex.id],
            0,
        );
        
        // Process bundle - should timeout
        let result = shim.process_bundle(bundle, [0u8; 32]).await;
        
        assert!(result.is_err(), "Should timeout waiting for payload");
        
        match result.unwrap_err() {
            ExecutorShimError::PayloadTimeout { total: 1, missing: 1 } => {
                // Expected
            }
            other => panic!("Expected PayloadTimeout, got: {:?}", other),
        }
    }
}