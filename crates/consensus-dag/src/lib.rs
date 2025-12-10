//! lib.rs — Consensus DAG for EEZO (Production Consensus)
//!
//! # EEZO's Production Consensus
//!
//! **DAG is the canonical consensus mechanism for EEZO networks.**
//!
//! This crate implements the DAG-backed BFT consensus that provides:
//! - Block finality and ordering for all EEZO transactions
//! - Deterministic, replay-safe execution
//! - Lock-free hot paths for high throughput
//!
//! ## T81: DAG-Only Runtime
//!
//! As of T81, DAG is the **sole production consensus** for EEZO:
//! - All devnet/testnet/mainnet deployments use DAG
//! - No legacy consensus code is compiled in production builds
//! - The `dag-only` feature provides the cleanest production build
//!
//! ## Architecture
//!
//! - **types**: Core data structures (VertexId, DagNode, OrderedBundle)
//! - **store**: Deterministic DAG storage with GC
//! - **gossip**: Network message types for vertex propagation
//! - **builder**: Payload construction from mempool
//! - **order**: Bullshark-style deterministic ordering
//! - **da_worker**: Data availability plane (hash-only consensus)
//! - **metrics**: Prometheus metrics
//! - **handle**: Public façade for node integration (DagConsensusHandle)
//!
//! ## Key Properties
//!
//! 1. **Deterministic**: Same inputs produce same outputs
//! 2. **Replay-safe**: Can replay from genesis
//! 3. **Compatible**: Works with existing prover/relay
//! 4. **Lock-free**: No global locks on hot paths
//! 5. **Production-ready**: Canonical consensus for EEZO networks
//!
//! ## Usage
//!
//! ```rust,ignore
//! use consensus_dag::{DagConsensusConfig, DagConsensusHandle, DagPayload};
//! use consensus_dag::types::AuthorId;
//!
//! // Create handle with default config
//! let handle = DagConsensusHandle::new(DagConsensusConfig::default());
//!
//! // Submit a payload
//! let payload = DagPayload::new(vec![1, 2, 3], AuthorId([0u8; 32]));
//! handle.submit_payload(payload).unwrap();
//!
//! // Poll for ordered batches
//! if let Some(batch) = handle.try_next_ordered_batch() {
//!     println!("Ordered: round={}", batch.round);
//! }
//! ```

pub mod types;
pub mod store;
pub mod gossip;
pub mod builder;
pub mod order;
pub mod da_worker;
pub mod metrics;
pub mod executor_shim;
pub mod handle;

// Re-export commonly used types
pub use types::{
    VertexId, PayloadId, Round, AuthorId,
    DagNode, OrderedBundle, DagConsensusConfig,
};

pub use store::DagStore;
pub use gossip::{VertexAnn, PayloadReq, PayloadResp, ParentsReq, ParentsResp, GossipMessage};
pub use builder::PayloadBuilder;
pub use order::OrderingEngine;
pub use da_worker::{DAWorker, PayloadCache};
pub use executor_shim::{DagExecutorShim, ExecutorShimError};

// Re-export handle types
pub use handle::{DagConsensusHandle, DagPayload, OrderedBatch, DagStats, DagError};

// Re-export metrics registration function (T74.3)
pub use crate::metrics::register_dag_metrics;

/// Initialize the DAG consensus system
pub fn initialize() -> (DagStore, OrderingEngine, DAWorker) {
    #[cfg(feature = "metrics")]
    metrics::register_metrics();

    let store = DagStore::new();
    let engine = OrderingEngine::new();
    let worker = DAWorker::new();

    log::info!("consensus-dag: initialized");

    (store, engine, worker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        let (_store, _engine, _worker) = initialize();
        // Initialization should succeed
    }
}