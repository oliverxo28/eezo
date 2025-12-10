//! lib.rs — Consensus DAG for EEZO v2
//!
//! DAG-backed BFT consensus implementation (replaces legacy pre-DAG consensus).
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
//!
//! ## Key Properties
//!
//! 1. **Deterministic**: Same inputs produce same outputs
//! 2. **Replay-safe**: Can replay from genesis
//! 3. **Compatible**: Works with existing prover/relay
//! 4. **Lock-free**: No global locks on hot paths
//!
//! ## Usage
//!
//! ```rust,ignore
//! use consensus_dag::{DagStore, OrderingEngine, DAWorker};
//!
//! let mut store = DagStore::new();
//! let engine = OrderingEngine::new();
//! let worker = DAWorker::new();
//!
//! // Store vertices, order rounds, fetch payloads
//! ```

pub mod types;
pub mod store;
pub mod gossip;
pub mod builder;
pub mod order;
pub mod da_worker;
pub mod metrics;
pub mod executor_shim;

// Re-export commonly used types
pub use types::{
    VertexId, PayloadId, Round, AuthorId,
    DagNode, OrderedBundle,
};

pub use store::DagStore;
pub use gossip::{VertexAnn, PayloadReq, PayloadResp, ParentsReq, ParentsResp, GossipMessage};
pub use builder::PayloadBuilder;
pub use order::OrderingEngine;
pub use da_worker::{DAWorker, PayloadCache};
pub use executor_shim::{DagExecutorShim, ExecutorShimError};

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
