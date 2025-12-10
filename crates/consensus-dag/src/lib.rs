//! lib.rs — Consensus DAG for EEZO v2
//!
//! DAG-backed BFT consensus implementation (replaces legacy pre-DAG consensus).
//!
//! ## Architecture
//!
//! - **types**: Core data structures (VertexId, DagNode, OrderedBundle, DagConsensusConfig, …)
//! - **store**: Deterministic DAG storage with GC
//! - **gossip**: Network message types for vertex propagation
//! - **builder**: Payload construction from mempool
//! - **order**: Bullshark-style deterministic ordering
//! - **da_worker**: Data availability plane (hash-only consensus)
//! - **metrics**: Prometheus metrics
//! - **handle**: High-level consensus handle API used by eezo-node
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
pub mod handle;

// Re-export commonly used types at the crate root so eezo-node can just use
// `consensus_dag::X` without reaching into submodules.
pub use types::{
    VertexId,
    PayloadId,
    Round,
    AuthorId,
    DagNode,
    OrderedBundle,
    // T75/T80/T81: config struct used to wire DAG into the node
    DagConsensusConfig,
};

pub use handle::{
    DagConsensusHandle,
    DagPayload,
    OrderedBatch,
    DagStats,
    DagError,
};

pub use store::DagStore;
pub use gossip::{VertexAnn, PayloadReq, PayloadResp, ParentsReq, ParentsResp, GossipMessage};
pub use builder::PayloadBuilder;
pub use order::OrderingEngine;
pub use da_worker::{DAWorker, PayloadCache};
pub use executor_shim::{DagExecutorShim, ExecutorShimError};

/// Public entry point to register all consensus-dag metrics.
///
/// Safe to call multiple times; internal registration is idempotent.
pub fn register_dag_metrics() {
    #[cfg(feature = "metrics")]
    {
        metrics::register_metrics();
    }
}

/// Initialize the DAG consensus system.
///
/// This is a convenience for simple setups; the node wiring may choose to
/// construct these pieces manually instead.
pub fn initialize() -> (DagStore, OrderingEngine, DAWorker) {
    // Ensure metrics are registered via the public entry point.
    register_dag_metrics();

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
