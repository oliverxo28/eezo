//! executor/types.rs
//!
//! Core types for the node-side block executor (T52.1).
//!
//! The executor decouples consensus-slot driving from block execution
//! so that later (T52.2+) we can introduce parallel or pipelined execution
//! without touching consensus code again.

use std::time::Duration;

use eezo_ledger::Block;
use eezo_ledger::ConsensusError;
use eezo_ledger::consensus_api::SlotOutcome;

/// Request passed to the executor when a new block slot must be executed.
///
/// For T52.1 this does not include the raw transactions directly; instead,
/// we rely on `run_one_slot` to select txs from the mempool. Later (T52.2),
/// we may extend this with custom batching strategies.
#[derive(Debug)]
pub struct ExecutorRequest {
    /// Height before running the slot (informational/debug).
    pub height_before: u64,

    /// Whether the slot should rollback on error.
    pub rollback_on_error: bool,
}

impl ExecutorRequest {
    pub fn new(height_before: u64, rollback_on_error: bool) -> Self {
        Self {
            height_before,
            rollback_on_error,
        }
    }
}

/// Result returned by the executor after running one slot.
#[derive(Debug)]
pub struct ExecutorOutcome {
    /// The underlying slot outcome from consensus (Committed / Skipped / Error).
    pub outcome: Result<SlotOutcome, ConsensusError>,

    /// If the slot produced a committed block, we return it here.
    pub block: Option<Block>,

    /// Total time spent executing the slot, including tx selection + apply.
    pub elapsed: Duration,

    /// Number of transactions in the committed block (0 for skipped).
    pub tx_count: usize,
}

/// Trait implemented by all block executors.
///
/// For T52.1 we provide a single-threaded implementation in `single.rs`.
pub trait BlockExecutor: Send + Sync {
    fn execute_slot(
        &self,
        node: &mut eezo_ledger::SingleNode,
        req: ExecutorRequest,
    ) -> ExecutorOutcome;
}