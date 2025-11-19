//! executor/single.rs
//!
//! Single-threaded executor implementation for T52.1.
//!
//! This is a thin wrapper around `eezo_ledger::consensus_api::run_one_slot` that:
//!   - measures how long the slot took
//!   - reconstructs the committed `Block` (header + txs) when applicable
//!   - reports tx_count for metrics
//!
//! Later (T52.2+) we can introduce parallel or pipelined executors that
//! implement the same `BlockExecutor` trait.

use std::time::Instant;

use eezo_ledger::{Block, SingleNode, ConsensusError};
use eezo_ledger::consensus_api::{run_one_slot, SlotOutcome};

// Add gated import for the new executor metrics (T52.1)
#[cfg(feature = "metrics")]
use crate::metrics::{
    EEZO_EXECUTOR_BLOCK_SECONDS,
    EEZO_EXECUTOR_TX_SECONDS,
    EEZO_EXECUTOR_TPS_INFERRED,
};

use super::{BlockExecutor, ExecutorOutcome, ExecutorRequest};

/// Simple single-threaded executor that directly calls into the ledger.
pub struct SingleThreadExecutor;

impl SingleThreadExecutor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SingleThreadExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockExecutor for SingleThreadExecutor {
    fn execute_slot(
        &self,
        node: &mut SingleNode,
        req: ExecutorRequest,
    ) -> ExecutorOutcome {
        let start = Instant::now();

        // Delegate to the existing consensus+execution function.
        let outcome: Result<SlotOutcome, ConsensusError> =
            run_one_slot(node, req.rollback_on_error);

        let elapsed = start.elapsed();
        let mut block_opt = None;
        let mut tx_count = 0usize;

        // If a block was committed, reconstruct it from the node’s view.
        if let Ok(SlotOutcome::Committed { .. }) = &outcome {
            let header_opt = node.last_committed_header();
            let txs_opt = node.last_committed_txs();

            match (header_opt, txs_opt) {
                (Some(header), Some(txs)) => {
                    tx_count = txs.len();
                    block_opt = Some(Block { header, txs });
                }
                _ => {
                    log::warn!(
                        "executor: SlotOutcome::Committed but last_committed_header/txs returned None"
                    );
                }
            }
        }

        // Record executor timing metrics (T52.1).
        #[cfg(feature = "metrics")]
        {
            let sec = elapsed.as_secs_f64().max(0.0);

            // Always track block-level execution time, even for empty blocks.
            EEZO_EXECUTOR_BLOCK_SECONDS
                .with_label_values(&["block"])
                .observe(sec);

            if tx_count > 0 && sec > 0.0 {
                let per_tx = sec / tx_count as f64;
                EEZO_EXECUTOR_TX_SECONDS
                    .with_label_values(&["tx"])
                    .observe(per_tx);

                let tps = (tx_count as f64 / sec) as i64;
                EEZO_EXECUTOR_TPS_INFERRED.set(tps);
            }
        }

        ExecutorOutcome {
            outcome,
            block: block_opt,
            elapsed,
            tx_count,
        }
    }
}