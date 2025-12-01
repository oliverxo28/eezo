//! executor/single.rs
//!
//! Single-threaded executor (serial fallback for T54).
//! Still delegates to `eezo_ledger::consensus_api::run_one_slot` and maps the
//! result into the new T54 `ExecOutcome` shape. This keeps the code buildable
//! before we introduce `parallel.rs` (step 4).

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

// T72.0: Import detailed executor perf metric helpers
use crate::metrics::{
    observe_exec_block_prepare_seconds,
    observe_exec_block_apply_seconds,
    observe_exec_block_commit_seconds,
    observe_exec_tx_apply_seconds,
    observe_exec_txs_per_block,
    // Note: observe_exec_block_bytes is imported but not used in single.rs
    // since SignedTx doesn't expose an encoded_len() method and computing
    // to_bytes().len() for each tx would be wasteful. Block bytes are tracked
    // in parallel.rs where PreparedTx already has the data cached.
};

use super::{Executor, ExecInput, ExecOutcome};

/// Simple single-threaded executor that directly calls into the ledger.
pub struct SingleExecutor;

impl SingleExecutor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SingleExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Executor for SingleExecutor {
    fn execute_block(
        &self,
        node: &mut SingleNode,
        _input: ExecInput,
    ) -> ExecOutcome {
        let start = Instant::now();

        // T72.0: In SingleExecutor, there's no explicit prepare phase since run_one_slot
        // handles everything. We record prepare as 0 for consistency.
        observe_exec_block_prepare_seconds(0.0);

        // Delegate to the existing consensus+execution function.
        // (T54 note) For the serial fallback we still rely on the ledger's slot runner.
        // The provided `input.txs` batch is not used here; in `parallel.rs` we'll
        // execute that batch directly via the block context wrapper (step 5).
        let apply_start = Instant::now();
        let outcome: Result<SlotOutcome, ConsensusError> = run_one_slot(node, /*rollback_on_error=*/ true);
        let apply_elapsed = apply_start.elapsed();

        // T72.0: Record the apply phase timing (entire run_one_slot is treated as apply)
        observe_exec_block_apply_seconds(apply_elapsed.as_secs_f64());

        let elapsed = start.elapsed();
        let mut block_opt: Option<Block> = None;
        let mut tx_count: usize = 0;

        // If a block was committed, reconstruct it from the node's view.
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

        // T72.0: Record detailed executor performance metrics
        observe_exec_txs_per_block(tx_count as u64);
        // Note: block_bytes tracking skipped in SingleExecutor as SignedTx
        // doesn't expose an encoded_len() method. Use parallel executor for byte metrics.

        // T72.0: Record per-tx apply time (average) and commit time
        // In SingleExecutor, there's no separate commit phase, so we record 0.
        if tx_count > 0 {
            let per_tx_sec = apply_elapsed.as_secs_f64() / tx_count as f64;
            observe_exec_tx_apply_seconds(per_tx_sec);
        }
        observe_exec_block_commit_seconds(0.0);

        // Record executor timing metrics.
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

        // Map legacy slot outcome → T54 ExecOutcome shape.
        let result: Result<Block, String> = match outcome {
            Ok(SlotOutcome::Committed { .. }) => {
                match block_opt {
                    Some(b) => Ok(b),
                    // Return Err(String)
                    None => Err("executor: committed slot but block missing".into()),
                }
            }
            // Return Err(String)
            Ok(SlotOutcome::Skipped { .. }) => Err("executor: slot skipped".into()),
            // Convert ConsensusError to String
            Err(e) => Err(format!("{}", e)),
        };

        ExecOutcome { result, elapsed, tx_count }
    }
}