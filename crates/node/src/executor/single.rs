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

        // Delegate to the existing consensus+execution function.
        // (T54 note) For the serial fallback we still rely on the ledger's slot runner.
        // The provided `input.txs` batch is not used here; in `parallel.rs` we'll
        // execute that batch directly via the block context wrapper (step 5).
        let outcome: Result<SlotOutcome, ConsensusError> = run_one_slot(node, /*rollback_on_error=*/ true);

        let elapsed = start.elapsed();
        let mut block_opt: Option<Block> = None;
        let mut tx_count: usize = 0;

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