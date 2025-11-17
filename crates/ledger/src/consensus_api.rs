// crates/ledger/src/consensus_api.rs

#[cfg(feature = "metrics")]
use crate::metrics::{observe_commit_latency_ms, set_highest_qc_height};
use crate::{consensus::SingleNode, ConsensusError};

// LIGHT exports with just `checkpoints`
#[cfg(feature = "checkpoints")]
pub use crate::checkpoints::{
    is_checkpoint_height, qc_message_bytes, quorum_threshold, verify_quorum_cert, QcHash,
    QuorumCert,
};

// HEAVY only with verify
#[cfg(all(feature = "checkpoints", feature = "checkpoints-verify"))]
pub use crate::checkpoints::{QcBatchItem, QcSigSet, QcVerifier, StubQcVerifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoOpReason {
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotOutcome {
    Committed { height: u64 },
    Skipped(NoOpReason),
}

/// Minimal surface for any block producer (single or multi-node)
pub trait BlockProducer {
    fn propose_block(&mut self) -> Result<crate::block::Block, ConsensusError>;
}

/// Minimal surface for block execution
pub trait BlockExecutor {
    fn preflight_and_apply(&mut self, blk: &crate::block::Block) -> Result<(), ConsensusError>;
}

// Default impls for SingleNode by delegating to your existing methods
impl BlockProducer for SingleNode {
    fn propose_block(&mut self) -> Result<crate::block::Block, ConsensusError> {
        let (blk, _sum) = self.propose_block()?;
        Ok(blk)
    }
}

impl BlockExecutor for SingleNode {
    fn preflight_and_apply(&mut self, blk: &crate::block::Block) -> Result<(), ConsensusError> {
        self.validate_and_apply(blk)
    }
}

/// Public wrapper to run a single slot; simply calls the node's method.
pub fn run_one_slot(
    node: &mut SingleNode,
    rollback_on_error: bool,
) -> Result<SlotOutcome, ConsensusError> {
    match node.run_one_slot(rollback_on_error) {
        Ok((block, _summary)) => {
            // ---- T17.1 metrics (no behavior change) ----
            #[cfg(feature = "metrics")]
            {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(block.header.timestamp_ms);
                let latency_ms = now_ms.saturating_sub(block.header.timestamp_ms);
                observe_commit_latency_ms(latency_ms);
                set_highest_qc_height(block.header.height);
            }
            // ---- Checkpoint verification stub (no behavior change) ----
            #[cfg(all(feature = "checkpoints", not(feature = "checkpoints-verify")))]
            {
                // Create a stub QC for verification (result ignored)
                let qc: QuorumCert = (&block.header).into();
                let _ = verify_quorum_cert(&qc);
            }
            Ok(SlotOutcome::Committed {
                height: block.header.height,
            })
        }
        Err(e) => Err(e),
    }
}