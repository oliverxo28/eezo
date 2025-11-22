//! executor/types.rs
//! Core types for the node-side block executor (T54 – Parallel Executor).
//!
//! This file defines the minimal abstract interface used by both:
//!   • single-threaded executor (`single.rs`)
//!   • parallel executor (`parallel.rs`)
//!
//! Consensus runner will call `Executor::execute_block(...)`.

use std::time::Duration;

use eezo_ledger::{Block, ConsensusError, SignedTx};
use eezo_ledger::consensus_api::SlotOutcome;

// =======================================================================
// T54 — PARALLEL EXECUTOR CORE TYPES
// =======================================================================

/// Input to the executor: a selected batch of mempool txs for this block.
#[derive(Debug)]
pub struct ExecInput {
    /// All signed txs chosen for this block.
    pub txs: Vec<SignedTx>,

    /// The height being built (for debug/logs only).
    pub height: u64,
}

impl ExecInput {
    pub fn new(txs: Vec<SignedTx>, height: u64) -> Self {
        Self { txs, height }
    }
}

/// Output produced by the executor after executing all txs.
#[derive(Debug)]
pub struct ExecOutcome {
    /// If all txs succeeded → `Ok(Block)`.
    /// Otherwise → `Err(String)` (executor-local error message).
    pub result: Result<Block, String>,

    /// How long execution took, including parallel scheduling.
    pub elapsed: Duration,

    /// Number of txs that ended up included in the block.
    pub tx_count: usize,
}

impl ExecOutcome {
    pub fn new(result: Result<Block, String>, elapsed: Duration, tx_count: usize) -> Self {
        Self { result, elapsed, tx_count }
    }
}

/// The abstract executor interface implemented by:
///   • `single.rs` (serial)
///   • `parallel.rs` (rayon-based wave executor)
pub trait Executor: Send + Sync {
    /// Execute a block consisting of the provided tx batch.
    ///
    /// `node` provides state access (accounts, supply, etc.).
    fn execute_block(
        &self,
        node: &mut eezo_ledger::SingleNode,
        input: ExecInput,
    ) -> ExecOutcome;
}