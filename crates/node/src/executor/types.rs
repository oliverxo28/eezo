//! executor/types.rs
//! Core types for the node-side block executor (T54 – Parallel Executor).
//!
//! This file defines the minimal abstract interface used by both:
//!   • single-threaded executor (`single.rs`)
//!   • parallel executor (`parallel.rs`)
//!
//! Consensus runner will call `Executor::execute_block(...)`.

use std::time::Duration;

use eezo_ledger::{Block, SignedTx};

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

    /// T76.4: When true, enable partial failure tolerance.
    /// Failed transactions are dropped (not included in the block) instead
    /// of causing the entire block execution to abort.
    /// Default: false (legacy behavior - abort on first failure)
    pub partial_failure_ok: bool,
}

impl ExecInput {
    pub fn new(txs: Vec<SignedTx>, height: u64) -> Self {
        Self { txs, height, partial_failure_ok: false }
    }

    /// T76.4: Create input with partial failure tolerance enabled.
    pub fn with_partial_failure(txs: Vec<SignedTx>, height: u64) -> Self {
        Self { txs, height, partial_failure_ok: true }
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

    /// T76.4: Number of transactions that succeeded apply.
    /// In legacy mode (partial_failure_ok=false), this equals tx_count since the block
    /// only succeeds if all transactions succeed.
    pub apply_ok: usize,

    /// T76.4: Number of transactions that failed apply.
    /// In legacy mode (partial_failure_ok=false), this is 0 since any failure causes
    /// the entire block to fail (and tx_count becomes 0).
    pub apply_fail: usize,
}

impl ExecOutcome {
    /// Create an ExecOutcome for legacy mode where all included txs must have succeeded.
    /// This constructor assumes apply_ok = tx_count and apply_fail = 0, which is correct
    /// for legacy mode where any tx failure causes the entire block to fail.
    pub fn new(result: Result<Block, String>, elapsed: Duration, tx_count: usize) -> Self {
        Self { result, elapsed, tx_count, apply_ok: tx_count, apply_fail: 0 }
    }

    /// T76.4: Create outcome with partial failure statistics.
    pub fn with_partial_stats(
        result: Result<Block, String>,
        elapsed: Duration,
        tx_count: usize,
        apply_ok: usize,
        apply_fail: usize,
    ) -> Self {
        Self { result, elapsed, tx_count, apply_ok, apply_fail }
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