//! executor/types.rs
//! Core types for the node-side block executor (T54 – Parallel Executor).
//!
//! This file defines the minimal abstract interface used by both:
//!   • single-threaded executor (`single.rs`)
//!   • parallel executor (`parallel.rs`)
//!
//! Consensus runner will call `Executor::execute_block(...)`.

use std::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};

use eezo_ledger::{Block, SignedTx};

// =======================================================================
// T76.5 — Per-reason apply failure tracking
// =======================================================================

/// T76.5: Tracks per-reason apply failure counts for hybrid batch diagnostics.
/// Uses atomic counters for thread-safe parallel execution.
#[derive(Debug, Default)]
pub struct ApplyFailureReasons {
    /// BadNonce errors (expected vs got nonce mismatch)
    pub bad_nonce: AtomicUsize,
    /// InsufficientFunds errors (balance too low for amount + fee)
    pub insufficient_funds: AtomicUsize,
    /// InvalidSender errors (sender derivation failed)
    pub invalid_sender: AtomicUsize,
    /// Any other errors not categorized above
    pub other: AtomicUsize,
}

impl ApplyFailureReasons {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Increment the appropriate counter based on error type
    pub fn record_error(&self, err: &eezo_ledger::tx::TxStateError) {
        match err {
            eezo_ledger::tx::TxStateError::BadNonce { .. } => {
                self.bad_nonce.fetch_add(1, Ordering::Relaxed);
            }
            eezo_ledger::tx::TxStateError::InsufficientFunds { .. } => {
                self.insufficient_funds.fetch_add(1, Ordering::Relaxed);
            }
            eezo_ledger::tx::TxStateError::InvalidSender => {
                self.invalid_sender.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Get the current counts as a snapshot
    pub fn snapshot(&self) -> ApplyFailureCounts {
        ApplyFailureCounts {
            bad_nonce: self.bad_nonce.load(Ordering::Relaxed),
            insufficient_funds: self.insufficient_funds.load(Ordering::Relaxed),
            invalid_sender: self.invalid_sender.load(Ordering::Relaxed),
            other: self.other.load(Ordering::Relaxed),
        }
    }
}

/// T76.5: Non-atomic snapshot of failure counts for reporting
#[derive(Debug, Default, Clone, Copy)]
pub struct ApplyFailureCounts {
    pub bad_nonce: usize,
    pub insufficient_funds: usize,
    pub invalid_sender: usize,
    pub other: usize,
}

impl ApplyFailureCounts {
    /// Total failure count
    pub fn total(&self) -> usize {
        self.bad_nonce + self.insufficient_funds + self.invalid_sender + self.other
    }
}

// =======================================================================
// T54 — PARALLEL EXECUTOR CORE TYPES
// =======================================================================

use std::sync::Arc;

// T76.9: Import DecodedTx for zero-copy handoff
#[cfg(feature = "pq44-runtime")]
use crate::tx_decode_pool::DecodedTx;

/// Input to the executor: a selected batch of mempool txs for this block.
#[derive(Debug)]
pub struct ExecInput {
    /// All signed txs chosen for this block.
    pub txs: Vec<SignedTx>,

    /// T76.9: Optional pre-decoded transactions for zero-copy handoff.
    /// When present, executors should use these instead of re-decoding from `txs`.
    #[cfg(feature = "pq44-runtime")]
    pub decoded_txs: Option<Vec<Arc<DecodedTx>>>,

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
        Self {
            txs,
            height,
            partial_failure_ok: false,
            #[cfg(feature = "pq44-runtime")]
            decoded_txs: None,
        }
    }

    /// T76.4: Create input with partial failure tolerance enabled.
    pub fn with_partial_failure(txs: Vec<SignedTx>, height: u64) -> Self {
        Self {
            txs,
            height,
            partial_failure_ok: true,
            #[cfg(feature = "pq44-runtime")]
            decoded_txs: None,
        }
    }

    /// T76.9: Create input with pre-decoded transactions for zero-copy handoff.
    #[cfg(feature = "pq44-runtime")]
    pub fn with_decoded(decoded_txs: Vec<Arc<DecodedTx>>, height: u64) -> Self {
        // Extract SignedTx references from decoded txs for backward compatibility
        let txs: Vec<SignedTx> = decoded_txs.iter().map(|d| d.tx.clone()).collect();
        Self {
            txs,
            height,
            partial_failure_ok: false,
            decoded_txs: Some(decoded_txs),
        }
    }

    /// T76.9: Create input with pre-decoded transactions and partial failure tolerance.
    #[cfg(feature = "pq44-runtime")]
    pub fn with_decoded_and_partial_failure(decoded_txs: Vec<Arc<DecodedTx>>, height: u64) -> Self {
        let txs: Vec<SignedTx> = decoded_txs.iter().map(|d| d.tx.clone()).collect();
        Self {
            txs,
            height,
            partial_failure_ok: true,
            decoded_txs: Some(decoded_txs),
        }
    }

    /// T76.9: Check if this input has pre-decoded transactions available.
    #[cfg(feature = "pq44-runtime")]
    pub fn has_decoded(&self) -> bool {
        self.decoded_txs.is_some()
    }

    /// T76.9: Get a reference to the decoded transactions if available.
    #[cfg(feature = "pq44-runtime")]
    pub fn get_decoded(&self) -> Option<&[Arc<DecodedTx>]> {
        self.decoded_txs.as_deref()
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
    
    /// T76.5: Per-reason breakdown of apply failures.
    /// Only populated when partial_failure_ok=true.
    pub failure_reasons: ApplyFailureCounts,
}

impl ExecOutcome {
    /// Create an ExecOutcome for legacy mode where all included txs must have succeeded.
    /// This constructor assumes apply_ok = tx_count and apply_fail = 0, which is correct
    /// for legacy mode where any tx failure causes the entire block to fail.
    pub fn new(result: Result<Block, String>, elapsed: Duration, tx_count: usize) -> Self {
        Self { 
            result, 
            elapsed, 
            tx_count, 
            apply_ok: tx_count, 
            apply_fail: 0,
            failure_reasons: ApplyFailureCounts::default(),
        }
    }

    /// T76.4: Create outcome with partial failure statistics.
    pub fn with_partial_stats(
        result: Result<Block, String>,
        elapsed: Duration,
        tx_count: usize,
        apply_ok: usize,
        apply_fail: usize,
    ) -> Self {
        Self { 
            result, 
            elapsed, 
            tx_count, 
            apply_ok, 
            apply_fail,
            failure_reasons: ApplyFailureCounts::default(),
        }
    }
    
    /// T76.5: Create outcome with full failure reason breakdown.
    pub fn with_failure_reasons(
        result: Result<Block, String>,
        elapsed: Duration,
        tx_count: usize,
        apply_ok: usize,
        apply_fail: usize,
        failure_reasons: ApplyFailureCounts,
    ) -> Self {
        Self { 
            result, 
            elapsed, 
            tx_count, 
            apply_ok, 
            apply_fail,
            failure_reasons,
        }
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