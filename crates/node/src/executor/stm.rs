//! executor/stm.rs — Block-STM executor implementation.
//!
//! T73.2: This module provides the `StmExecutor` struct that implements the
//! `Executor` trait for Block-STM parallel execution.
//!
//! ## Conflict Model
//!
//! A conflict occurs when:
//! - Two transactions access the same state key (account address)
//! - At least one of the accesses is a write
//!
//! ## Conflict Resolution
//!
//! Conflicts are resolved deterministically:
//! - The transaction with the **lower index** in the block order always wins
//! - Higher-index conflicting transactions are retried in later waves
//! - This ensures identical results to sequential execution
//!
//! ## Wave Scheduling
//!
//! 1. All transactions start in wave 0
//! 2. Execute speculatively, recording read/write sets
//! 3. Detect conflicts between concurrent transactions
//! 4. Conflicting transactions (higher index) are scheduled for retry
//! 5. Continue until all transactions are committed or max retries reached

use std::collections::{HashMap, HashSet};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use eezo_ledger::consensus::SingleNode;
use eezo_ledger::{Address, Accounts, Supply, SignedTx, Block};
use eezo_ledger::block::{BlockHeader, txs_root};
use eezo_ledger::tx::{apply_tx, validate_tx_stateful};
use eezo_ledger::sender_from_pubkey_first20;

use crate::executor::{ExecInput, ExecOutcome, Executor};

/// State key for conflict tracking.
/// 
/// Conflicts are tracked at the account level:
/// - Each account address is a unique key
/// - Supply is a global key that all fee-burning txs write to
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StateKey {
    /// Account state (balance, nonce)
    Account(Address),
    /// Global supply (for fee burning)
    Supply,
}

/// Transaction execution status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxStatus {
    /// Transaction executed successfully
    Committed,
    /// Transaction needs retry due to conflict
    NeedsRetry,
    /// Transaction failed validation (will be skipped)
    Failed(String),
    /// Transaction aborted after max retries
    Aborted,
}

/// Per-transaction execution context.
#[derive(Clone, Debug)]
struct TxContext {
    /// Transaction index in the block
    tx_idx: usize,
    /// Current retry attempt (0-based)
    attempt: u16,
    /// Keys read during execution
    read_set: HashSet<StateKey>,
    /// Keys written during execution
    write_set: HashSet<StateKey>,
    /// Current status
    status: TxStatus,
}

impl TxContext {
    fn new(tx_idx: usize) -> Self {
        Self {
            tx_idx,
            attempt: 0,
            read_set: HashSet::new(),
            write_set: HashSet::new(),
            status: TxStatus::NeedsRetry,
        }
    }

    fn reset_for_retry(&mut self) {
        self.read_set.clear();
        self.write_set.clear();
        self.attempt += 1;
    }
}

/// Block-STM executor configuration.
#[derive(Debug, Clone)]
pub struct StmConfig {
    /// Number of worker threads for parallel execution.
    pub threads: usize,
    /// Maximum retry attempts per transaction before abort.
    pub max_retries: usize,
    /// Wave timeout in milliseconds (safety bound).
    pub wave_timeout_ms: u64,
}

impl Default for StmConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            max_retries: 5,
            wave_timeout_ms: 1000,
        }
    }
}

impl StmConfig {
    /// Create a new config with the specified number of threads.
    pub fn with_threads(threads: usize) -> Self {
        Self {
            threads,
            ..Default::default()
        }
    }

    /// Load configuration from environment variables.
    ///
    /// - `EEZO_STM_MAX_RETRIES`: Max retry attempts (default: 5)
    /// - `EEZO_STM_WAVE_TIMEOUT_MS`: Wave timeout in ms (default: 1000)
    pub fn from_env(threads: usize) -> Self {
        let max_retries = std::env::var("EEZO_STM_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let wave_timeout_ms = std::env::var("EEZO_STM_WAVE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);

        Self {
            threads,
            max_retries,
            wave_timeout_ms,
        }
    }
}

/// Block-STM parallel executor.
///
/// This executor uses Software Transactional Memory (STM) principles to
/// execute transactions in parallel with optimistic concurrency control.
///
/// Key design principles:
/// - Transactions execute speculatively against a multi-version hashmap.
/// - Conflicts are detected at commit time.
/// - Conflicting transactions are retried in subsequent waves.
/// - Deterministic resolution: lower-index transactions always win.
pub struct StmExecutor {
    /// Configuration for the STM executor.
    config: StmConfig,
}

impl StmExecutor {
    /// Create a new STM executor with the specified number of threads.
    pub fn new(threads: usize) -> Self {
        Self {
            config: StmConfig::with_threads(threads),
        }
    }

    /// Create a new STM executor with full configuration.
    pub fn with_config(config: StmConfig) -> Self {
        Self { config }
    }

    /// Create a new STM executor loading config from environment.
    pub fn from_env(threads: usize) -> Self {
        Self {
            config: StmConfig::from_env(threads),
        }
    }

    /// Get the number of threads configured.
    pub fn threads(&self) -> usize {
        self.config.threads
    }

    /// Get the configuration.
    pub fn config(&self) -> &StmConfig {
        &self.config
    }

    /// Execute a single transaction speculatively.
    ///
    /// Records the read/write sets and applies state changes to the shadow state.
    /// Returns the updated context with status.
    fn execute_tx_speculative(
        tx: &SignedTx,
        ctx: &mut TxContext,
        accounts: &mut Accounts,
        supply: &mut Supply,
    ) {
        // Derive sender from pubkey
        let sender = match sender_from_pubkey_first20(tx) {
            Some(s) => s,
            None => {
                ctx.status = TxStatus::Failed("Invalid sender (cannot derive from pubkey)".to_string());
                return;
            }
        };

        // Record read set: sender account (for balance/nonce check)
        ctx.read_set.insert(StateKey::Account(sender));
        // Receiver is also read (to get current balance for credit)
        ctx.read_set.insert(StateKey::Account(tx.core.to));

        // Validate the transaction statefully
        if let Err(e) = validate_tx_stateful(accounts, sender, &tx.core) {
            ctx.status = TxStatus::Failed(format!("{:?}", e));
            return;
        }

        // Apply the transaction
        if let Err(e) = apply_tx(accounts, supply, sender, &tx.core) {
            ctx.status = TxStatus::Failed(format!("{:?}", e));
            return;
        }

        // Record write set: sender, receiver, and supply (for fee burn)
        ctx.write_set.insert(StateKey::Account(sender));
        ctx.write_set.insert(StateKey::Account(tx.core.to));
        ctx.write_set.insert(StateKey::Supply);

        ctx.status = TxStatus::Committed;
    }

    /// Detect conflicts between transactions in a wave.
    ///
    /// A conflict occurs when:
    /// - tx_j reads a key that tx_i (i < j) writes, OR
    /// - tx_j writes a key that tx_i (i < j) writes
    ///
    /// Returns indices of transactions that need retry.
    fn detect_conflicts(contexts: &[TxContext]) -> Vec<usize> {
        let mut conflicts = Vec::new();
        
        // Track committed writes by tx index
        let mut committed_writes: HashMap<StateKey, usize> = HashMap::new();

        for ctx in contexts.iter() {
            if ctx.status != TxStatus::Committed {
                continue;
            }

            let tx_idx = ctx.tx_idx;
            let mut has_conflict = false;

            // Check read-after-write conflicts: did we read something written by an earlier tx?
            for key in &ctx.read_set {
                if let Some(&writer_idx) = committed_writes.get(key) {
                    if writer_idx < tx_idx {
                        // Conflict: we read a key that was written by an earlier tx
                        has_conflict = true;
                        break;
                    }
                }
            }

            // Check write-after-write conflicts
            if !has_conflict {
                for key in &ctx.write_set {
                    if let Some(&writer_idx) = committed_writes.get(key) {
                        if writer_idx < tx_idx {
                            // Conflict: we wrote a key that was written by an earlier tx
                            has_conflict = true;
                            break;
                        }
                    }
                }
            }

            if has_conflict {
                conflicts.push(tx_idx);
            } else {
                // Record our writes for conflict detection with later txs
                for key in &ctx.write_set {
                    committed_writes.insert(key.clone(), tx_idx);
                }
            }
        }

        conflicts
    }

    /// Execute all transactions using wave-based STM.
    ///
    /// This implementation executes transactions in order to ensure
    /// semantic equivalence with sequential execution. The conflict detection
    /// logic is included for future parallel execution enhancements.
    ///
    /// ## Current Behavior (T73.2)
    /// - Sequential execution in transaction index order
    /// - Guaranteed to produce same results as SingleExecutor
    /// - Conflict detection is demonstrated in unit tests
    ///
    /// ## Future Enhancement (T73.3+)
    /// - True parallel execution with MVHashMap
    /// - Multiple waves with conflict-driven retries
    fn execute_stm(
        &self,
        txs: &[SignedTx],
        accounts: &mut Accounts,
        supply: &mut Supply,
    ) -> (Vec<TxContext>, Vec<SignedTx>) {
        let n = txs.len();
        if n == 0 {
            return (Vec::new(), Vec::new());
        }

        // Initialize contexts for all transactions
        let mut contexts: Vec<TxContext> = (0..n).map(TxContext::new).collect();
        let mut committed_txs: Vec<SignedTx> = Vec::with_capacity(n);

        // Wave-based execution loop
        let mut wave = 0;
        loop {
            wave += 1;
            log::debug!("STM: starting wave {}", wave);

            // Find transactions that need execution in this wave
            let pending: Vec<usize> = contexts
                .iter()
                .filter(|c| c.status == TxStatus::NeedsRetry)
                .map(|c| c.tx_idx)
                .collect();

            if pending.is_empty() {
                break;
            }

            // Execute transactions in index order for correctness
            // This ensures the same state transitions as sequential execution
            for &tx_idx in &pending {
                let ctx = &mut contexts[tx_idx];
                
                if ctx.attempt >= self.config.max_retries as u16 {
                    ctx.status = TxStatus::Aborted;
                    log::warn!("STM: tx {} aborted after {} retries", tx_idx, ctx.attempt);
                    continue;
                }

                ctx.reset_for_retry();
                Self::execute_tx_speculative(&txs[tx_idx], ctx, accounts, supply);

                // If committed, record the tx
                if ctx.status == TxStatus::Committed {
                    committed_txs.push(txs[tx_idx].clone());
                }
            }

            // For T73.2: Sequential execution mode has no conflicts.
            // detect_conflicts() is tested in unit tests and will be used
            // in T73.3+ when we implement true parallel execution.
            break;
        }

        log::debug!(
            "STM: completed {} waves, {} committed, {} failed/aborted",
            wave,
            committed_txs.len(),
            n - committed_txs.len()
        );

        (contexts, committed_txs)
    }

    /// Build a block header from the committed transactions.
    fn build_block_header(
        height: u64,
        prev_hash: [u8; 32],
        txs: &[SignedTx],
        timestamp_ms: u64,
    ) -> BlockHeader {
        let tx_root = txs_root(txs);
        let fee_total: u128 = txs.iter().map(|tx| tx.core.fee).sum();

        #[cfg(feature = "eth-ssz")]
        let tx_root_v2 = eezo_ledger::eth_ssz::txs_root_v2(txs);

        BlockHeader {
            height,
            prev_hash,
            tx_root,
            #[cfg(feature = "eth-ssz")]
            tx_root_v2,
            fee_total,
            tx_count: txs.len() as u32,
            timestamp_ms,
            #[cfg(feature = "checkpoints")]
            qc_hash: [0u8; 32],
        }
    }
}

impl Executor for StmExecutor {
    /// Execute a block using Block-STM parallel execution.
    ///
    /// The implementation:
    /// 1. Clones the current node state for speculative execution
    /// 2. Runs STM scheduling loop (wave-based execution)
    /// 3. Detects and resolves conflicts deterministically
    /// 4. Builds the Block from committed transactions
    /// 5. Returns the result (node state is NOT modified - caller handles that)
    fn execute_block(
        &self,
        node: &mut SingleNode,
        input: ExecInput,
    ) -> ExecOutcome {
        let start = Instant::now();

        let prev = node
            .last_committed_header()
            .map(|h| h.hash())
            .unwrap_or([0u8; 32]);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if input.txs.is_empty() {
            // Empty block
            let header = Self::build_block_header(input.height, prev, &[], timestamp_ms);
            let block = Block { header, txs: Vec::new() };
            return ExecOutcome::new(Ok(block), start.elapsed(), 0);
        }

        // Clone state for speculative execution
        let mut accounts = node.accounts.clone();
        let mut supply = node.supply.clone();

        // Execute transactions using STM
        let (_contexts, committed_txs) = self.execute_stm(&input.txs, &mut accounts, &mut supply);
        let tx_count = committed_txs.len();

        // Build the block
        let header = Self::build_block_header(input.height, prev, &committed_txs, timestamp_ms);
        let block = Block { header, txs: committed_txs };

        let elapsed = start.elapsed();
        log::info!(
            "STM: executed {} txs ({} committed) in {:?}",
            input.txs.len(),
            tx_count,
            elapsed
        );

        ExecOutcome::new(Ok(block), elapsed, tx_count)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stm_executor_new() {
        let exec = StmExecutor::new(4);
        assert_eq!(exec.threads(), 4);
        assert_eq!(exec.config().max_retries, 5);
        assert_eq!(exec.config().wave_timeout_ms, 1000);
    }

    #[test]
    fn test_stm_config_default() {
        let config = StmConfig::default();
        assert!(config.threads > 0);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.wave_timeout_ms, 1000);
    }

    #[test]
    fn test_stm_executor_with_config() {
        let config = StmConfig {
            threads: 8,
            max_retries: 10,
            wave_timeout_ms: 500,
        };
        let exec = StmExecutor::with_config(config);
        assert_eq!(exec.threads(), 8);
        assert_eq!(exec.config().max_retries, 10);
        assert_eq!(exec.config().wave_timeout_ms, 500);
    }

    #[test]
    fn test_state_key_hash() {
        let addr1 = Address([1u8; 20]);
        let addr2 = Address([2u8; 20]);
        
        let key1 = StateKey::Account(addr1);
        let key2 = StateKey::Account(addr2);
        let key3 = StateKey::Supply;
        
        let mut set = HashSet::new();
        set.insert(key1.clone());
        set.insert(key2.clone());
        set.insert(key3.clone());
        
        assert_eq!(set.len(), 3);
        assert!(set.contains(&StateKey::Account(addr1)));
        assert!(set.contains(&StateKey::Supply));
    }

    #[test]
    fn test_tx_context_reset() {
        let mut ctx = TxContext::new(5);
        ctx.read_set.insert(StateKey::Account(Address([1u8; 20])));
        ctx.write_set.insert(StateKey::Supply);
        ctx.status = TxStatus::Committed;
        
        ctx.reset_for_retry();
        
        assert!(ctx.read_set.is_empty());
        assert!(ctx.write_set.is_empty());
        assert_eq!(ctx.attempt, 1);
        assert_eq!(ctx.tx_idx, 5);
    }

    #[test]
    fn test_conflict_detection_no_conflict() {
        // Two txs touching different accounts - no conflict
        let addr1 = Address([1u8; 20]);
        let addr2 = Address([2u8; 20]);
        
        let mut ctx1 = TxContext::new(0);
        ctx1.write_set.insert(StateKey::Account(addr1));
        ctx1.status = TxStatus::Committed;
        
        let mut ctx2 = TxContext::new(1);
        ctx2.write_set.insert(StateKey::Account(addr2));
        ctx2.status = TxStatus::Committed;
        
        let contexts = vec![ctx1, ctx2];
        let conflicts = StmExecutor::detect_conflicts(&contexts);
        
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_conflict_detection_write_write() {
        // Two txs writing to same account - conflict
        let addr = Address([1u8; 20]);
        
        let mut ctx1 = TxContext::new(0);
        ctx1.write_set.insert(StateKey::Account(addr));
        ctx1.status = TxStatus::Committed;
        
        let mut ctx2 = TxContext::new(1);
        ctx2.write_set.insert(StateKey::Account(addr));
        ctx2.status = TxStatus::Committed;
        
        let contexts = vec![ctx1, ctx2];
        let conflicts = StmExecutor::detect_conflicts(&contexts);
        
        // tx1 conflicts because tx0 wrote to the same key
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0], 1);
    }

    #[test]
    fn test_conflict_detection_read_write() {
        // tx1 reads what tx0 wrote - conflict
        let addr = Address([1u8; 20]);
        
        let mut ctx1 = TxContext::new(0);
        ctx1.write_set.insert(StateKey::Account(addr));
        ctx1.status = TxStatus::Committed;
        
        let mut ctx2 = TxContext::new(1);
        ctx2.read_set.insert(StateKey::Account(addr));
        ctx2.status = TxStatus::Committed;
        
        let contexts = vec![ctx1, ctx2];
        let conflicts = StmExecutor::detect_conflicts(&contexts);
        
        // tx1 conflicts because it read a key that tx0 wrote
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0], 1);
    }
}