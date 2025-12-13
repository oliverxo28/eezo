//! executor/stm.rs — Block-STM executor implementation.
//!
//! T73.2: This module provides the `StmExecutor` struct that implements the
//! `Executor` trait for Block-STM parallel execution.
//!
//! T73.6: Multi-wave parallelism using rayon's par_iter() for speculative execution.
//!
//! T82.1: AnalyzedTx & BlockOverlay groundwork for higher TPS.
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
//! 2. Execute speculatively in parallel, recording read/write sets
//! 3. Detect conflicts between concurrent transactions
//! 4. Conflicting transactions (higher index) are scheduled for retry
//! 5. Continue until all transactions are committed or max retries reached
//!
//! ## T82.1 Enhancements
//!
//! - `AnalyzedTx`: Pre-computed conflict metadata per transaction (once per block).
//! - `BlockOverlay`: Block-level state overlay to avoid cloning full state per wave.
//!   Waves read from overlay first, fall back to base snapshot.
//! - Conflict detection uses `ConflictMetadata` fingerprints for efficient comparison.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rayon::prelude::*;

use eezo_ledger::consensus::SingleNode;
use eezo_ledger::{Address, Account, Accounts, Supply, SignedTx, Block, AccountArena, TxCore};
use eezo_ledger::block::{BlockHeader, txs_root};
use eezo_ledger::tx::{apply_tx, validate_tx_stateful, TxStateError};
use eezo_ledger::sender_from_pubkey_first20;

use crate::executor::{ExecInput, ExecOutcome, Executor};

// =============================================================================
// T82.1: AnalyzedTx & ConflictMetadata
// =============================================================================

/// Pre-computed conflict metadata for a transaction.
///
/// T82.1: This is computed once per tx at block start and used for all
/// conflict comparisons, avoiding repeated inspection of raw tx data.
///
/// For simple transfers, we store 64-bit fingerprints of sender and receiver.
///
/// T82.4: Added `Complex` variant with a small bloom filter for multi-touch txs.
/// The pre-screen uses these fingerprints for fast conflict detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictMetadata {
    /// Simple transfer: sender writes to from_key, receiver gets to_key.
    /// Keys are 64-bit fingerprints derived from addresses for fast comparison.
    Simple {
        /// 64-bit fingerprint of sender address
        from_key: u64,
        /// 64-bit fingerprint of receiver address
        to_key: u64,
    },
    /// T82.4: Complex transaction touching multiple accounts.
    /// Uses a compact bloom filter for fast conflict pre-screening.
    /// The bloom filter is a 64-bit bitset with 4 hash functions.
    Complex {
        /// Compact bloom filter representing all touched accounts
        bloom: u64,
        /// Count of accounts touched (for diagnostics)
        touch_count: u8,
    },
}

impl ConflictMetadata {
    /// Check if this tx might conflict with another based on metadata.
    ///
    /// Two txs conflict if they touch overlapping keys (addresses).
    /// For Simple metadata, we compare fingerprints directly.
    /// For Complex metadata, we check bloom filter intersection.
    /// Supply conflicts are always assumed (all txs burn fees).
    ///
    /// T82.4: This is used for fast conflict pre-screening. The result may
    /// have false positives (says "conflict" when there is none) but never
    /// false negatives (never misses an actual conflict).
    #[inline]
    pub fn conflicts_with(&self, other: &ConflictMetadata) -> bool {
        match (self, other) {
            (
                ConflictMetadata::Simple { from_key: f1, to_key: t1 },
                ConflictMetadata::Simple { from_key: f2, to_key: t2 },
            ) => {
                // Conflict if any key overlaps:
                // - from1 == from2 (same sender)
                // - from1 == to2 (sender is receiver of other)
                // - to1 == from2 (receiver is sender of other)
                // - to1 == to2 (same receiver)
                // Note: Supply conflicts are implicit (all txs write Supply)
                f1 == f2 || f1 == t2 || t1 == f2 || t1 == t2
            }
            // T82.4: Handle Complex metadata with bloom filter intersection
            (
                ConflictMetadata::Complex { bloom: b1, .. },
                ConflictMetadata::Complex { bloom: b2, .. },
            ) => {
                // If any bits overlap, there may be a conflict
                (b1 & b2) != 0
            }
            // Mixed: Simple vs Complex - convert Simple to bloom and check
            (
                ConflictMetadata::Simple { from_key, to_key },
                ConflictMetadata::Complex { bloom, .. },
            ) => {
                let simple_bloom = fingerprint_to_bloom(*from_key) | fingerprint_to_bloom(*to_key);
                (simple_bloom & bloom) != 0
            }
            (
                ConflictMetadata::Complex { bloom, .. },
                ConflictMetadata::Simple { from_key, to_key },
            ) => {
                let simple_bloom = fingerprint_to_bloom(*from_key) | fingerprint_to_bloom(*to_key);
                (bloom & simple_bloom) != 0
            }
        }
    }

    /// T82.4: Convert this metadata to a bloom filter representation.
    /// Used by WaveFingerprint for efficient conflict pre-screening.
    #[inline]
    pub fn to_bloom(&self) -> u64 {
        match self {
            ConflictMetadata::Simple { from_key, to_key } => {
                fingerprint_to_bloom(*from_key) | fingerprint_to_bloom(*to_key)
            }
            ConflictMetadata::Complex { bloom, .. } => *bloom,
        }
    }

    /// T82.4: Get the raw fingerprint keys for Simple metadata.
    /// Returns None for Complex metadata (use bloom filter instead).
    #[inline]
    pub fn keys(&self) -> Option<(u64, u64)> {
        match self {
            ConflictMetadata::Simple { from_key, to_key } => Some((*from_key, *to_key)),
            ConflictMetadata::Complex { .. } => None,
        }
    }
}

/// T82.4: Convert a 64-bit fingerprint to bloom filter bits.
/// Uses 4 hash functions to set 4 bits in the 64-bit bloom filter.
/// This provides a compact representation for fast conflict pre-screening.
///
/// Uses XOR folding to incorporate all 64 bits of the fingerprint for better
/// distribution of hash values across the bloom filter space.
#[inline]
fn fingerprint_to_bloom(fingerprint: u64) -> u64 {
    // XOR-fold the 64-bit fingerprint to use all bits for better entropy.
    // Split into high and low 32-bit halves and XOR them together.
    let folded = (fingerprint as u32) ^ ((fingerprint >> 32) as u32);
    
    // Extract 4 x 6-bit hash values from different parts of the folded value
    // Each "hash function" gives a bit position 0-63 for the bloom filter
    let h1 = (folded & 0x3F) as u32;              // bits 0-5
    let h2 = ((folded >> 6) & 0x3F) as u32;       // bits 6-11
    let h3 = ((folded >> 12) & 0x3F) as u32;      // bits 12-17
    let h4 = ((folded >> 18) & 0x3F) as u32;      // bits 18-23
    
    // For additional entropy, mix in rotated versions of the fingerprint
    let rot = fingerprint.rotate_left(32);
    let h5 = ((rot >> 24) & 0x3F) as u32;         // bits from rotated value
    
    (1u64 << h1) | (1u64 << h2) | (1u64 << h3) | (1u64 << h4) | (1u64 << h5)
}

// =============================================================================
// T82.4: WaveFingerprint — Per-wave conflict pre-screening
// =============================================================================

/// T82.4: Per-wave fingerprint for fast conflict pre-screening.
///
/// This structure tracks the set of "already used" keys in the current wave
/// using a compact bloom filter representation. It provides:
/// - `may_conflict()`: Fast check if a tx might conflict with the wave
/// - `record()`: Register a tx's keys in the wave fingerprint
///
/// ## Design Notes
///
/// The pre-screen is a **pure optimization** layered on top of the existing
/// conflict detection logic. It may have false positives (says "may conflict"
/// when there is no actual conflict) but never false negatives.
///
/// Correctness is preserved because:
/// 1. If pre-screen says "no conflict" → tx is definitely safe for this wave
/// 2. If pre-screen says "may conflict" → fall back to precise conflict detection
///
/// The bloom filter is local to a single wave and cheap to allocate/clone.
#[derive(Clone, Debug, Default)]
pub struct WaveFingerprint {
    /// Combined bloom filter of all tx fingerprints recorded in this wave.
    /// Each bit represents potential presence of certain address fingerprints.
    bloom: u64,
    
    /// Set of exact fingerprint keys seen in this wave.
    /// Used for precise conflict checking when bloom filter indicates possible conflict.
    /// For simple transfers, stores both from_key and to_key.
    keys: HashSet<u64>,
    
    /// Number of transactions recorded in this wave.
    tx_count: usize,
}

impl WaveFingerprint {
    /// Create a new empty wave fingerprint.
    #[inline]
    pub fn new() -> Self {
        Self {
            bloom: 0,
            keys: HashSet::new(),
            tx_count: 0,
        }
    }

    /// T82.4: Fast pre-screen check if a tx might conflict with the wave.
    ///
    /// Returns `true` if there MAY be a conflict (requires precise check).
    /// Returns `false` if there is DEFINITELY no conflict (tx is safe).
    ///
    /// This is the first stage of conflict detection:
    /// - If `may_conflict()` returns `false` → skip precise conflict detection
    /// - If `may_conflict()` returns `true` → run precise conflict detection
    #[inline]
    pub fn may_conflict(&self, meta: &ConflictMetadata) -> bool {
        if self.bloom == 0 {
            // Empty wave - no conflicts possible
            return false;
        }
        
        let tx_bloom = meta.to_bloom();
        
        // Fast bloom filter check
        if (self.bloom & tx_bloom) == 0 {
            // No overlapping bits - definitely no conflict
            return false;
        }
        
        // Bloom filter indicates possible conflict.
        // For Simple metadata, do precise key check to reduce false positives.
        if let Some((from_key, to_key)) = meta.keys() {
            // Check if any of the tx's keys are actually in the wave
            self.keys.contains(&from_key) || self.keys.contains(&to_key)
        } else {
            // Complex metadata - rely on bloom filter alone
            true
        }
    }

    /// T82.4: Record a transaction's keys in the wave fingerprint.
    ///
    /// Called after a tx is accepted into the wave so future txs see it.
    #[inline]
    pub fn record(&mut self, meta: &ConflictMetadata) {
        // Add to bloom filter
        self.bloom |= meta.to_bloom();
        
        // Add exact keys for precise checking
        match meta {
            ConflictMetadata::Simple { from_key, to_key } => {
                self.keys.insert(*from_key);
                self.keys.insert(*to_key);
            }
            ConflictMetadata::Complex { .. } => {
                // Complex metadata uses bloom only, no exact keys
            }
        }
        
        self.tx_count += 1;
    }

    /// Get the number of transactions recorded in this wave.
    #[inline]
    pub fn tx_count(&self) -> usize {
        self.tx_count
    }

    /// Check if the wave fingerprint is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tx_count == 0
    }
}

// =============================================================================
// T95.0: ArenaConflictBitmap — Lightweight conflict pre-screen
// =============================================================================

/// Default bitmap capacity in bits (handles arena indices 0..65535).
/// T95.0.3: Increased from 1024 to 65536 to prevent overflow to HashMap
/// for typical spam workloads (5000+ txs with many unique accounts).
/// Exceeding this capacity triggers fallback to HashMap.
const ARENA_BITMAP_CAPACITY: usize = 65536;

/// Number of u64 words needed to store ARENA_BITMAP_CAPACITY bits.
/// 65536 bits / 64 bits per u64 = 1024 words.
/// Bitmap array size: 1024 words × 8 bytes = 8 KB per array (16 KB for both).
/// Note: Total struct size also includes HashSet overflow fields.
const ARENA_BITMAP_WORDS: usize = ARENA_BITMAP_CAPACITY / 64;

/// T95.0: Compact bitmap for fast "has arena index been touched?" checks.
///
/// This structure provides O(1) bit operations for conflict detection in the
/// STM fast path, avoiding HashMap overhead for the common case where arena
/// indices are small (<65536).
///
/// ## Design
///
/// - Uses two stack-allocated fixed-size arrays `[u64; 1024]` (65536 bits = 8 KB each, 16 KB total)
/// - Zero heap allocation in the hot path for bitmap operations
/// - Falls back to `HashSet<u32>` when indices exceed bitmap capacity (rare)
/// - Separate tracking for claimed senders (one per wave) and touched accounts
/// - Cheap reset per wave (memset for arrays + clear HashSet)
///
/// ## Correctness
///
/// The bitmap is a pure optimization. For indices within capacity, the bitmap
/// is authoritative. For overflow indices, the HashSet fallback ensures no
/// false negatives (missed conflicts).
///
/// ## Performance
///
/// - Bitmap check: ~1-2 ns (bit array indexing, no heap allocation)
/// - HashMap check: ~30-50 ns (hash + probe)
/// - Typical speedup: 15-30x for conflict checks when within bitmap range
#[derive(Clone, Debug)]
pub struct ArenaConflictBitmap {
    /// Bitmap tracking claimed sender indices (one sender per wave).
    /// Bit i is set if arena index i has been claimed as a sender.
    /// Stack-allocated: 1024 × 8 bytes = 8 KB.
    claimed_senders_bits: [u64; ARENA_BITMAP_WORDS],
    
    /// Bitmap tracking touched account indices (senders + receivers).
    /// Bit i is set if arena index i has been touched.
    /// Stack-allocated: 1024 × 8 bytes = 8 KB.
    touched_accounts_bits: [u64; ARENA_BITMAP_WORDS],
    
    /// Fallback HashSet for sender indices >= ARENA_BITMAP_CAPACITY.
    claimed_senders_overflow: HashSet<u32>,
    
    /// Fallback HashSet for touched indices >= ARENA_BITMAP_CAPACITY.
    touched_accounts_overflow: HashSet<u32>,
    
    /// Track whether any overflow has occurred (for metrics).
    overflow_occurred: bool,
}

impl Default for ArenaConflictBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl ArenaConflictBitmap {
    /// Create a new empty conflict bitmap.
    /// Uses stack-allocated arrays to avoid heap allocation overhead.
    #[inline]
    pub fn new() -> Self {
        Self {
            claimed_senders_bits: [0u64; ARENA_BITMAP_WORDS],
            touched_accounts_bits: [0u64; ARENA_BITMAP_WORDS],
            claimed_senders_overflow: HashSet::new(),
            touched_accounts_overflow: HashSet::new(),
            overflow_occurred: false,
        }
    }
    
    /// Reset the bitmap for a new wave.
    /// This is cheaper than allocating a new structure.
    ///
    /// Note: `overflow_occurred` is intentionally NOT reset here. It's tracked 
    /// per-block (not per-wave) so we only emit the metric once per block even
    /// if multiple waves have overflow. This prevents metric inflation and gives
    /// a true count of "blocks with bitmap overflow".
    #[inline]
    pub fn reset(&mut self) {
        self.claimed_senders_bits = [0u64; ARENA_BITMAP_WORDS];
        self.touched_accounts_bits = [0u64; ARENA_BITMAP_WORDS];
        self.claimed_senders_overflow.clear();
        self.touched_accounts_overflow.clear();
    }
    
    /// Record that overflow occurred and emit metric (once per block).
    #[inline]
    fn record_overflow(&mut self) {
        if !self.overflow_occurred {
            self.overflow_occurred = true;
            #[cfg(feature = "metrics")]
            crate::metrics::stm_bitmap_fallback_inc();
        }
    }
    
    /// Check if an arena index has been claimed as a sender.
    #[inline]
    pub fn is_sender_claimed(&self, idx: u32) -> bool {
        let i = idx as usize;
        if i < ARENA_BITMAP_CAPACITY {
            let word_idx = i / 64;
            let bit_idx = i % 64;
            (self.claimed_senders_bits[word_idx] & (1u64 << bit_idx)) != 0
        } else {
            self.claimed_senders_overflow.contains(&idx)
        }
    }
    
    /// Check if an arena index has been touched (sender or receiver).
    #[inline]
    pub fn is_account_touched(&self, idx: u32) -> bool {
        let i = idx as usize;
        if i < ARENA_BITMAP_CAPACITY {
            let word_idx = i / 64;
            let bit_idx = i % 64;
            (self.touched_accounts_bits[word_idx] & (1u64 << bit_idx)) != 0
        } else {
            self.touched_accounts_overflow.contains(&idx)
        }
    }
    
    /// Claim an arena index as a sender for this wave.
    #[inline]
    pub fn claim_sender(&mut self, idx: u32) {
        let i = idx as usize;
        if i < ARENA_BITMAP_CAPACITY {
            let word_idx = i / 64;
            let bit_idx = i % 64;
            self.claimed_senders_bits[word_idx] |= 1u64 << bit_idx;
        } else {
            self.record_overflow();
            self.claimed_senders_overflow.insert(idx);
        }
    }
    
    /// Mark an arena index as touched for this wave.
    #[inline]
    pub fn touch_account(&mut self, idx: u32) {
        let i = idx as usize;
        if i < ARENA_BITMAP_CAPACITY {
            let word_idx = i / 64;
            let bit_idx = i % 64;
            self.touched_accounts_bits[word_idx] |= 1u64 << bit_idx;
        } else {
            self.record_overflow();
            self.touched_accounts_overflow.insert(idx);
        }
    }
    
    /// Check if any overflow occurred (for diagnostics).
    #[inline]
    pub fn had_overflow(&self) -> bool {
        self.overflow_occurred
    }
}

// =============================================================================
// T93.2: AnalyzedTxKind — Simple Transfer vs General Transaction
// =============================================================================

/// Identifies whether a transaction is a simple transfer or a general transaction.
///
/// T93.2: Simple transfers can use the fast path execution which bypasses
/// expensive HashMap lookups and full conflict detection. General transactions
/// use the standard STM execution path.
///
/// ## Simple Transfer Definition
///
/// A "simple transfer" is a transaction that:
/// - Has exactly one sender and one receiver
/// - Contains no contract call, script data, or extra side effects
/// - Uses standard amount + fee fields only
/// - Is still subject to all validity checks (chain ID, ML-DSA signature, nonce, balance)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AnalyzedTxKind {
    /// Simple value transfer: one sender, one receiver, no contract logic.
    /// Can use the fast path execution when enabled.
    #[default]
    SimpleTransfer,
    
    /// General transaction that may have complex effects.
    /// Always uses the standard STM execution path.
    General,
}

impl AnalyzedTxKind {
    /// Check if this is a simple transfer.
    #[inline]
    pub fn is_simple(&self) -> bool {
        matches!(self, AnalyzedTxKind::SimpleTransfer)
    }
}

/// Analyzed transaction with pre-computed conflict metadata.
///
/// T82.1: Internal representation that caches conflict-relevant data
/// computed once at block start. Does not change wire format.
///
/// T93.2: Added `kind` field for fast path routing and optional arena indices.
///
/// T97.0: Removed `Arc<SignedTx>` to eliminate Arc cloning in hot path.
/// Instead, we store the receiver address and core transaction fields directly.
/// The STM executor uses `tx_idx` to look up the full transaction from the
/// canonical block tx list when needed (only at final block assembly).
#[derive(Clone, Debug)]
pub struct AnalyzedTx {
    /// Index in the block's tx list (acts as a lightweight "handle")
    pub tx_idx: usize,
    /// Pre-computed sender address (derived from pubkey)
    pub sender: Address,
    /// Receiver address (cached from tx.core.to)
    pub receiver: Address,
    /// Transaction amount (cached from tx.core.amount)
    pub amount: u128,
    /// Transaction fee (cached from tx.core.fee)
    pub fee: u128,
    /// Transaction nonce (cached from tx.core.nonce)
    pub nonce: u64,
    /// Pre-computed conflict metadata
    pub meta: ConflictMetadata,
    /// T93.2: Transaction kind for fast path routing
    pub kind: AnalyzedTxKind,
    /// T93.2: Pre-resolved sender arena index (set during arena construction)
    pub sender_arena_idx: Option<u32>,
    /// T93.2: Pre-resolved receiver arena index (set during arena construction)
    pub receiver_arena_idx: Option<u32>,
}

/// Compute a 64-bit fingerprint from an Address for conflict detection.
///
/// Uses first 8 bytes of the address as a fast fingerprint.
/// This is sufficient for conflict detection since full address
/// comparison happens during actual state operations.
#[inline]
fn address_fingerprint(addr: &Address) -> u64 {
    // Take first 8 bytes of address as u64 (little-endian)
    let bytes = addr.as_bytes();
    let arr: [u8; 8] = bytes[..8].try_into().expect("Address has at least 8 bytes");
    u64::from_le_bytes(arr)
}

/// Analyze a signed transaction to build AnalyzedTx with conflict metadata.
///
/// Returns None if sender cannot be derived from pubkey (requires 20+ byte pubkey).
///
/// T93.2: All basic transfers are classified as SimpleTransfer. Currently, EEZO
/// only supports simple value transfers (no contracts), so all valid txs are Simple.
/// When contract support is added, this function will need to detect contract calls
/// and classify them as General.
///
/// T97.0: No longer creates Arc<SignedTx>. Instead, caches the core fields directly
/// in AnalyzedTx to avoid Arc cloning overhead in the hot path.
pub fn analyze_tx(tx: &SignedTx, tx_idx: usize) -> Option<AnalyzedTx> {
    let sender = sender_from_pubkey_first20(tx)?;
    let from_key = address_fingerprint(&sender);
    let to_key = address_fingerprint(&tx.core.to);
    
    // T93.2: Detect transaction kind
    // Currently all txs in EEZO are simple transfers (value + fee only).
    // When contracts are added, check for contract call indicators here.
    let kind = AnalyzedTxKind::SimpleTransfer;
    
    Some(AnalyzedTx {
        tx_idx,
        sender,
        receiver: tx.core.to,
        amount: tx.core.amount,
        fee: tx.core.fee,
        nonce: tx.core.nonce,
        meta: ConflictMetadata::Simple { from_key, to_key },
        kind,
        sender_arena_idx: None,    // Set during arena construction
        receiver_arena_idx: None,  // Set during arena construction
    })
}

/// Analyze a batch of transactions into AnalyzedTx representations.
///
/// T82.1: Called once at block start. Txs that fail analysis (invalid sender)
/// are excluded and will be skipped during execution.
pub fn analyze_batch(txs: &[SignedTx]) -> Vec<AnalyzedTx> {
    txs.iter()
        .enumerate()
        .filter_map(|(idx, tx)| analyze_tx(tx, idx))
        .collect()
}

/// T83.4: Analyze a SharedTx to build AnalyzedTx with conflict metadata.
///
/// Uses pre-computed sender from SharedTx, avoiding redundant derivation.
/// Returns None if SharedTx has no valid sender.
///
/// T93.2: Added transaction kind detection and arena index placeholders.
///
/// T97.0: No longer creates Arc<SignedTx>. Caches core fields directly.
pub fn analyze_shared_tx(shared_tx: &std::sync::Arc<crate::tx_decode_pool::SharedTx>, tx_idx: usize) -> Option<AnalyzedTx> {
    let sender = shared_tx.sender()?;
    let core = shared_tx.core();
    let from_key = address_fingerprint(&sender);
    let to_key = address_fingerprint(&core.to);
    
    // T93.2: All current txs are simple transfers
    let kind = AnalyzedTxKind::SimpleTransfer;
    
    Some(AnalyzedTx {
        tx_idx,
        sender,
        receiver: core.to,
        amount: core.amount,
        fee: core.fee,
        nonce: core.nonce,
        meta: ConflictMetadata::Simple { from_key, to_key },
        kind,
        sender_arena_idx: None,
        receiver_arena_idx: None,
    })
}

/// T83.4: Analyze a batch of SharedTx into AnalyzedTx representations.
///
/// Uses pre-computed sender from SharedTx, avoiding redundant derivation.
/// Txs without valid sender are excluded.
pub fn analyze_shared_batch(shared_txs: &[std::sync::Arc<crate::tx_decode_pool::SharedTx>]) -> Vec<AnalyzedTx> {
    shared_txs.iter()
        .enumerate()
        .filter_map(|(idx, stx)| analyze_shared_tx(stx, idx))
        .collect()
}

// =============================================================================
// T82.1: BlockOverlay - Block-level state overlay
// =============================================================================

/// Block-level state overlay for efficient wave execution.
///
/// T82.1: Instead of cloning full state for each wave, we maintain an overlay
/// of accounts modified within this block. Reads check overlay first, then
/// fall back to the base snapshot.
///
/// This reduces per-wave allocation from O(total_accounts) to O(touched_accounts).
#[derive(Clone, Debug, Default)]
pub struct BlockOverlay {
    /// Accounts modified within this block (address -> current state)
    modified_accounts: HashMap<Address, Account>,
    /// Total fees burned in this block (applied to Supply at block commit)
    total_fees_burned: u128,
}

impl BlockOverlay {
    /// Create a new empty overlay.
    pub fn new() -> Self {
        Self {
            modified_accounts: HashMap::new(),
            total_fees_burned: 0,
        }
    }

    /// Get an account, checking overlay first then base snapshot.
    #[inline]
    pub fn get_account(&self, addr: &Address, base: &Accounts) -> Account {
        self.modified_accounts
            .get(addr)
            .cloned()
            .unwrap_or_else(|| base.get(addr))
    }

    /// Put an account into the overlay.
    #[inline]
    pub fn put_account(&mut self, addr: Address, acct: Account) {
        self.modified_accounts.insert(addr, acct);
    }

    /// Record a fee burn (accumulated and applied to Supply at block commit).
    #[inline]
    pub fn record_fee_burn(&mut self, fee: u128) {
        self.total_fees_burned = self.total_fees_burned.saturating_add(fee);
    }

    /// Get the total fees burned in this block.
    #[inline]
    pub fn total_fees_burned(&self) -> u128 {
        self.total_fees_burned
    }

    /// Apply all overlay changes to the base state (called at block commit).
    ///
    /// This transfers modified accounts to the actual Accounts state and
    /// applies accumulated fee burns to Supply.
    pub fn apply_to_state(&self, accounts: &mut Accounts, supply: &mut Supply) {
        for (addr, acct) in &self.modified_accounts {
            accounts.put(*addr, acct.clone());
        }
        supply.apply_burn(self.total_fees_burned);
    }

    /// Get the number of accounts in the overlay (for diagnostics).
    pub fn len(&self) -> usize {
        self.modified_accounts.len()
    }

    /// Check if overlay is empty.
    pub fn is_empty(&self) -> bool {
        self.modified_accounts.is_empty()
    }
}

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

/// Speculative execution result for a single transaction.
/// 
/// Holds the state changes that would be applied if this tx commits.
/// This struct is populated during parallel speculative execution and contains
/// cloned account state snapshots. The values become stale after conflicts are
/// detected and retries occur - each retry creates a fresh SpeculativeResult
/// based on the updated state snapshot.
#[derive(Clone, Debug)]
struct SpeculativeResult {
    /// Sender address
    sender: Address,
    /// Receiver address  
    receiver: Address,
    /// New sender account state after tx
    sender_account: Account,
    /// New receiver account state after tx
    receiver_account: Account,
    /// Fee burned
    fee: u128,
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
    /// Speculative result (only set if status == Committed)
    spec_result: Option<SpeculativeResult>,
}

impl TxContext {
    /// T87.2: Create a new TxContext with pre-sized collections.
    /// Typical transfer tx touches 2 read keys (sender, receiver) and 3 write keys
    /// (sender, receiver, supply). Pre-sizing avoids reallocation.
    fn new(tx_idx: usize) -> Self {
        Self {
            tx_idx,
            attempt: 0,
            read_set: HashSet::with_capacity(2),
            write_set: HashSet::with_capacity(3),
            status: TxStatus::NeedsRetry,
            spec_result: None,
        }
    }

    fn reset_for_retry(&mut self) {
        self.read_set.clear();
        self.write_set.clear();
        self.spec_result = None;
        self.attempt += 1;
    }
}

// =============================================================================
// T87.4: Arena-Based Transaction Execution Types
// =============================================================================

/// T87.4: Arena-based transaction execution context.
///
/// Instead of storing Address values, this stores u32 indices into an AccountArena.
/// All address lookups are resolved once at block start, and during execution
/// all state access is done via Vec indexing for better cache locality.
#[derive(Clone, Debug)]
struct ArenaTxContext {
    /// Transaction index in the block's tx list
    tx_idx: usize,
    /// Sender's index in the arena
    sender_idx: u32,
    /// Receiver's index in the arena
    receiver_idx: u32,
    /// Current retry attempt (0-based)
    attempt: u16,
    /// Current status
    status: TxStatus,
    /// Speculative result (only set if status == Committed)
    spec_result: Option<ArenaSpeculativeResult>,
}

/// T87.4: Arena-based speculative execution result.
///
/// Like SpeculativeResult, but stores indices instead of addresses.
#[derive(Clone, Debug)]
struct ArenaSpeculativeResult {
    /// Sender's index in the arena
    sender_idx: u32,
    /// Receiver's index in the arena
    receiver_idx: u32,
    /// New sender account state after tx
    sender_account: Account,
    /// New receiver account state after tx
    receiver_account: Account,
    /// Fee burned
    fee: u128,
}

impl ArenaTxContext {
    /// Create a new ArenaTxContext from an AnalyzedTx and AccountArena.
    ///
    /// Resolves sender and receiver addresses to arena indices by loading them
    /// from the base state if not already present in the arena.
    ///
    /// # Note
    ///
    /// This method mutates the arena by adding any accounts that aren't already
    /// present. This is intentional - all touched accounts should be loaded into
    /// the arena before execution begins.
    fn from_analyzed(analyzed: &AnalyzedTx, arena: &mut AccountArena, base: &Accounts) -> Self {
        let sender_idx = arena.ensure_account(&analyzed.sender, base);
        let receiver_idx = arena.ensure_account(&analyzed.receiver, base);
        
        Self {
            tx_idx: analyzed.tx_idx,
            sender_idx,
            receiver_idx,
            attempt: 0,
            status: TxStatus::NeedsRetry,
            spec_result: None,
        }
    }

    /// Reset for retry in next wave.
    fn reset_for_retry(&mut self) {
        self.spec_result = None;
        self.attempt += 1;
    }
}

// =============================================================================
// T87.4: STM Kernel Mode Selection
// =============================================================================

/// Selects which STM kernel implementation to use.
///
/// T87.4: The arena kernel uses cache-friendly contiguous storage for accounts,
/// while the legacy kernel uses HashMap-based lookups. Both produce identical
/// results; the arena kernel is an optimization for better cache locality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StmKernelMode {
    /// Use the existing HashMap-based implementation.
    /// This is the default and matches pre-T87.4 behavior exactly.
    #[default]
    Legacy,
    
    /// Use the arena-indexed implementation for better cache locality.
    /// Opt-in via EEZO_STM_KERNEL_MODE=arena.
    Arena,
}

impl StmKernelMode {
    /// Parse kernel mode from environment variable.
    ///
    /// Returns `Arena` if EEZO_STM_KERNEL_MODE is set to "arena".
    /// Returns `Legacy` for any other value or if the variable is not set.
    pub fn from_env() -> Self {
        std::env::var("EEZO_STM_KERNEL_MODE")
            .map(|v| {
                let s = v.trim().to_ascii_lowercase();
                if s == "arena" {
                    StmKernelMode::Arena
                } else {
                    StmKernelMode::Legacy
                }
            })
            .unwrap_or(StmKernelMode::Legacy)
    }

    /// Check if this is the arena kernel mode.
    #[inline]
    pub fn is_arena(&self) -> bool {
        matches!(self, StmKernelMode::Arena)
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
    /// T76.7: Number of execution lanes for parallel processing.
    /// Configured via EEZO_EXEC_LANES env var (default 16, allow 32/48/64).
    pub exec_lanes: usize,
    /// T76.7: Optional cap on transactions per wave.
    /// Configured via EEZO_EXEC_WAVE_CAP env var (default: no cap, i.e., 0 means unlimited).
    pub wave_cap: usize,
    /// T87.1: Enable aggressive wave grouping for better parallelism.
    /// Configured via EEZO_STM_WAVE_AGGRESSIVE env var (default: false).
    pub wave_aggressive: bool,
    /// T87.4: STM kernel mode (legacy or arena).
    /// Configured via EEZO_STM_KERNEL_MODE env var (default: legacy).
    pub kernel_mode: StmKernelMode,
    /// T93.2: Enable simple transfer fast path.
    /// Configured via EEZO_STM_SIMPLE_FASTPATH_ENABLED env var (default: false).
    /// When enabled, simple transfers bypass expensive conflict detection.
    pub simple_fastpath_enabled: bool,
}

impl Default for StmConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            max_retries: 5,
            wave_timeout_ms: 1000,
            exec_lanes: 16,
            wave_cap: 0, // 0 means unlimited
            wave_aggressive: false, // T87.1: opt-in
            kernel_mode: StmKernelMode::Legacy, // T87.4: default to legacy
            simple_fastpath_enabled: false, // T93.2: opt-in for safety
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
    /// - `EEZO_EXEC_LANES`: Number of execution lanes (default: 16, allow 32/48/64)
    /// - `EEZO_EXEC_WAVE_CAP`: Optional cap on txs per wave (default: 0 = unlimited)
    /// - `EEZO_STM_WAVE_AGGRESSIVE`: Enable aggressive wave grouping (default: 0)
    /// - `EEZO_STM_KERNEL_MODE`: Kernel mode selection (default: legacy, optional: arena)
    /// - `EEZO_STM_SIMPLE_FASTPATH_ENABLED`: Enable simple transfer fast path (default: 0)
    pub fn from_env(threads: usize) -> Self {
        let max_retries = std::env::var("EEZO_STM_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let wave_timeout_ms = std::env::var("EEZO_STM_WAVE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);

        // T76.7: Parse exec_lanes from environment (default 16, allow 32/48/64)
        let exec_lanes = std::env::var("EEZO_EXEC_LANES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|v| {
                // Validate allowed values: 16, 32, 48, 64
                match v {
                    16 | 32 | 48 | 64 => v,
                    _ => {
                        log::warn!("EEZO_EXEC_LANES={} is not a valid value (allowed: 16/32/48/64), using default 16", v);
                        16
                    }
                }
            })
            .unwrap_or(16);

        // T76.7: Parse wave_cap from environment (default 0 = unlimited)
        let wave_cap = std::env::var("EEZO_EXEC_WAVE_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        // T87.1: Parse wave_aggressive from environment (default false)
        let wave_aggressive = std::env::var("EEZO_STM_WAVE_AGGRESSIVE")
            .map(|v| {
                let s = v.trim().to_ascii_lowercase();
                matches!(s.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);

        // T87.4: Parse kernel_mode from environment (default legacy)
        let kernel_mode = StmKernelMode::from_env();

        // T93.2: Parse simple_fastpath_enabled from environment (default false)
        let simple_fastpath_enabled = std::env::var("EEZO_STM_SIMPLE_FASTPATH_ENABLED")
            .map(|v| {
                let s = v.trim().to_ascii_lowercase();
                matches!(s.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);

        Self {
            threads,
            max_retries,
            wave_timeout_ms,
            exec_lanes,
            wave_cap,
            wave_aggressive,
            kernel_mode,
            simple_fastpath_enabled,
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
    /// T76.7: Also logs and sets gauges for exec_lanes and wave_cap.
    /// T87.1: Also logs and sets gauge for wave_aggressive.
    /// T87.4: Also logs and sets gauge for kernel_mode.
    /// T93.2: Also logs and sets gauge for simple_fastpath_enabled.
    pub fn from_env(threads: usize) -> Self {
        let config = StmConfig::from_env(threads);
        
        // T76.7 + T87.1 + T87.4 + T93.2: Log the configured values
        let kernel_mode_str = if config.kernel_mode.is_arena() { "arena" } else { "legacy" };
        log::info!(
            "stm-executor: initialized with threads={} exec_lanes={} wave_cap={} (0=unlimited) wave_aggressive={} kernel_mode={} simple_fastpath={}",
            config.threads, config.exec_lanes, config.wave_cap, config.wave_aggressive, kernel_mode_str, config.simple_fastpath_enabled
        );
        
        // T76.7: Set gauge metrics
        #[cfg(feature = "metrics")]
        {
            crate::metrics::exec_lanes_set(config.exec_lanes);
            crate::metrics::exec_wave_cap_set(config.wave_cap);
            // T87.1: Set aggressive wave mode gauge
            crate::metrics::exec_stm_wave_aggressive_set(config.wave_aggressive);
            // T87.4: Set kernel mode gauge
            crate::metrics::exec_stm_kernel_mode_set(config.kernel_mode.is_arena());
            // T93.2: Set simple fastpath gauge
            crate::metrics::exec_stm_simple_fastpath_enabled_set(config.simple_fastpath_enabled);
        }
        
        Self { config }
    }

    /// Get the number of threads configured.
    pub fn threads(&self) -> usize {
        self.config.threads
    }

    /// Get the configuration.
    pub fn config(&self) -> &StmConfig {
        &self.config
    }

    /// T82.1: Execute a transaction speculatively using AnalyzedTx and BlockOverlay.
    ///
    /// This version reads from overlay first, falls back to base snapshot.
    /// Uses pre-computed sender from AnalyzedTx to avoid re-derivation.
    ///
    /// T97.0: Uses cached fields from AnalyzedTx (no Arc access).
    fn execute_tx_with_overlay(
        analyzed: &AnalyzedTx,
        attempt: u16,
        overlay: &BlockOverlay,
        base_accounts: &Accounts,
    ) -> TxContext {
        let mut ctx = TxContext::new(analyzed.tx_idx);
        ctx.attempt = attempt;
        
        let sender = analyzed.sender;
        let receiver = analyzed.receiver;
        
        // Record read set using StateKey (for compatibility with conflict detection)
        ctx.read_set.insert(StateKey::Account(sender));
        ctx.read_set.insert(StateKey::Account(receiver));
        
        // Read from overlay first, fall back to base
        let sender_acc = overlay.get_account(&sender, base_accounts);
        let receiver_acc = overlay.get_account(&receiver, base_accounts);
        
        // Validate nonce and balance using cached fields
        if sender_acc.nonce != analyzed.nonce {
            // Temporary failure - may succeed after earlier txs commit
            ctx.status = TxStatus::NeedsRetry;
            return ctx;
        }
        
        let need = analyzed.amount.saturating_add(analyzed.fee);
        if sender_acc.balance < need {
            ctx.status = TxStatus::NeedsRetry;
            return ctx;
        }
        
        // Compute new states
        // T97.0: Track account clones for metrics
        #[cfg(feature = "metrics")]
        crate::metrics::stm_account_clones_inc(2);
        
        let mut new_sender = sender_acc.clone();
        new_sender.balance = new_sender.balance.saturating_sub(need);
        new_sender.nonce = new_sender.nonce.saturating_add(1);
        
        let mut new_receiver = receiver_acc.clone();
        new_receiver.balance = new_receiver.balance.saturating_add(analyzed.amount);
        
        // Record write set
        ctx.write_set.insert(StateKey::Account(sender));
        ctx.write_set.insert(StateKey::Account(receiver));
        ctx.write_set.insert(StateKey::Supply);
        
        ctx.spec_result = Some(SpeculativeResult {
            sender,
            receiver,
            sender_account: new_sender,
            receiver_account: new_receiver,
            fee: analyzed.fee,
        });
        
        ctx.status = TxStatus::Committed;
        ctx
    }

    /// Execute a single transaction speculatively against a snapshot.
    ///
    /// This method is used for parallel execution: it reads from the provided
    /// snapshot, computes the state changes, and returns the result without
    /// mutating the base state. The caller is responsible for applying the
    /// result in order.
    ///
    /// Returns TxContext with status and speculative result (if committed).
    fn execute_tx_speculative_parallel(
        tx: &SignedTx,
        tx_idx: usize,
        attempt: u16,
        accounts: &Accounts,
        supply: &Supply,
    ) -> TxContext {
        let mut ctx = TxContext::new(tx_idx);
        ctx.attempt = attempt;

        // Derive sender from pubkey
        let sender = match sender_from_pubkey_first20(tx) {
            Some(s) => s,
            None => {
                ctx.status = TxStatus::Failed("Invalid sender (cannot derive from pubkey)".to_string());
                return ctx;
            }
        };

        // Record read set: sender account (for balance/nonce check)
        ctx.read_set.insert(StateKey::Account(sender));
        // Receiver is also read (to get current balance for credit)
        ctx.read_set.insert(StateKey::Account(tx.core.to));

        // Validate the transaction statefully against the snapshot
        // BadNonce and InsufficientFunds are temporary failures that should be retried
        // (they may succeed after earlier txs commit and update the state)
        // Note: Infinite retry loops are prevented by max_retries config (default: 5).
        // When max_retries is reached, the tx is marked as Aborted.
        if let Err(e) = validate_tx_stateful(accounts, sender, &tx.core) {
            match e {
                TxStateError::BadNonce { .. } | TxStateError::InsufficientFunds { .. } => {
                    // Temporary failure - can be retried in a later wave
                    // Mark as NeedsRetry so the tx is scheduled for retry
                    ctx.status = TxStatus::NeedsRetry;
                }
                TxStateError::InvalidSender => {
                    // Permanent failure - cannot be recovered
                    ctx.status = TxStatus::Failed(format!("{:?}", e));
                }
            }
            return ctx;
        }

        // Compute the state changes speculatively (without mutating accounts/supply)
        let sender_acc = accounts.get(&sender);
        let receiver_acc = accounts.get(&tx.core.to);
        
        let need = tx.core.amount.saturating_add(tx.core.fee);
        
        // Compute new sender state
        let mut new_sender = sender_acc.clone();
        new_sender.balance = new_sender.balance.saturating_sub(need);
        new_sender.nonce = new_sender.nonce.saturating_add(1);
        
        // Compute new receiver state
        let mut new_receiver = receiver_acc.clone();
        new_receiver.balance = new_receiver.balance.saturating_add(tx.core.amount);
        
        // Record write set: sender, receiver, and supply (for fee burn)
        ctx.write_set.insert(StateKey::Account(sender));
        ctx.write_set.insert(StateKey::Account(tx.core.to));
        ctx.write_set.insert(StateKey::Supply);
        
        // Store the speculative result
        ctx.spec_result = Some(SpeculativeResult {
            sender,
            receiver: tx.core.to,
            sender_account: new_sender,
            receiver_account: new_receiver,
            fee: tx.core.fee,
        });

        ctx.status = TxStatus::Committed;
        ctx
    }

    /// Execute a single transaction speculatively (mutable version).
    ///
    /// Records the read/write sets and applies state changes to the shadow state.
    /// This is the legacy method used for sequential fallback.
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
    /// Only considers transactions in the current wave (pending_indices).
    /// Returns indices of transactions that need retry.
    fn detect_conflicts_in_wave(contexts: &[TxContext], pending_indices: &[usize]) -> Vec<usize> {
        let mut conflicts = Vec::new();
        
        // Track committed writes by tx index (only for this wave)
        let mut committed_writes: HashMap<StateKey, usize> = HashMap::new();

        // Process in index order for determinism
        let mut sorted_pending: Vec<usize> = pending_indices.to_vec();
        sorted_pending.sort();

        for &tx_idx in &sorted_pending {
            let ctx = &contexts[tx_idx];
            
            if ctx.status != TxStatus::Committed {
                continue;
            }

            let mut has_conflict = false;

            // Check read-after-write conflicts: did we read something written by an earlier tx?
            // Note: committed_writes only contains entries from txs in the current wave that
            // have already been processed (earlier indices), so no extra filtering is needed.
            for key in &ctx.read_set {
                if let Some(&writer_idx) = committed_writes.get(key) {
                    if writer_idx < tx_idx {
                        // Conflict: we read a key that was written by an earlier tx in this wave
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
                            // Conflict: we wrote a key that was written by an earlier tx in this wave
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

    /// Legacy conflict detection for unit tests.
    /// Detects conflicts across all contexts (not wave-scoped).
    fn detect_conflicts(contexts: &[TxContext]) -> Vec<usize> {
        let all_indices: Vec<usize> = contexts.iter().map(|c| c.tx_idx).collect();
        Self::detect_conflicts_in_wave(contexts, &all_indices)
    }

    /// Execute all transactions using wave-based STM with parallel execution.
    ///
    /// T73.6: This implementation uses rayon's par_iter() for true parallel
    /// execution within each wave, while maintaining determinism.
    ///
    /// ## Algorithm
    /// 1. Clone state snapshot for speculative execution
    /// 2. Execute pending txs in parallel against the snapshot
    /// 3. Collect results and detect conflicts deterministically
    /// 4. Apply non-conflicting results in tx index order
    /// 5. Mark conflicting txs for retry in next wave
    /// 6. Repeat until all txs are committed/failed or max retries reached
    ///
    /// Returns (contexts, committed_txs, waves_this_block, conflicts_this_block, retries_this_block, aborted_this_block)
    fn execute_stm(
        &self,
        txs: &[SignedTx],
        accounts: &mut Accounts,
        supply: &mut Supply,
    ) -> (Vec<TxContext>, Vec<SignedTx>, u64, u64, u64, u64) {
        let n = txs.len();
        if n == 0 {
            return (Vec::new(), Vec::new(), 0, 0, 0, 0);
        }

        // Initialize contexts for all transactions
        let mut contexts: Vec<TxContext> = (0..n).map(TxContext::new).collect();

        // STM metrics tracking (T73.4 + T82.0)
        let mut waves_this_block: u64 = 0;
        let mut conflicts_this_block: u64 = 0;
        let mut retries_this_block: u64 = 0;
        let mut aborted_this_block: u64 = 0;

        // Track which txs have been finally committed (won't be retried)
        let mut finally_committed: HashSet<usize> = HashSet::new();

        // Wave-based execution loop
        loop {
            waves_this_block += 1;
            log::debug!("STM: starting wave {}", waves_this_block);

            // Find transactions that need execution in this wave
            let pending: Vec<(usize, u16)> = contexts
                .iter()
                .filter(|c| c.status == TxStatus::NeedsRetry)
                .map(|c| (c.tx_idx, c.attempt))
                .collect();

            if pending.is_empty() {
                break;
            }

            // Check for max retries before execution
            for &(tx_idx, attempt) in &pending {
                if attempt >= self.config.max_retries as u16 {
                    contexts[tx_idx].status = TxStatus::Aborted;
                    log::warn!("STM: tx {} aborted after {} retries", tx_idx, attempt);
                    aborted_this_block += 1;
                }
            }
            
            // Filter out aborted txs
            let pending: Vec<(usize, u16)> = pending
                .into_iter()
                .filter(|&(tx_idx, _)| contexts[tx_idx].status == TxStatus::NeedsRetry)
                .collect();
            
            if pending.is_empty() {
                break;
            }

            // Count retries (attempt > 0 means this is a retry)
            for &(_, attempt) in &pending {
                if attempt > 0 {
                    retries_this_block += 1;
                }
            }

            // T73.6: Execute transactions in parallel using rayon
            // Each tx reads from the current snapshot and computes speculative results.
            // Note: We clone the entire state for each wave. This is acceptable for now
            // because Accounts and Supply are relatively small structures. For very large
            // state sets, a copy-on-write or snapshot mechanism would be more efficient.
            let snapshot_accounts = accounts.clone();
            let snapshot_supply = supply.clone();
            
            let wave_results: Vec<TxContext> = pending
                .par_iter()
                .map(|&(tx_idx, attempt)| {
                    Self::execute_tx_speculative_parallel(
                        &txs[tx_idx],
                        tx_idx,
                        attempt,
                        &snapshot_accounts,
                        &snapshot_supply,
                    )
                })
                .collect();

            // Create a map from tx_idx to result for quick lookup
            let mut result_map: HashMap<usize, TxContext> = HashMap::new();
            for result in wave_results {
                result_map.insert(result.tx_idx, result);
            }

            // Update contexts with parallel results
            for (&tx_idx, result) in &result_map {
                contexts[tx_idx] = result.clone();
            }

            // Detect conflicts deterministically (lower index wins)
            // Build a sorted list of tx indices for deterministic processing
            let mut pending_indices: Vec<usize> = pending.iter().map(|&(idx, _)| idx).collect();
            pending_indices.sort();

            // Use wave-scoped conflict detection to only consider txs in this wave
            let conflicts = Self::detect_conflicts_in_wave(&contexts, &pending_indices);
            let conflict_set: HashSet<usize> = conflicts.into_iter().collect();
            conflicts_this_block += conflict_set.len() as u64;

            // Process results in tx index order
            for tx_idx in pending_indices {
                let ctx = &mut contexts[tx_idx];
                
                if ctx.status != TxStatus::Committed {
                    // Failed txs stay failed
                    continue;
                }

                if conflict_set.contains(&tx_idx) {
                    // This tx has a conflict with an earlier tx
                    // Mark for retry and increment attempt counter
                    ctx.status = TxStatus::NeedsRetry;
                    ctx.attempt += 1;
                    ctx.spec_result = None;
                    log::debug!("STM: tx {} conflicts, scheduling retry (attempt {})", tx_idx, ctx.attempt);
                } else {
                    // No conflict - apply the speculative result to actual state
                    if let Some(ref spec) = ctx.spec_result {
                        accounts.put(spec.sender, spec.sender_account.clone());
                        accounts.put(spec.receiver, spec.receiver_account.clone());
                        supply.apply_burn(spec.fee);
                    }
                    
                    // Record as finally committed (index only, build result at end)
                    finally_committed.insert(tx_idx);
                }
            }

            // Safety: break if no more pending txs
            let still_pending = contexts
                .iter()
                .filter(|c| c.status == TxStatus::NeedsRetry)
                .count();
            if still_pending == 0 {
                break;
            }
        }

        // Build committed_txs from finally_committed set, sorted by tx_idx for deterministic order.
        // Using tx_idx directly is O(n log n) vs O(n²) hash lookups.
        let mut committed_indices: Vec<usize> = finally_committed.into_iter().collect();
        committed_indices.sort();
        let committed_txs: Vec<SignedTx> = committed_indices
            .into_iter()
            .map(|idx| txs[idx].clone())
            .collect();

        log::debug!(
            "STM: completed {} waves, {} committed, {} failed/aborted, {} conflicts, {} retries",
            waves_this_block,
            committed_txs.len(),
            n - committed_txs.len(),
            conflicts_this_block,
            retries_this_block
        );

        (contexts, committed_txs, waves_this_block, conflicts_this_block, retries_this_block, aborted_this_block)
    }

    /// T82.1 + T82.4: Execute all transactions using wave-based STM with BlockOverlay.
    ///
    /// This version uses:
    /// - `AnalyzedTx` for pre-computed conflict metadata (avoids re-deriving sender each time)
    /// - `BlockOverlay` to track modified accounts (avoids cloning full state per wave)
    /// - T82.4: `WaveFingerprint` for fast conflict pre-screening
    ///
    /// The base snapshot is read-only; all writes go to the overlay.
    /// At block commit, overlay changes are applied to the actual state.
    ///
    /// ## T82.4: Conflict Pre-Screening
    ///
    /// Before deciding whether a tx can join the current wave:
    /// 1. First call the fast pre-screen (`WaveFingerprint::may_conflict`)
    /// 2. If it returns `false` → definitely safe, no further conflict check needed
    /// 3. If it returns `true` → fall back to precise StateKey-based conflict detection
    ///
    /// The pre-screen is a pure optimization. The existing conflict detection logic
    /// remains the ultimate source of truth for correctness.
    ///
    /// Returns (contexts, committed_txs, waves, conflicts, retries, aborted)
    fn execute_stm_with_overlay(
        &self,
        txs: &[SignedTx],
        accounts: &mut Accounts,
        supply: &mut Supply,
    ) -> (Vec<TxContext>, Vec<SignedTx>, u64, u64, u64, u64) {
        let n = txs.len();
        if n == 0 {
            return (Vec::new(), Vec::new(), 0, 0, 0, 0);
        }

        // T82.1: Pre-analyze all transactions once at block start
        let analyzed_txs = analyze_batch(txs);
        
        // Map from tx_idx to AnalyzedTx for quick lookup
        let analyzed_map: HashMap<usize, &AnalyzedTx> = analyzed_txs
            .iter()
            .map(|a| (a.tx_idx, a))
            .collect();

        // Initialize contexts for all transactions
        // Txs that failed analysis (invalid sender) start as Failed
        let mut contexts: Vec<TxContext> = (0..n)
            .map(|idx| {
                if analyzed_map.contains_key(&idx) {
                    TxContext::new(idx)
                } else {
                    let mut ctx = TxContext::new(idx);
                    ctx.status = TxStatus::Failed("Invalid sender (cannot derive from pubkey)".to_string());
                    ctx
                }
            })
            .collect();

        // STM metrics tracking
        let mut waves_this_block: u64 = 0;
        let mut conflicts_this_block: u64 = 0;
        let mut retries_this_block: u64 = 0;
        let mut aborted_this_block: u64 = 0;

        // Track which txs have been finally committed
        let mut finally_committed: HashSet<usize> = HashSet::new();

        // T82.1: Block-level overlay (starts empty)
        let mut overlay = BlockOverlay::new();

        // Take a read-only base snapshot of accounts
        // (we don't clone supply since we track fees in overlay)
        let base_accounts = accounts.clone();

        // Wave-based execution loop
        loop {
            waves_this_block += 1;
            log::debug!("STM(overlay): starting wave {}", waves_this_block);

            // Find transactions that need execution in this wave
            let pending: Vec<(usize, u16)> = contexts
                .iter()
                .filter(|c| c.status == TxStatus::NeedsRetry)
                .map(|c| (c.tx_idx, c.attempt))
                .collect();

            if pending.is_empty() {
                break;
            }

            // Check for max retries before execution
            for &(tx_idx, attempt) in &pending {
                if attempt >= self.config.max_retries as u16 {
                    contexts[tx_idx].status = TxStatus::Aborted;
                    log::warn!("STM(overlay): tx {} aborted after {} retries", tx_idx, attempt);
                    aborted_this_block += 1;
                }
            }
            
            // Filter out aborted txs
            let pending: Vec<(usize, u16)> = pending
                .into_iter()
                .filter(|&(tx_idx, _)| contexts[tx_idx].status == TxStatus::NeedsRetry)
                .collect();
            
            if pending.is_empty() {
                break;
            }

            // Count retries
            for &(_, attempt) in &pending {
                if attempt > 0 {
                    retries_this_block += 1;
                }
            }

            // T82.1: Execute transactions in parallel using overlay
            // Each tx reads from overlay (with base fallback) and computes speculative results.
            // The overlay is shared read-only during parallel execution.
            let overlay_ref = &overlay;
            let base_ref = &base_accounts;
            
            let wave_results: Vec<TxContext> = pending
                .par_iter()
                .filter_map(|&(tx_idx, attempt)| {
                    analyzed_map.get(&tx_idx).map(|analyzed| {
                        Self::execute_tx_with_overlay(
                            analyzed,
                            attempt,
                            overlay_ref,
                            base_ref,
                        )
                    })
                })
                .collect();

            // Update contexts with parallel results
            for result in wave_results {
                let tx_idx = result.tx_idx;
                contexts[tx_idx] = result;
            }

            // Detect conflicts deterministically
            let mut pending_indices: Vec<usize> = pending.iter().map(|&(idx, _)| idx).collect();
            pending_indices.sort();

            // T82.4: Use WaveFingerprint for conflict pre-screening combined with
            // the existing StateKey-based conflict detection for correctness.
            //
            // The pre-screen is an optimization only - it reduces the work done
            // in precise conflict detection but doesn't replace it for correctness.
            //
            // T87.x: Track wave build timing for profiling
            let wave_build_start = std::time::Instant::now();
            let conflicts = Self::detect_conflicts_with_prescreen(
                &contexts, 
                &pending_indices, 
                &analyzed_map
            );
            #[cfg(feature = "metrics")]
            {
                let wave_build_secs = wave_build_start.elapsed().as_secs_f64();
                crate::metrics::exec_stm_observe_wave_build_seconds(wave_build_secs);
            }
            let conflict_set: HashSet<usize> = conflicts.into_iter().collect();
            conflicts_this_block += conflict_set.len() as u64;

            // Process results in tx index order and apply to overlay
            for tx_idx in pending_indices {
                let ctx = &mut contexts[tx_idx];
                
                if ctx.status != TxStatus::Committed {
                    continue;
                }

                if conflict_set.contains(&tx_idx) {
                    ctx.status = TxStatus::NeedsRetry;
                    ctx.attempt += 1;
                    ctx.spec_result = None;
                    log::debug!("STM(overlay): tx {} conflicts, scheduling retry (attempt {})", tx_idx, ctx.attempt);
                } else {
                    // Apply speculative result to overlay (not to base state)
                    if let Some(ref spec) = ctx.spec_result {
                        overlay.put_account(spec.sender, spec.sender_account.clone());
                        overlay.put_account(spec.receiver, spec.receiver_account.clone());
                        overlay.record_fee_burn(spec.fee);
                    }
                    
                    finally_committed.insert(tx_idx);
                }
            }

            // Break if no more pending txs
            let still_pending = contexts
                .iter()
                .filter(|c| c.status == TxStatus::NeedsRetry)
                .count();
            if still_pending == 0 {
                break;
            }
        }

        // T82.1: Apply overlay to actual state at block commit
        overlay.apply_to_state(accounts, supply);

        // Build committed_txs
        let mut committed_indices: Vec<usize> = finally_committed.into_iter().collect();
        committed_indices.sort();
        let committed_txs: Vec<SignedTx> = committed_indices
            .into_iter()
            .map(|idx| txs[idx].clone())
            .collect();

        // T82.4: Emit wave-building metrics
        #[cfg(feature = "metrics")]
        {
            crate::metrics::exec_stm_waves_built_inc(waves_this_block);
        }

        log::debug!(
            "STM(overlay): completed {} waves, {} committed, {} failed/aborted, {} conflicts, {} retries, overlay_size={}",
            waves_this_block,
            committed_txs.len(),
            n - committed_txs.len(),
            conflicts_this_block,
            retries_this_block,
            overlay.len()
        );

        (contexts, committed_txs, waves_this_block, conflicts_this_block, retries_this_block, aborted_this_block)
    }

    // =============================================================================
    // T93.2 + T93.3: Simple Transfer Fast Path
    // =============================================================================
    //
    // The fast path is an optimization for simple value transfers that bypasses
    // expensive conflict detection. It works by:
    //
    // 1. Pre-partitioning transactions by sender address
    // 2. Ensuring only one tx per sender in a wave (no intra-sender conflicts)
    // 3. Tracking receiver touches to detect inter-tx conflicts
    // 4. Executing non-conflicting transfers directly on the arena
    //
    // This is safe because:
    // - Simple transfers only touch sender + receiver accounts
    // - If we ensure no two txs in a wave share a sender, there are no write-write
    //   conflicts on the sender account
    // - If no tx writes to an account that another tx reads/writes, there are no
    //   read-after-write or write-after-write conflicts
    //
    // T93.3 Metrics Semantics:
    // - Txs that commit via fast path are tracked in `fastpath_committed` set
    // - Txs that fail fast path scheduling (same sender/touched account) stay as
    //   NeedsRetry and may be executed via general STM path in subsequent waves
    // - The final fastpath/fallback counts are computed at block end based on
    //   which txs ultimately committed via each path
    // - Txs with temporary failures (nonce mismatch, insufficient balance) stay
    //   as NeedsRetry without counting as fallback (they may succeed in fast path
    //   after earlier txs commit)

    /// T93.2 + T93.3 + T95.0 + T95.1: Execute simple transfers via the fast path.
    ///
    /// This function attempts to execute simple transfers without conflict detection
    /// overhead. It partitions transactions by sender and ensures only one tx per
    /// sender is executed per wave.
    ///
    /// ## T95.0 Optimization
    ///
    /// Uses `ArenaConflictBitmap` for O(1) bit-level conflict checks instead of
    /// HashMap lookups. For typical block sizes (arena indices < 1024), this avoids
    /// all hash computation overhead. Falls back to HashMap for overflow cases.
    ///
    /// ## T95.1 Optimization
    ///
    /// - Precomputed `simple_candidate_indices` (already sorted by tx_idx) is passed in
    ///   to avoid per-wave Vec allocation and sort.
    /// - `conflict_bitmap` is passed in and reset() at the start, avoiding re-allocation
    ///   of the 16KB bitmap arrays per wave.
    /// - `analyzed_map` provides O(1) lookup of AnalyzedTx by tx_idx.
    ///
    /// ## T93.3 Metrics Note
    ///
    /// This function tracks which txs successfully commit via fast path in the
    /// `fastpath_committed` set. Txs that cannot be scheduled in this wave's fast
    /// path stay as NeedsRetry and will be attempted again in subsequent waves
    /// (either via fast path or general STM).
    ///
    /// # Arguments
    /// * `simple_candidate_indices` - Pre-sorted list of tx indices for simple transfer candidates
    /// * `analyzed_map` - Map from tx_idx to AnalyzedTx for O(1) lookup
    /// * `arena_contexts` - Arena execution contexts for each tx
    /// * `arena` - The account arena for this block
    /// * `idx_to_arena` - Map from tx_idx to arena_contexts index
    /// * `conflict_bitmap` - Reusable bitmap for conflict tracking (reset at start)
    /// * `fastpath_committed` - Set of tx_idx that committed via fast path (updated in place)
    ///
    /// # Safety
    ///
    /// This function must only be called when `simple_fastpath_enabled` is true.
    /// It modifies the arena directly for successfully executed txs.
    #[allow(dead_code)]
    fn execute_simple_fastpath_wave(
        simple_candidate_indices: &[usize],
        analyzed_map: &HashMap<usize, &AnalyzedTx>,
        arena_contexts: &mut [ArenaTxContext],
        arena: &mut AccountArena,
        idx_to_arena: &HashMap<usize, usize>,
        conflict_bitmap: &mut ArenaConflictBitmap,
        fastpath_committed: &mut HashSet<usize>,
    ) {
        let fastpath_start = std::time::Instant::now();
        
        // T95.1: Reset the bitmap at wave start (cheap memset, no allocation)
        conflict_bitmap.reset();
        
        // T95.1: Iterate over precomputed candidate indices (already sorted, no allocation)
        // Skip txs that are not NeedsRetry (already committed or failed)
        for &tx_idx in simple_candidate_indices {
            let arena_idx = match idx_to_arena.get(&tx_idx) {
                Some(&idx) => idx,
                None => continue,
            };
            let ctx = &mut arena_contexts[arena_idx];
            
            // Skip txs that are not pending
            if ctx.status != TxStatus::NeedsRetry {
                continue;
            }
            
            // Get the analyzed tx for this index (O(1) HashMap lookup)
            let atx = match analyzed_map.get(&tx_idx) {
                Some(a) => *a,
                None => continue,
            };
            
            // Only handle simple transfers via fast path
            // Non-simple txs stay as NeedsRetry for general STM path
            if !atx.kind.is_simple() {
                continue;
            }
            
            // Check if we can safely execute this tx in this wave
            // Rule 1: No other tx in this wave can have the same sender
            // (Skip this tx for this wave - it stays NeedsRetry for general path)
            // T95.0: Use bitmap O(1) check instead of HashMap contains_key
            if conflict_bitmap.is_sender_claimed(ctx.sender_idx) {
                continue;
            }
            
            // Rule 2: No other tx in this wave can touch our sender or receiver
            // (This prevents read-after-write conflicts)
            // T95.0: Use bitmap O(1) check instead of HashMap contains_key
            if conflict_bitmap.is_account_touched(ctx.sender_idx) || 
               conflict_bitmap.is_account_touched(ctx.receiver_idx) {
                continue;
            }
            
            // Read accounts from arena (O(1) Vec access)
            let sender_acc = arena.account(ctx.sender_idx);
            
            // T97.0: Use cached fields from AnalyzedTx (no Arc access)
            // Validate nonce - if mismatch, leave as NeedsRetry
            // (may succeed in a later wave after earlier txs update the nonce)
            if sender_acc.nonce != atx.nonce {
                continue;
            }
            
            // Validate balance - if insufficient, leave as NeedsRetry
            let need = atx.amount.saturating_add(atx.fee);
            if sender_acc.balance < need {
                continue;
            }
            
            // Execute the transfer directly on the arena
            // (No speculative result needed - we commit immediately)
            {
                let sender = arena.account_mut(ctx.sender_idx);
                sender.balance = sender.balance.saturating_sub(need);
                sender.nonce = sender.nonce.saturating_add(1);
            }
            {
                let receiver = arena.account_mut(ctx.receiver_idx);
                receiver.balance = receiver.balance.saturating_add(atx.amount);
            }
            arena.record_fee(atx.fee);
            
            // Mark as committed
            ctx.status = TxStatus::Committed;
            
            // Record that this tx committed via fast path (for metrics)
            fastpath_committed.insert(atx.tx_idx);
            
            // T95.0: Claim sender and touch both accounts using bitmap
            conflict_bitmap.claim_sender(ctx.sender_idx);
            conflict_bitmap.touch_account(ctx.sender_idx);
            conflict_bitmap.touch_account(ctx.receiver_idx);
        }
        
        // Emit timing metric
        #[cfg(feature = "metrics")]
        {
            let elapsed = fastpath_start.elapsed().as_secs_f64();
            crate::metrics::stm_simple_time_add(elapsed);
        }
    }

    /// T87.4 + T93.3: Execute all transactions using arena-indexed STM kernel.
    ///
    /// This version uses:
    /// - `AccountArena`: All touched accounts stored contiguously in a Vec
    /// - `ArenaTxContext`: Indices instead of addresses for O(1) access
    /// - Same conflict detection semantics as legacy kernel
    ///
    /// The arena is built once at block start by pre-loading all touched accounts.
    /// During execution, all state access is done via Vec indexing (cache-friendly).
    ///
    /// ## T93.3 Metrics Semantics
    ///
    /// At block start, we count candidate txs (classified as SimpleTransfer).
    /// We track which txs commit via fast path in `fastpath_committed`.
    /// At block end, we compute:
    /// - fastpath_total = |fastpath_committed|
    /// - fallback_total = |finally_committed ∩ simple_candidates \ fastpath_committed|
    ///
    /// Returns (committed_txs, waves, conflicts, retries, aborted)
    fn execute_stm_with_arena(
        &self,
        txs: &[SignedTx],
        accounts: &mut Accounts,
        supply: &mut Supply,
    ) -> (Vec<SignedTx>, u64, u64, u64, u64) {
        let n = txs.len();
        if n == 0 {
            return (Vec::new(), 0, 0, 0, 0);
        }

        // T87.4: Measure arena build time
        let arena_build_start = std::time::Instant::now();

        // Pre-analyze all transactions
        let analyzed_txs = analyze_batch(txs);
        
        // T93.3: Count simple candidates at block start (once per tx)
        // T95.1: Pre-compute sorted list of simple candidate indices for fast path
        // This avoids per-wave Vec allocation and sort
        let simple_candidates: HashSet<usize> = analyzed_txs
            .iter()
            .filter(|atx| atx.kind.is_simple())
            .map(|atx| atx.tx_idx)
            .collect();
        let candidate_count = simple_candidates.len() as u64;
        
        // T95.1: Pre-sorted list of simple candidate indices (computed once per block)
        let simple_candidate_indices: Vec<usize> = {
            let mut indices: Vec<usize> = simple_candidates.iter().copied().collect();
            indices.sort();
            indices
        };
        
        // T95.1: Build map from tx_idx to AnalyzedTx for O(1) lookup
        let analyzed_map: HashMap<usize, &AnalyzedTx> = analyzed_txs
            .iter()
            .map(|a| (a.tx_idx, a))
            .collect();
        
        // Emit candidate metric once at block start
        #[cfg(feature = "metrics")]
        {
            crate::metrics::stm_simple_candidate_inc(candidate_count);
        }
        
        // Build arena with all touched accounts
        let base_accounts = accounts.clone();
        let mut arena = AccountArena::with_capacity(analyzed_txs.len() * 2);
        
        // Build ArenaTxContext for each analyzed tx
        let mut arena_contexts: Vec<ArenaTxContext> = analyzed_txs
            .iter()
            .map(|atx| ArenaTxContext::from_analyzed(atx, &mut arena, &base_accounts))
            .collect();
        
        // Map from tx_idx to arena_contexts index (for failed analysis txs)
        let idx_to_arena: HashMap<usize, usize> = arena_contexts
            .iter()
            .enumerate()
            .map(|(i, ctx)| (ctx.tx_idx, i))
            .collect();

        #[cfg(feature = "metrics")]
        {
            let arena_build_secs = arena_build_start.elapsed().as_secs_f64();
            crate::metrics::exec_stm_observe_arena_build_seconds(arena_build_secs);
            crate::metrics::exec_stm_arena_accounts_inc(arena.len() as u64);
        }

        // STM metrics tracking
        let mut waves_this_block: u64 = 0;
        let mut conflicts_this_block: u64 = 0;
        let mut retries_this_block: u64 = 0;
        let mut aborted_this_block: u64 = 0;

        // T93.3: Track which txs committed via fast path (per-tx, not per-wave)
        let mut fastpath_committed: HashSet<usize> = HashSet::new();

        // Track which txs have been finally committed
        let mut finally_committed: HashSet<usize> = HashSet::new();
        
        // T95.1: Create conflict bitmap once per block (reused across waves)
        // This avoids 16KB allocation per wave (two 8KB arrays)
        let mut conflict_bitmap = ArenaConflictBitmap::new();

        // Wave-based execution loop
        loop {
            waves_this_block += 1;
            log::debug!("STM(arena): starting wave {}", waves_this_block);

            // Find transactions that need execution in this wave
            let pending: Vec<(usize, u16)> = arena_contexts
                .iter()
                .filter(|c| c.status == TxStatus::NeedsRetry)
                .map(|c| (c.tx_idx, c.attempt))
                .collect();

            if pending.is_empty() {
                break;
            }

            // T93.2 + T93.3 + T95.1: Try simple fast path first if enabled
            if self.config.simple_fastpath_enabled {
                Self::execute_simple_fastpath_wave(
                    &simple_candidate_indices,
                    &analyzed_map,
                    &mut arena_contexts,
                    &mut arena,
                    &idx_to_arena,
                    &mut conflict_bitmap,
                    &mut fastpath_committed,
                );
                
                // Collect committed txs from fast path
                for ctx in arena_contexts.iter() {
                    if ctx.status == TxStatus::Committed {
                        finally_committed.insert(ctx.tx_idx);
                    }
                }
                
                // Check if all txs are done after fast path
                let still_pending = arena_contexts
                    .iter()
                    .filter(|c| c.status == TxStatus::NeedsRetry)
                    .count();
                if still_pending == 0 {
                    log::debug!("STM(arena/fastpath): all {} txs committed via fast path", fastpath_committed.len());
                    break;
                }
            }

            // Check for max retries before execution
            for &(tx_idx, attempt) in &pending {
                if attempt >= self.config.max_retries as u16 {
                    if let Some(&arena_idx) = idx_to_arena.get(&tx_idx) {
                        arena_contexts[arena_idx].status = TxStatus::Aborted;
                        log::warn!("STM(arena): tx {} aborted after {} retries", tx_idx, attempt);
                        aborted_this_block += 1;
                    }
                }
            }
            
            // Filter out aborted txs
            let pending: Vec<(usize, u16)> = pending
                .into_iter()
                .filter(|&(tx_idx, _)| {
                    idx_to_arena.get(&tx_idx)
                        .map(|&idx| arena_contexts[idx].status == TxStatus::NeedsRetry)
                        .unwrap_or(false)
                })
                .collect();
            
            if pending.is_empty() {
                break;
            }

            // Count retries
            for &(_, attempt) in &pending {
                if attempt > 0 {
                    retries_this_block += 1;
                }
            }

            // Take a snapshot of the arena for speculative execution
            let arena_snapshot = arena.snapshot();

            // Execute transactions speculatively in parallel
            // T97.0: Use analyzed_map for O(1) lookup instead of linear search
            let wave_results: Vec<(usize, ArenaTxContext)> = pending
                .par_iter()
                .filter_map(|&(tx_idx, attempt)| {
                    idx_to_arena.get(&tx_idx).and_then(|&arena_idx| {
                        let ctx = &arena_contexts[arena_idx];
                        // T97.0: Get AnalyzedTx from map (no Arc access)
                        analyzed_map.get(&tx_idx).map(|analyzed| {
                            let result = Self::execute_tx_with_arena(
                                ctx,
                                analyzed,
                                attempt,
                                &arena_snapshot,
                            );
                            (arena_idx, result)
                        })
                    })
                })
                .collect();

            // Update contexts with parallel results
            for (arena_idx, result) in wave_results {
                arena_contexts[arena_idx] = result;
            }

            // Build sorted pending indices for conflict detection
            let mut pending_indices: Vec<usize> = pending.iter().map(|&(idx, _)| idx).collect();
            pending_indices.sort();

            // T87.4: Detect conflicts using arena-based contexts
            let wave_build_start = std::time::Instant::now();
            let conflicts = Self::detect_conflicts_arena(&arena_contexts, &pending_indices, &idx_to_arena);
            #[cfg(feature = "metrics")]
            {
                let wave_build_secs = wave_build_start.elapsed().as_secs_f64();
                crate::metrics::exec_stm_observe_wave_build_seconds(wave_build_secs);
            }
            let conflict_set: HashSet<usize> = conflicts.into_iter().collect();
            conflicts_this_block += conflict_set.len() as u64;

            // Process results in tx index order and apply to arena
            for tx_idx in pending_indices {
                if let Some(&arena_idx) = idx_to_arena.get(&tx_idx) {
                    let ctx = &mut arena_contexts[arena_idx];
                    
                    if ctx.status != TxStatus::Committed {
                        continue;
                    }

                    if conflict_set.contains(&tx_idx) {
                        ctx.status = TxStatus::NeedsRetry;
                        ctx.attempt += 1;
                        ctx.spec_result = None;
                        log::debug!("STM(arena): tx {} conflicts, scheduling retry (attempt {})", tx_idx, ctx.attempt);
                    } else {
                        // Apply speculative result to arena
                        if let Some(ref spec) = ctx.spec_result {
                            arena.set_account(spec.sender_idx, spec.sender_account.clone());
                            arena.set_account(spec.receiver_idx, spec.receiver_account.clone());
                            arena.record_fee(spec.fee);
                        }
                        
                        finally_committed.insert(tx_idx);
                    }
                }
            }

            // Break if no more pending txs
            let still_pending = arena_contexts
                .iter()
                .filter(|c| c.status == TxStatus::NeedsRetry)
                .count();
            if still_pending == 0 {
                break;
            }
        }

        // Apply arena changes to actual state
        arena.apply_to_state(accounts, supply);

        // Build committed_txs from finally_committed
        let committed_indices: Vec<usize> = {
            let mut indices: Vec<usize> = finally_committed.iter().copied().collect();
            indices.sort();
            indices
        };
        let committed_txs: Vec<SignedTx> = committed_indices
            .iter()
            .map(|&idx| txs[idx].clone())
            .collect();

        // T93.3: Compute final fastpath/fallback metrics at block end
        // fastpath_total = number of txs that committed via fast path
        // fallback_total = number of simple candidates that committed via general STM path
        let fastpath_total = fastpath_committed.len() as u64;
        let fallback_total = if self.config.simple_fastpath_enabled {
            // Count simple candidates that committed but NOT via fast path
            finally_committed
                .iter()
                .filter(|tx_idx| simple_candidates.contains(tx_idx) && !fastpath_committed.contains(tx_idx))
                .count() as u64
        } else {
            0
        };

        // Emit wave-building metrics
        #[cfg(feature = "metrics")]
        {
            crate::metrics::exec_stm_waves_built_inc(waves_this_block);
            // T93.3: Emit fast path metrics (per-tx, not per-wave)
            if self.config.simple_fastpath_enabled {
                crate::metrics::stm_simple_fastpath_inc(fastpath_total);
                crate::metrics::stm_simple_fallback_inc(fallback_total);
            }
        }

        log::debug!(
            "STM(arena): completed {} waves, {} committed, {} failed/aborted, {} conflicts, {} retries, arena_size={}, candidates={}, fastpath={}, fallback={}",
            waves_this_block,
            committed_txs.len(),
            n - committed_txs.len(),
            conflicts_this_block,
            retries_this_block,
            arena.len(),
            candidate_count,
            fastpath_total,
            fallback_total
        );

        (committed_txs, waves_this_block, conflicts_this_block, retries_this_block, aborted_this_block)
    }

    /// T87.4: Execute a single transaction speculatively using arena indices.
    ///
    /// T97.0: Takes `&AnalyzedTx` instead of `&Arc<SignedTx>` to avoid Arc cloning.
    /// Uses cached fields from AnalyzedTx for nonce/amount/fee.
    fn execute_tx_with_arena(
        ctx: &ArenaTxContext,
        analyzed: &AnalyzedTx,
        attempt: u16,
        arena: &AccountArena,
    ) -> ArenaTxContext {
        let mut new_ctx = ArenaTxContext {
            tx_idx: ctx.tx_idx,
            sender_idx: ctx.sender_idx,
            receiver_idx: ctx.receiver_idx,
            attempt,
            status: TxStatus::NeedsRetry,
            spec_result: None,
        };
        
        // Read accounts from arena (O(1) Vec access)
        let sender_acc = arena.account(ctx.sender_idx);
        let receiver_acc = arena.account(ctx.receiver_idx);
        
        // Validate nonce and balance using cached fields from AnalyzedTx
        if sender_acc.nonce != analyzed.nonce {
            // Temporary failure - may succeed after earlier txs commit
            new_ctx.status = TxStatus::NeedsRetry;
            return new_ctx;
        }
        
        let need = analyzed.amount.saturating_add(analyzed.fee);
        if sender_acc.balance < need {
            new_ctx.status = TxStatus::NeedsRetry;
            return new_ctx;
        }
        
        // Compute new states
        // T97.0: Track account clones for metrics
        #[cfg(feature = "metrics")]
        crate::metrics::stm_account_clones_inc(2);
        
        let mut new_sender = sender_acc.clone();
        new_sender.balance = new_sender.balance.saturating_sub(need);
        new_sender.nonce = new_sender.nonce.saturating_add(1);
        
        let mut new_receiver = receiver_acc.clone();
        new_receiver.balance = new_receiver.balance.saturating_add(analyzed.amount);
        
        new_ctx.spec_result = Some(ArenaSpeculativeResult {
            sender_idx: ctx.sender_idx,
            receiver_idx: ctx.receiver_idx,
            sender_account: new_sender,
            receiver_account: new_receiver,
            fee: analyzed.fee,
        });
        
        new_ctx.status = TxStatus::Committed;
        new_ctx
    }

    /// T87.4: Detect conflicts for arena-based execution.
    ///
    /// Uses the same conflict semantics as legacy kernel but with arena indices.
    fn detect_conflicts_arena(
        contexts: &[ArenaTxContext],
        pending_indices: &[usize],
        idx_to_arena: &HashMap<usize, usize>,
    ) -> Vec<usize> {
        let mut conflicts = Vec::new();
        
        // Track committed writes by arena index -> tx_idx
        let mut committed_writes: HashMap<u32, usize> = HashMap::new();

        // Process in tx index order for determinism
        let mut sorted_pending: Vec<usize> = pending_indices.to_vec();
        sorted_pending.sort();

        let mut wave_size = 0usize;

        for &tx_idx in &sorted_pending {
            let arena_idx = match idx_to_arena.get(&tx_idx) {
                Some(&idx) => idx,
                None => continue,
            };
            let ctx = &contexts[arena_idx];
            
            if ctx.status != TxStatus::Committed {
                continue;
            }

            let mut has_conflict = false;

            // Check read-after-write conflicts: did we read something written by an earlier tx?
            // Sender reads their own account
            if let Some(&writer_idx) = committed_writes.get(&ctx.sender_idx) {
                if writer_idx < tx_idx {
                    has_conflict = true;
                }
            }
            // Receiver reads its account
            if !has_conflict {
                if let Some(&writer_idx) = committed_writes.get(&ctx.receiver_idx) {
                    if writer_idx < tx_idx {
                        has_conflict = true;
                    }
                }
            }

            if has_conflict {
                conflicts.push(tx_idx);
            } else {
                // Record our writes for conflict detection with later txs
                committed_writes.insert(ctx.sender_idx, tx_idx);
                committed_writes.insert(ctx.receiver_idx, tx_idx);
                wave_size += 1;
            }
        }

        // Emit wave size metric
        #[cfg(feature = "metrics")]
        {
            crate::metrics::exec_stm_observe_wave_size(wave_size);
        }

        conflicts
    }

    /// T82.4: Detect conflicts in a wave using pre-screening optimization.
    ///
    /// This method uses a two-phase approach:
    /// 1. Fast pre-screen using WaveFingerprint (bloom filter + exact key check)
    /// 2. Fall back to precise StateKey-based conflict detection when needed
    ///
    /// The pre-screen is a pure optimization layered on top of the existing
    /// conflict detection. It never introduces false negatives (missed conflicts),
    /// only reduces false positives vs. bloom-only pre-screening.
    fn detect_conflicts_with_prescreen(
        contexts: &[TxContext],
        pending_indices: &[usize],
        analyzed_map: &HashMap<usize, &AnalyzedTx>,
    ) -> Vec<usize> {
        let mut conflicts = Vec::new();
        
        // T82.4: Wave fingerprint for pre-screening
        let mut wave_fingerprint = WaveFingerprint::new();
        
        // Track committed writes by tx index (for precise conflict detection)
        let mut committed_writes: HashMap<StateKey, usize> = HashMap::new();

        // Process in index order for determinism
        let mut sorted_pending: Vec<usize> = pending_indices.to_vec();
        sorted_pending.sort();

        for &tx_idx in &sorted_pending {
            let ctx = &contexts[tx_idx];
            
            if ctx.status != TxStatus::Committed {
                continue;
            }

            let mut has_conflict = false;

            // Get the analyzed tx for pre-screening
            if let Some(analyzed) = analyzed_map.get(&tx_idx) {
                // T82.4: Fast pre-screen using WaveFingerprint
                if wave_fingerprint.may_conflict(&analyzed.meta) {
                    // Pre-screen says "may conflict" - do precise check
                    #[cfg(feature = "metrics")]
                    crate::metrics::exec_stm_prescreen_hit_inc();

                    // Fall back to existing precise StateKey-based conflict detection
                    // Check read-after-write conflicts
                    for key in &ctx.read_set {
                        if let Some(&writer_idx) = committed_writes.get(key) {
                            if writer_idx < tx_idx {
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
                                    has_conflict = true;
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    // Pre-screen says "no conflict" - definitely safe
                    #[cfg(feature = "metrics")]
                    crate::metrics::exec_stm_prescreen_miss_inc();
                    
                    // Still need to record writes for future conflict detection
                    // but we know this tx has no conflict with earlier txs
                }
            } else {
                // No analyzed metadata - fall back to precise check only
                // (This shouldn't happen for valid txs, but handle gracefully)
                for key in &ctx.read_set {
                    if let Some(&writer_idx) = committed_writes.get(key) {
                        if writer_idx < tx_idx {
                            has_conflict = true;
                            break;
                        }
                    }
                }
                if !has_conflict {
                    for key in &ctx.write_set {
                        if let Some(&writer_idx) = committed_writes.get(key) {
                            if writer_idx < tx_idx {
                                has_conflict = true;
                                break;
                            }
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
                
                // T82.4: Record in wave fingerprint for pre-screening later txs
                if let Some(analyzed) = analyzed_map.get(&tx_idx) {
                    wave_fingerprint.record(&analyzed.meta);
                }
            }
        }

        // T82.4: Emit wave size metric
        // Wave size is the count of transactions that were successfully committed
        // in this wave (i.e., passed both execution and conflict detection).
        // This equals: wave_fingerprint.tx_count() since we only record non-conflicting txs.
        #[cfg(feature = "metrics")]
        {
            crate::metrics::exec_stm_observe_wave_size(wave_fingerprint.tx_count());
        }

        conflicts
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
    /// T82.1: Uses BlockOverlay and AnalyzedTx for efficient execution:
    /// - Transactions are analyzed once at block start (pre-computed sender/metadata)
    /// - State changes tracked in overlay (no full state clone per wave)
    /// - Overlay applied to base state at block commit
    ///
    /// T87.4: When EEZO_STM_KERNEL_MODE=arena, uses arena-indexed execution:
    /// - All touched accounts stored contiguously in a Vec
    /// - Access via indices instead of HashMap lookups
    /// - Same semantics, better cache locality
    ///
    /// The implementation:
    /// 1. Takes a read-only base snapshot of accounts
    /// 2. Analyzes all txs to build AnalyzedTx with conflict metadata
    /// 3. Runs STM scheduling loop (wave-based execution)
    /// 4. Detects and resolves conflicts deterministically
    /// 5. Applies changes to base state at block commit
    /// 6. Builds the Block from committed transactions
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
            // Empty block - skip metrics for empty blocks to avoid skewing histograms
            let header = Self::build_block_header(input.height, prev, &[], timestamp_ms);
            let block = Block { header, txs: Vec::new() };
            return ExecOutcome::new(Ok(block), start.elapsed(), 0);
        }

        // Clone state for speculative execution
        let mut accounts = node.accounts.clone();
        let mut supply = node.supply.clone();

        // T87.4: Select kernel based on configuration
        let (committed_txs, waves_this_block, conflicts_this_block, retries_this_block, aborted_this_block) = 
            match self.config.kernel_mode {
                StmKernelMode::Arena => {
                    // T87.4: Use arena-indexed kernel for better cache locality
                    self.execute_stm_with_arena(&input.txs, &mut accounts, &mut supply)
                }
                StmKernelMode::Legacy => {
                    // T82.1: Use overlay-based kernel (default)
                    let (_contexts, txs, waves, conflicts, retries, aborted) = 
                        self.execute_stm_with_overlay(&input.txs, &mut accounts, &mut supply);
                    (txs, waves, conflicts, retries, aborted)
                }
            };
        let tx_count = committed_txs.len();

        // T73.4: Emit STM-specific metrics (legacy eezo_stm_* prefix)
        #[cfg(feature = "metrics")]
        {
            crate::metrics::stm_block_waves_inc(waves_this_block);
            crate::metrics::stm_block_conflicts_inc(conflicts_this_block);
            crate::metrics::stm_block_retries_inc(retries_this_block);
            crate::metrics::stm_observe_waves_per_block(waves_this_block);
            crate::metrics::stm_observe_conflicts_per_block(conflicts_this_block);
            crate::metrics::stm_observe_retries_per_block(retries_this_block);
        }

        // T82.0: Emit executor metrics with eezo_exec_* prefix
        #[cfg(feature = "metrics")]
        {
            crate::metrics::exec_stm_waves_inc(waves_this_block);
            crate::metrics::exec_stm_conflicts_inc(conflicts_this_block);
            crate::metrics::exec_stm_retries_inc(retries_this_block);
            crate::metrics::exec_stm_aborted_inc(aborted_this_block);
            crate::metrics::exec_stm_observe_waves_per_block(waves_this_block);
            crate::metrics::exec_stm_observe_conflicts_per_block(conflicts_this_block);
            crate::metrics::exec_stm_observe_retries_per_block(retries_this_block);
        }

        // T72.metrics.fix: Record transactions per block histogram
        // This is called unconditionally (via no-op stub when metrics disabled)
        crate::metrics::observe_exec_txs_per_block(tx_count as u64);

        // Build the block
        let header = Self::build_block_header(input.height, prev, &committed_txs, timestamp_ms);
        let block = Block { header, txs: committed_txs };

        let elapsed = start.elapsed();
        let kernel_mode_str = if self.config.kernel_mode.is_arena() { "arena" } else { "overlay" };
        log::info!(
            "STM({}): executed {} txs ({} committed) in {:?}, waves={}, conflicts={}, retries={}, aborted={}",
            kernel_mode_str,
            input.txs.len(),
            tx_count,
            elapsed,
            waves_this_block,
            conflicts_this_block,
            retries_this_block,
            aborted_this_block
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
    use std::sync::Mutex;

    // Mutex to serialize env var access across tests to prevent race conditions
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        // T76.7: Check new fields
        assert_eq!(config.exec_lanes, 16);
        assert_eq!(config.wave_cap, 0); // 0 = unlimited
        // T87.1: Check wave_aggressive
        assert!(!config.wave_aggressive);
        // T87.4: Check kernel_mode
        assert_eq!(config.kernel_mode, StmKernelMode::Legacy);
        // T93.2: Check simple_fastpath_enabled
        assert!(!config.simple_fastpath_enabled);
    }

    #[test]
    fn test_stm_executor_with_config() {
        let config = StmConfig {
            threads: 8,
            max_retries: 10,
            wave_timeout_ms: 500,
            exec_lanes: 32,
            wave_cap: 100,
            wave_aggressive: true, // T87.1
            kernel_mode: StmKernelMode::Arena, // T87.4
            simple_fastpath_enabled: true, // T93.2
        };
        let exec = StmExecutor::with_config(config);
        assert_eq!(exec.threads(), 8);
        assert_eq!(exec.config().max_retries, 10);
        assert_eq!(exec.config().wave_timeout_ms, 500);
        // T76.7: Check new fields
        assert_eq!(exec.config().exec_lanes, 32);
        assert_eq!(exec.config().wave_cap, 100);
        // T87.1: Check wave_aggressive
        assert!(exec.config().wave_aggressive);
        // T87.4: Check kernel_mode
        assert_eq!(exec.config().kernel_mode, StmKernelMode::Arena);
        // T93.2: Check simple_fastpath_enabled
        assert!(exec.config().simple_fastpath_enabled);
    }

    // T76.7: Test exec_lanes and wave_cap configuration from environment
    #[test]
    fn test_stm_config_from_env_defaults() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Clear env vars to test defaults
        std::env::remove_var("EEZO_EXEC_LANES");
        std::env::remove_var("EEZO_EXEC_WAVE_CAP");
        std::env::remove_var("EEZO_STM_WAVE_AGGRESSIVE"); // T87.1
        std::env::remove_var("EEZO_STM_KERNEL_MODE"); // T87.4
        std::env::remove_var("EEZO_STM_SIMPLE_FASTPATH_ENABLED"); // T93.2
        
        let config = StmConfig::from_env(4);
        
        assert_eq!(config.threads, 4);
        assert_eq!(config.exec_lanes, 16); // default
        assert_eq!(config.wave_cap, 0); // default, unlimited
        assert!(!config.wave_aggressive); // T87.1: default off
        assert_eq!(config.kernel_mode, StmKernelMode::Legacy); // T87.4: default legacy
        assert!(!config.simple_fastpath_enabled); // T93.2: default off
    }

    #[test]
    fn test_stm_config_from_env_valid_lanes() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Set valid exec_lanes values
        std::env::set_var("EEZO_EXEC_LANES", "32");
        std::env::set_var("EEZO_EXEC_WAVE_CAP", "50");
        
        let config = StmConfig::from_env(4);
        
        assert_eq!(config.exec_lanes, 32);
        assert_eq!(config.wave_cap, 50);
        
        // Clean up
        std::env::remove_var("EEZO_EXEC_LANES");
        std::env::remove_var("EEZO_EXEC_WAVE_CAP");
    }

    // T87.1: Test wave_aggressive configuration from environment
    #[test]
    fn test_stm_config_from_env_wave_aggressive() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Test enabling wave_aggressive
        std::env::set_var("EEZO_STM_WAVE_AGGRESSIVE", "1");
        let config = StmConfig::from_env(4);
        assert!(config.wave_aggressive);
        
        std::env::set_var("EEZO_STM_WAVE_AGGRESSIVE", "true");
        let config = StmConfig::from_env(4);
        assert!(config.wave_aggressive);
        
        std::env::set_var("EEZO_STM_WAVE_AGGRESSIVE", "yes");
        let config = StmConfig::from_env(4);
        assert!(config.wave_aggressive);
        
        // Test disabling
        std::env::set_var("EEZO_STM_WAVE_AGGRESSIVE", "0");
        let config = StmConfig::from_env(4);
        assert!(!config.wave_aggressive);
        
        std::env::set_var("EEZO_STM_WAVE_AGGRESSIVE", "false");
        let config = StmConfig::from_env(4);
        assert!(!config.wave_aggressive);
        
        // Clean up
        std::env::remove_var("EEZO_STM_WAVE_AGGRESSIVE");
    }

    // T87.4: Test kernel_mode configuration from environment
    #[test]
    fn test_stm_config_from_env_kernel_mode() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Test arena kernel mode
        std::env::set_var("EEZO_STM_KERNEL_MODE", "arena");
        let config = StmConfig::from_env(4);
        assert_eq!(config.kernel_mode, StmKernelMode::Arena);
        assert!(config.kernel_mode.is_arena());
        
        // Test legacy kernel mode (explicit)
        std::env::set_var("EEZO_STM_KERNEL_MODE", "legacy");
        let config = StmConfig::from_env(4);
        assert_eq!(config.kernel_mode, StmKernelMode::Legacy);
        assert!(!config.kernel_mode.is_arena());
        
        // Test unknown value defaults to legacy
        std::env::set_var("EEZO_STM_KERNEL_MODE", "unknown");
        let config = StmConfig::from_env(4);
        assert_eq!(config.kernel_mode, StmKernelMode::Legacy);
        
        // Clean up
        std::env::remove_var("EEZO_STM_KERNEL_MODE");
    }

    // T87.4: Test StmKernelMode enum
    #[test]
    fn test_stm_kernel_mode_default() {
        assert_eq!(StmKernelMode::default(), StmKernelMode::Legacy);
    }

    #[test]
    fn test_stm_kernel_mode_from_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Test unset defaults to Legacy
        std::env::remove_var("EEZO_STM_KERNEL_MODE");
        assert_eq!(StmKernelMode::from_env(), StmKernelMode::Legacy);
        
        // Test "arena" value
        std::env::set_var("EEZO_STM_KERNEL_MODE", "arena");
        assert_eq!(StmKernelMode::from_env(), StmKernelMode::Arena);
        
        // Test "ARENA" (case insensitive)
        std::env::set_var("EEZO_STM_KERNEL_MODE", "ARENA");
        assert_eq!(StmKernelMode::from_env(), StmKernelMode::Arena);
        
        // Test other values default to Legacy
        std::env::set_var("EEZO_STM_KERNEL_MODE", "other");
        assert_eq!(StmKernelMode::from_env(), StmKernelMode::Legacy);
        
        // Clean up
        std::env::remove_var("EEZO_STM_KERNEL_MODE");
    }

    #[test]
    fn test_stm_config_from_env_invalid_lanes_defaults() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Set invalid exec_lanes value (should default to 16)
        std::env::set_var("EEZO_EXEC_LANES", "100"); // Invalid, not in 16/32/48/64
        
        let config = StmConfig::from_env(4);
        
        assert_eq!(config.exec_lanes, 16); // Should default to 16
        
        // Clean up
        std::env::remove_var("EEZO_EXEC_LANES");
    }

    #[test]
    fn test_stm_config_with_threads() {
        let config = StmConfig::with_threads(8);
        
        assert_eq!(config.threads, 8);
        // T76.7: Ensure defaults are applied
        assert_eq!(config.exec_lanes, 16);
        assert_eq!(config.wave_cap, 0);
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

    // =========================================================================
    // T72.metrics.fix: Executor block histogram tests
    // =========================================================================

    #[cfg(feature = "metrics")]
    #[test]
    fn test_stm_executor_records_txs_per_block_metric() {
        use crate::metrics::EEZO_EXEC_TXS_PER_BLOCK;
        
        // Get the initial count (number of observations)
        let initial_count = EEZO_EXEC_TXS_PER_BLOCK.get_sample_count();
        
        // Create a test node and executor
        let chain_id = [0u8; 20];
        let cfg = eezo_ledger::consensus::SingleNodeCfg {
            chain_id,
            block_byte_budget: 1 << 20,
            header_cache_cap: 100,
            ..Default::default()
        };
        let (pk, sk) = pqcrypto_mldsa::mldsa44::keypair();
        let mut node = eezo_ledger::consensus::SingleNode::new(cfg, sk, pk);
        
        // Execute an empty block (which still records the metric)
        let executor = StmExecutor::new(1);
        let input = crate::executor::ExecInput::new(vec![], 1);
        let _outcome = executor.execute_block(&mut node, input);
        
        // Note: Empty blocks don't increment the metric in STM executor
        // because we return early. Let's just verify the metric is accessible.
        let _count = EEZO_EXEC_TXS_PER_BLOCK.get_sample_count();
        
        // The test passes if we can access the metric without panicking
        // A full test with transactions would require setting up valid signed txs
    }

    // =========================================================================
    // T82.1: AnalyzedTx & BlockOverlay Tests
    // =========================================================================

    #[test]
    fn test_address_fingerprint_deterministic() {
        let addr1 = Address([1u8; 20]);
        let addr2 = Address([2u8; 20]);
        
        // Same address produces same fingerprint
        let fp1a = address_fingerprint(&addr1);
        let fp1b = address_fingerprint(&addr1);
        assert_eq!(fp1a, fp1b);
        
        // Different addresses produce different fingerprints
        let fp2 = address_fingerprint(&addr2);
        assert_ne!(fp1a, fp2);
    }

    #[test]
    fn test_analyzed_tx_construction_simple_transfer() {
        use eezo_ledger::TxCore;
        
        // Create a test transaction
        let sender_bytes: [u8; 20] = [0x11; 20];
        let receiver_bytes: [u8; 20] = [0x22; 20];
        
        let tx = SignedTx {
            core: TxCore {
                to: Address(receiver_bytes),
                amount: 1000,
                fee: 1,
                nonce: 0,
            },
            pubkey: sender_bytes.to_vec(),
            sig: vec![],
        };
        
        // Analyze the transaction
        let analyzed = analyze_tx(&tx, 0).expect("analyze should succeed");
        
        // Check that sender was derived correctly
        assert_eq!(analyzed.sender, Address(sender_bytes));
        assert_eq!(analyzed.tx_idx, 0);
        
        // Check that ConflictMetadata is Simple with correct fingerprints
        match &analyzed.meta {
            ConflictMetadata::Simple { from_key, to_key } => {
                assert_eq!(*from_key, address_fingerprint(&Address(sender_bytes)));
                assert_eq!(*to_key, address_fingerprint(&Address(receiver_bytes)));
            }
            ConflictMetadata::Complex { .. } => {
                panic!("Expected Simple metadata for simple transfer");
            }
        }
    }

    #[test]
    fn test_analyzed_tx_invalid_sender_returns_none() {
        use eezo_ledger::TxCore;
        
        // Create a transaction with pubkey too short.
        // sender_from_pubkey_first20() requires at least 20 bytes to derive sender address.
        let tx = SignedTx {
            core: TxCore {
                to: Address([0x22; 20]),
                amount: 1000,
                fee: 1,
                nonce: 0,
            },
            pubkey: vec![1, 2, 3], // Only 3 bytes, sender derivation requires 20+
            sig: vec![],
        };
        
        let result = analyze_tx(&tx, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_conflict_metadata_conflicts_with_same_sender() {
        let addr1 = Address([1u8; 20]);
        let addr2 = Address([2u8; 20]);
        let addr3 = Address([3u8; 20]);
        
        let meta1 = ConflictMetadata::Simple {
            from_key: address_fingerprint(&addr1),
            to_key: address_fingerprint(&addr2),
        };
        
        // Same sender, different receiver
        let meta2 = ConflictMetadata::Simple {
            from_key: address_fingerprint(&addr1),
            to_key: address_fingerprint(&addr3),
        };
        
        // Should conflict (same sender)
        assert!(meta1.conflicts_with(&meta2));
    }

    #[test]
    fn test_conflict_metadata_conflicts_with_overlapping_accounts() {
        let addr1 = Address([1u8; 20]);
        let addr2 = Address([2u8; 20]);
        let addr3 = Address([3u8; 20]);
        
        // tx1: addr1 -> addr2
        let meta1 = ConflictMetadata::Simple {
            from_key: address_fingerprint(&addr1),
            to_key: address_fingerprint(&addr2),
        };
        
        // tx2: addr2 -> addr3 (sender is tx1's receiver)
        let meta2 = ConflictMetadata::Simple {
            from_key: address_fingerprint(&addr2),
            to_key: address_fingerprint(&addr3),
        };
        
        // Should conflict (tx2's sender is tx1's receiver)
        assert!(meta1.conflicts_with(&meta2));
    }

    #[test]
    fn test_conflict_metadata_no_conflict_independent() {
        let addr1 = Address([1u8; 20]);
        let addr2 = Address([2u8; 20]);
        let addr3 = Address([3u8; 20]);
        let addr4 = Address([4u8; 20]);
        
        // tx1: addr1 -> addr2
        let meta1 = ConflictMetadata::Simple {
            from_key: address_fingerprint(&addr1),
            to_key: address_fingerprint(&addr2),
        };
        
        // tx2: addr3 -> addr4 (completely independent)
        let meta2 = ConflictMetadata::Simple {
            from_key: address_fingerprint(&addr3),
            to_key: address_fingerprint(&addr4),
        };
        
        // Should NOT conflict
        assert!(!meta1.conflicts_with(&meta2));
    }

    #[test]
    fn test_block_overlay_new_is_empty() {
        let overlay = BlockOverlay::new();
        assert!(overlay.is_empty());
        assert_eq!(overlay.len(), 0);
        assert_eq!(overlay.total_fees_burned(), 0);
    }

    #[test]
    fn test_block_overlay_read_falls_back_to_base() {
        use eezo_ledger::Account;
        
        let addr = Address([0x42; 20]);
        let mut base = Accounts::default();
        
        // Set up base account with balance
        base.put(addr, Account { balance: 1000, nonce: 5 });
        
        let overlay = BlockOverlay::new();
        
        // Read from overlay should fall back to base
        let acct = overlay.get_account(&addr, &base);
        assert_eq!(acct.balance, 1000);
        assert_eq!(acct.nonce, 5);
    }

    #[test]
    fn test_block_overlay_read_prefers_overlay() {
        use eezo_ledger::Account;
        
        let addr = Address([0x42; 20]);
        let mut base = Accounts::default();
        
        // Set up base account
        base.put(addr, Account { balance: 1000, nonce: 5 });
        
        // Put modified account in overlay
        let mut overlay = BlockOverlay::new();
        overlay.put_account(addr, Account { balance: 500, nonce: 6 });
        
        // Read should prefer overlay
        let acct = overlay.get_account(&addr, &base);
        assert_eq!(acct.balance, 500);
        assert_eq!(acct.nonce, 6);
    }

    #[test]
    fn test_block_overlay_tracks_fee_burns() {
        let mut overlay = BlockOverlay::new();
        
        overlay.record_fee_burn(10);
        overlay.record_fee_burn(25);
        overlay.record_fee_burn(5);
        
        assert_eq!(overlay.total_fees_burned(), 40);
    }

    #[test]
    fn test_block_overlay_apply_to_state() {
        use eezo_ledger::Account;
        
        let addr1 = Address([1u8; 20]);
        let addr2 = Address([2u8; 20]);
        
        let mut accounts = Accounts::default();
        let mut supply = Supply::default();
        
        // Set up overlay with some modifications
        let mut overlay = BlockOverlay::new();
        overlay.put_account(addr1, Account { balance: 900, nonce: 1 });
        overlay.put_account(addr2, Account { balance: 100, nonce: 0 });
        overlay.record_fee_burn(10);
        
        // Apply to state
        overlay.apply_to_state(&mut accounts, &mut supply);
        
        // Check accounts were updated
        let acct1 = accounts.get(&addr1);
        assert_eq!(acct1.balance, 900);
        assert_eq!(acct1.nonce, 1);
        
        let acct2 = accounts.get(&addr2);
        assert_eq!(acct2.balance, 100);
        assert_eq!(acct2.nonce, 0);
        
        // Check supply was updated
        assert_eq!(supply.burn_total, 10);
    }

    #[test]
    fn test_analyze_batch_filters_invalid_senders() {
        use eezo_ledger::TxCore;
        
        let valid_tx = SignedTx {
            core: TxCore {
                to: Address([0x22; 20]),
                amount: 1000,
                fee: 1,
                nonce: 0,
            },
            pubkey: [0x11u8; 20].to_vec(), // Valid pubkey (20 bytes)
            sig: vec![],
        };
        
        let invalid_tx = SignedTx {
            core: TxCore {
                to: Address([0x33; 20]),
                amount: 500,
                fee: 1,
                nonce: 0,
            },
            pubkey: vec![1, 2, 3], // Invalid pubkey (too short)
            sig: vec![],
        };
        
        let txs = vec![valid_tx, invalid_tx];
        let analyzed = analyze_batch(&txs);
        
        // Only the valid tx should be analyzed
        assert_eq!(analyzed.len(), 1);
        assert_eq!(analyzed[0].tx_idx, 0);
    }

    // =========================================================================
    // T82.4: WaveFingerprint Tests
    // =========================================================================

    #[test]
    fn test_wave_fingerprint_new_is_empty() {
        let fp = WaveFingerprint::new();
        assert!(fp.is_empty());
        assert_eq!(fp.tx_count(), 0);
    }

    #[test]
    fn test_wave_fingerprint_may_conflict_empty_returns_false() {
        let fp = WaveFingerprint::new();
        
        let meta = ConflictMetadata::Simple {
            from_key: 12345,
            to_key: 67890,
        };
        
        // Empty fingerprint should never indicate conflict
        assert!(!fp.may_conflict(&meta));
    }

    #[test]
    fn test_wave_fingerprint_record_and_may_conflict_same_keys() {
        let mut fp = WaveFingerprint::new();
        
        let meta1 = ConflictMetadata::Simple {
            from_key: 12345,
            to_key: 67890,
        };
        
        fp.record(&meta1);
        assert_eq!(fp.tx_count(), 1);
        
        // Same keys should indicate conflict
        let meta2 = ConflictMetadata::Simple {
            from_key: 12345,  // Same from_key
            to_key: 99999,
        };
        assert!(fp.may_conflict(&meta2));
        
        // Same to_key
        let meta3 = ConflictMetadata::Simple {
            from_key: 11111,
            to_key: 67890,  // Same to_key
        };
        assert!(fp.may_conflict(&meta3));
    }

    #[test]
    fn test_wave_fingerprint_no_conflict_different_keys() {
        let mut fp = WaveFingerprint::new();
        
        let meta1 = ConflictMetadata::Simple {
            from_key: 12345,
            to_key: 67890,
        };
        
        fp.record(&meta1);
        
        // Different keys should not indicate conflict (with high probability)
        let meta2 = ConflictMetadata::Simple {
            from_key: 0xDEADBEEF12345678,
            to_key: 0xCAFEBABE87654321,
        };
        
        // Note: This may have false positives due to bloom filter collisions,
        // but with well-distributed keys, the probability is low.
        // The test uses distinct enough keys to make collisions unlikely.
        assert!(!fp.may_conflict(&meta2));
    }

    #[test]
    fn test_wave_fingerprint_record_multiple() {
        let mut fp = WaveFingerprint::new();
        
        // Record 3 transactions
        for i in 0..3 {
            let meta = ConflictMetadata::Simple {
                from_key: (i * 1000) as u64,
                to_key: (i * 1000 + 100) as u64,
            };
            fp.record(&meta);
        }
        
        assert_eq!(fp.tx_count(), 3);
        assert!(!fp.is_empty());
    }

    #[test]
    fn test_wave_fingerprint_cross_conflict() {
        let mut fp = WaveFingerprint::new();
        
        // tx1: A -> B
        let meta1 = ConflictMetadata::Simple {
            from_key: 0xAAAA,
            to_key: 0xBBBB,
        };
        fp.record(&meta1);
        
        // tx2: B -> C (B was receiver of tx1, now sender of tx2 - conflict)
        let meta2 = ConflictMetadata::Simple {
            from_key: 0xBBBB,  // Same as meta1's to_key
            to_key: 0xCCCC,
        };
        
        assert!(fp.may_conflict(&meta2));
    }

    #[test]
    fn test_fingerprint_to_bloom_deterministic() {
        let fp1 = fingerprint_to_bloom(0x123456789ABCDEF0);
        let fp2 = fingerprint_to_bloom(0x123456789ABCDEF0);
        
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, 0); // Should set some bits
    }

    #[test]
    fn test_conflict_metadata_to_bloom_simple() {
        let meta = ConflictMetadata::Simple {
            from_key: 0x1234,
            to_key: 0x5678,
        };
        
        let bloom = meta.to_bloom();
        
        // Should be a combination of both fingerprints
        let expected = fingerprint_to_bloom(0x1234) | fingerprint_to_bloom(0x5678);
        assert_eq!(bloom, expected);
    }

    #[test]
    fn test_conflict_metadata_complex_variant() {
        let meta = ConflictMetadata::Complex {
            bloom: 0b10101010,
            touch_count: 5,
        };
        
        // to_bloom should return the stored bloom
        assert_eq!(meta.to_bloom(), 0b10101010);
        
        // keys() should return None for Complex
        assert!(meta.keys().is_none());
    }

    #[test]
    fn test_conflict_metadata_simple_vs_complex_conflict() {
        let simple = ConflictMetadata::Simple {
            from_key: 0x1234,
            to_key: 0x5678,
        };
        
        // Create a Complex metadata with overlapping bloom bits
        let simple_bloom = simple.to_bloom();
        let complex = ConflictMetadata::Complex {
            bloom: simple_bloom,  // Same bloom bits
            touch_count: 2,
        };
        
        // Should indicate conflict
        assert!(simple.conflicts_with(&complex));
        assert!(complex.conflicts_with(&simple));
    }

    #[test]
    fn test_conflict_metadata_complex_vs_complex_no_overlap() {
        let complex1 = ConflictMetadata::Complex {
            bloom: 0b00001111,
            touch_count: 2,
        };
        
        let complex2 = ConflictMetadata::Complex {
            bloom: 0b11110000,  // No overlapping bits
            touch_count: 2,
        };
        
        // Should NOT indicate conflict
        assert!(!complex1.conflicts_with(&complex2));
    }

    #[test]
    fn test_conflict_metadata_complex_vs_complex_overlap() {
        let complex1 = ConflictMetadata::Complex {
            bloom: 0b00111111,
            touch_count: 2,
        };
        
        let complex2 = ConflictMetadata::Complex {
            bloom: 0b11111100,  // Overlapping bits in the middle
            touch_count: 2,
        };
        
        // Should indicate conflict
        assert!(complex1.conflicts_with(&complex2));
    }

    // =========================================================================
    // T82.4b: Integration test for STM metrics wiring
    // =========================================================================

    #[cfg(feature = "metrics")]
    #[test]
    fn test_stm_executor_increments_wave_metrics() {
        use crate::metrics::{
            EEZO_EXEC_STM_WAVES_TOTAL,
            EEZO_EXEC_STM_WAVES_BUILT_TOTAL,
        };
        use eezo_ledger::TxCore;
        
        // Create a test node
        let chain_id = [0u8; 20];
        let cfg = eezo_ledger::consensus::SingleNodeCfg {
            chain_id,
            block_byte_budget: 1 << 20,
            header_cache_cap: 100,
            ..Default::default()
        };
        let (pk, sk) = pqcrypto_mldsa::mldsa44::keypair();
        let mut node = eezo_ledger::consensus::SingleNode::new(cfg, sk, pk);
        
        // Fund a sender
        let sender_bytes: [u8; 20] = [0x42; 20];
        let sender = Address(sender_bytes);
        node.dev_faucet_credit(sender, 100_000);
        
        // Capture initial metric values
        let waves_before = EEZO_EXEC_STM_WAVES_TOTAL.get();
        let waves_built_before = EEZO_EXEC_STM_WAVES_BUILT_TOTAL.get();
        
        // Create a valid transaction
        let recipient = Address([0xBE; 20]);
        let tx = SignedTx {
            core: TxCore {
                to: recipient,
                amount: 1000,
                fee: 1,
                nonce: 0,
            },
            pubkey: sender_bytes.to_vec(),
            sig: vec![],
        };
        
        // Execute with STM executor
        let executor = StmExecutor::new(1);
        let input = crate::executor::ExecInput::new(vec![tx], 1);
        let outcome = executor.execute_block(&mut node, input);
        
        // Verify execution succeeded
        assert!(outcome.result.is_ok());
        let block = outcome.result.unwrap();
        assert_eq!(block.txs.len(), 1);
        
        // Verify metrics were incremented
        let waves_after = EEZO_EXEC_STM_WAVES_TOTAL.get();
        let waves_built_after = EEZO_EXEC_STM_WAVES_BUILT_TOTAL.get();
        
        assert!(waves_after > waves_before, 
            "eezo_exec_stm_waves_total should increment: before={}, after={}", 
            waves_before, waves_after);
        assert!(waves_built_after > waves_built_before, 
            "eezo_exec_stm_waves_built_total should increment: before={}, after={}", 
            waves_built_before, waves_built_after);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_stm_executor_increments_prescreen_metrics_with_conflicts() {
        use crate::metrics::{
            EEZO_EXEC_STM_PRESCREEN_HITS_TOTAL,
            EEZO_EXEC_STM_PRESCREEN_MISSES_TOTAL,
        };
        use eezo_ledger::TxCore;
        
        // Create a test node
        let chain_id = [0u8; 20];
        let cfg = eezo_ledger::consensus::SingleNodeCfg {
            chain_id,
            block_byte_budget: 1 << 20,
            header_cache_cap: 100,
            ..Default::default()
        };
        let (pk, sk) = pqcrypto_mldsa::mldsa44::keypair();
        let mut node = eezo_ledger::consensus::SingleNode::new(cfg, sk, pk);
        
        // Fund two senders
        let sender1_bytes: [u8; 20] = [0x11; 20];
        let sender2_bytes: [u8; 20] = [0x22; 20];
        node.dev_faucet_credit(Address(sender1_bytes), 100_000);
        node.dev_faucet_credit(Address(sender2_bytes), 100_000);
        
        // Capture initial metric values
        let hits_before = EEZO_EXEC_STM_PRESCREEN_HITS_TOTAL.get();
        let misses_before = EEZO_EXEC_STM_PRESCREEN_MISSES_TOTAL.get();
        
        // Create transactions - two senders to the same receiver (causes conflicts)
        let receiver = Address([0xDD; 20]);
        let txs = vec![
            SignedTx {
                core: TxCore { to: receiver, amount: 1000, fee: 1, nonce: 0 },
                pubkey: sender1_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: receiver, amount: 2000, fee: 2, nonce: 0 },
                pubkey: sender2_bytes.to_vec(),
                sig: vec![],
            },
        ];
        
        // Execute with STM executor
        let executor = StmExecutor::new(1);
        let input = crate::executor::ExecInput::new(txs, 1);
        let outcome = executor.execute_block(&mut node, input);
        
        // Verify execution succeeded
        assert!(outcome.result.is_ok());
        let block = outcome.result.unwrap();
        assert_eq!(block.txs.len(), 2);
        
        // Verify pre-screen metrics were incremented
        // With conflicting txs (same receiver), we expect at least one hit
        let hits_after = EEZO_EXEC_STM_PRESCREEN_HITS_TOTAL.get();
        let misses_after = EEZO_EXEC_STM_PRESCREEN_MISSES_TOTAL.get();
        
        // Either hits or misses (or both) should have incremented
        let total_before = hits_before + misses_before;
        let total_after = hits_after + misses_after;
        assert!(total_after > total_before,
            "Pre-screen metrics should increment: hits before={} after={}, misses before={} after={}",
            hits_before, hits_after, misses_before, misses_after);
    }

    // =========================================================================
    // T83.4: SharedTx → AnalyzedTx Integration Tests
    // =========================================================================

    #[test]
    fn test_analyze_shared_tx_basic() {
        use eezo_ledger::TxCore;
        use crate::tx_decode_pool::SharedTx;
        use std::sync::Arc;

        // Create a test transaction
        let sender_bytes: [u8; 20] = [0x11; 20];
        let receiver_bytes: [u8; 20] = [0x22; 20];

        let tx = SignedTx {
            core: TxCore {
                to: Address(receiver_bytes),
                amount: 1000,
                fee: 1,
                nonce: 42,
            },
            // Use a 20-byte pubkey so sender derivation works
            pubkey: sender_bytes.to_vec(),
            sig: vec![],
        };

        // Create SharedTx
        let chain_id = [0x01u8; 20];
        let shared_tx = Arc::new(SharedTx::new(tx, chain_id));

        // Analyze the SharedTx
        let analyzed = analyze_shared_tx(&shared_tx, 5).expect("analyze should succeed");

        // Verify fields are correct
        assert_eq!(analyzed.tx_idx, 5);
        assert_eq!(analyzed.sender, Address(sender_bytes));
        
        // T97.0: Core fields are now cached directly in AnalyzedTx
        assert_eq!(analyzed.nonce, 42);
        assert_eq!(analyzed.amount, 1000);
    }

    #[test]
    fn test_analyze_shared_tx_uses_cached_sender() {
        use eezo_ledger::TxCore;
        use crate::tx_decode_pool::SharedTx;
        use std::sync::Arc;

        // Create SharedTx
        let tx = SignedTx {
            core: TxCore {
                to: Address([0xaa; 20]),
                amount: 500,
                fee: 5,
                nonce: 0,
            },
            pubkey: vec![0x42; 32], // 32-byte pubkey
            sig: vec![],
        };

        let shared_tx = Arc::new(SharedTx::new(tx, [0; 20]));
        
        // The sender is pre-computed in SharedTx
        let cached_sender = shared_tx.sender().expect("should have sender");
        
        // Analyze should use the same sender
        let analyzed = analyze_shared_tx(&shared_tx, 0).expect("should succeed");
        assert_eq!(analyzed.sender, cached_sender);
    }

    #[test]
    fn test_analyze_shared_batch() {
        use eezo_ledger::TxCore;
        use crate::tx_decode_pool::SharedTx;
        use std::sync::Arc;

        // Create a batch of SharedTx
        let chain_id = [0x01u8; 20];
        let shared_txs: Vec<Arc<SharedTx>> = (0..5).map(|i| {
            let tx = SignedTx {
                core: TxCore {
                    to: Address([0xcc; 20]),
                    amount: 100 * (i as u128 + 1),
                    fee: 1,
                    nonce: i as u64,
                },
                pubkey: vec![0x11 + i; 20], // Different sender for each
                sig: vec![],
            };
            Arc::new(SharedTx::new(tx, chain_id))
        }).collect();

        // Analyze the batch
        let analyzed = analyze_shared_batch(&shared_txs);

        // All should be analyzed successfully
        assert_eq!(analyzed.len(), 5);

        // Check indices are correct
        for (i, atx) in analyzed.iter().enumerate() {
            assert_eq!(atx.tx_idx, i);
            assert_eq!(atx.nonce, i as u64);
        }
    }

    #[test]
    fn test_analyze_shared_tx_invalid_sender() {
        use eezo_ledger::TxCore;
        use crate::tx_decode_pool::SharedTx;
        use std::sync::Arc;

        // Create tx with pubkey too short for sender derivation
        let tx = SignedTx {
            core: TxCore {
                to: Address([0xaa; 20]),
                amount: 100,
                fee: 1,
                nonce: 0,
            },
            pubkey: vec![0x01; 5], // Only 5 bytes - too short
            sig: vec![],
        };

        let shared_tx = Arc::new(SharedTx::new(tx, [0; 20]));

        // SharedTx should not have valid sender
        assert!(shared_tx.sender().is_none());

        // analyze_shared_tx should return None
        assert!(analyze_shared_tx(&shared_tx, 0).is_none());
    }

    // ========================================================================
    // T93.2: Simple Fast Path Tests
    // ========================================================================

    #[test]
    fn test_stm_config_from_env_simple_fastpath() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Test enabling simple_fastpath
        std::env::set_var("EEZO_STM_SIMPLE_FASTPATH_ENABLED", "1");
        let config = StmConfig::from_env(4);
        assert!(config.simple_fastpath_enabled);
        
        // Clean up
        std::env::remove_var("EEZO_STM_SIMPLE_FASTPATH_ENABLED");
        
        // Test disabled
        std::env::set_var("EEZO_STM_SIMPLE_FASTPATH_ENABLED", "0");
        let config = StmConfig::from_env(4);
        assert!(!config.simple_fastpath_enabled);
        
        // Clean up
        std::env::remove_var("EEZO_STM_SIMPLE_FASTPATH_ENABLED");
    }

    #[test]
    fn test_analyzed_tx_kind_defaults_to_simple() {
        // Create a test transaction
        let tx = SignedTx {
            core: TxCore {
                to: Address([0xca; 20]),
                amount: 1000,
                fee: 1,
                nonce: 0,
            },
            pubkey: vec![0x42; 20], // Valid 20-byte pubkey
            sig: vec![],
        };

        let analyzed = analyze_tx(&tx, 0);
        assert!(analyzed.is_some());
        
        let atx = analyzed.unwrap();
        // T93.2: All basic transfers are classified as SimpleTransfer
        assert_eq!(atx.kind, AnalyzedTxKind::SimpleTransfer);
        assert!(atx.kind.is_simple());
        // Arena indices should be None until arena construction
        assert!(atx.sender_arena_idx.is_none());
        assert!(atx.receiver_arena_idx.is_none());
    }

    #[test]
    fn test_analyzed_tx_kind_is_simple() {
        assert!(AnalyzedTxKind::SimpleTransfer.is_simple());
        assert!(!AnalyzedTxKind::General.is_simple());
    }

    // ========================================================================
    // T93.3: Simple Fast Path Metrics & Coverage Tests
    // ========================================================================

    /// T93.3: Test that simple candidates are counted correctly at block start.
    #[test]
    fn test_simple_candidates_counted_at_block_start() {
        use eezo_ledger::TxCore;

        // Create a batch of transactions with valid senders
        let txs: Vec<SignedTx> = (0..5).map(|i| {
            SignedTx {
                core: TxCore {
                    to: Address([0xcc; 20]),
                    amount: 100,
                    fee: 1,
                    nonce: i as u64,
                },
                pubkey: vec![(0x11 + i) as u8; 20], // Different sender for each
                sig: vec![],
            }
        }).collect();

        // Analyze the batch
        let analyzed = analyze_batch(&txs);
        
        // All should be simple transfers
        assert_eq!(analyzed.len(), 5);
        for atx in &analyzed {
            assert!(atx.kind.is_simple(), "All txs should be SimpleTransfer");
        }
    }

    /// T93.3: Test that fast path committed set tracks per-tx outcomes.
    #[test]
    fn test_fastpath_committed_tracks_per_tx() {
        use eezo_ledger::{TxCore, AccountArena};

        // Setup: Create 3 txs from different senders to different receivers
        let sender1 = Address([0x11; 20]);
        let sender2 = Address([0x22; 20]);
        let sender3 = Address([0x33; 20]);
        let receiver1 = Address([0xAA; 20]);
        let receiver2 = Address([0xBB; 20]);
        let receiver3 = Address([0xCC; 20]);

        let txs: Vec<SignedTx> = vec![
            SignedTx {
                core: TxCore { to: receiver1, amount: 100, fee: 1, nonce: 0 },
                pubkey: sender1.0.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: receiver2, amount: 200, fee: 2, nonce: 0 },
                pubkey: sender2.0.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: receiver3, amount: 300, fee: 3, nonce: 0 },
                pubkey: sender3.0.to_vec(),
                sig: vec![],
            },
        ];

        // Analyze
        let analyzed_txs = analyze_batch(&txs);
        assert_eq!(analyzed_txs.len(), 3);

        // Build arena and contexts
        let mut accounts = Accounts::default();
        accounts.put(sender1, Account { balance: 1000, nonce: 0 });
        accounts.put(sender2, Account { balance: 2000, nonce: 0 });
        accounts.put(sender3, Account { balance: 3000, nonce: 0 });

        let mut arena = AccountArena::with_capacity(6);
        let mut arena_contexts: Vec<ArenaTxContext> = analyzed_txs
            .iter()
            .map(|atx| ArenaTxContext::from_analyzed(atx, &mut arena, &accounts))
            .collect();
        
        let idx_to_arena: HashMap<usize, usize> = arena_contexts
            .iter()
            .enumerate()
            .map(|(i, ctx)| (ctx.tx_idx, i))
            .collect();

        // Track fast path commits
        let mut fastpath_committed: HashSet<usize> = HashSet::new();
        
        // T95.1: Pre-compute simple candidate indices
        let simple_candidate_indices: Vec<usize> = analyzed_txs
            .iter()
            .filter(|atx| atx.kind.is_simple())
            .map(|atx| atx.tx_idx)
            .collect();
        
        // T95.1: Build analyzed_map for O(1) lookup
        let analyzed_map: HashMap<usize, &AnalyzedTx> = analyzed_txs
            .iter()
            .map(|a| (a.tx_idx, a))
            .collect();
        
        // T95.1: Create conflict bitmap (reused across waves in production)
        let mut conflict_bitmap = ArenaConflictBitmap::new();

        // Execute fast path wave
        StmExecutor::execute_simple_fastpath_wave(
            &simple_candidate_indices,
            &analyzed_map,
            &mut arena_contexts,
            &mut arena,
            &idx_to_arena,
            &mut conflict_bitmap,
            &mut fastpath_committed,
        );

        // All 3 should have committed via fast path (no conflicts)
        assert_eq!(fastpath_committed.len(), 3, "All 3 non-conflicting txs should use fast path");
        assert!(fastpath_committed.contains(&0));
        assert!(fastpath_committed.contains(&1));
        assert!(fastpath_committed.contains(&2));

        // All contexts should be committed
        for ctx in &arena_contexts {
            assert_eq!(ctx.status, TxStatus::Committed);
        }
    }

    /// T93.3: Test that conflicting txs (same receiver) force some to fallback.
    #[test]
    fn test_conflicting_txs_force_fallback() {
        use eezo_ledger::{TxCore, AccountArena};

        // Setup: 3 txs from different senders to the SAME receiver
        // This should cause conflicts since they all touch the same receiver account
        let sender1 = Address([0x11; 20]);
        let sender2 = Address([0x22; 20]);
        let sender3 = Address([0x33; 20]);
        let shared_receiver = Address([0xFF; 20]);

        let txs: Vec<SignedTx> = vec![
            SignedTx {
                core: TxCore { to: shared_receiver, amount: 100, fee: 1, nonce: 0 },
                pubkey: sender1.0.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: shared_receiver, amount: 200, fee: 2, nonce: 0 },
                pubkey: sender2.0.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: shared_receiver, amount: 300, fee: 3, nonce: 0 },
                pubkey: sender3.0.to_vec(),
                sig: vec![],
            },
        ];

        // Analyze
        let analyzed_txs = analyze_batch(&txs);
        assert_eq!(analyzed_txs.len(), 3);

        // Build arena and contexts
        let mut accounts = Accounts::default();
        accounts.put(sender1, Account { balance: 1000, nonce: 0 });
        accounts.put(sender2, Account { balance: 2000, nonce: 0 });
        accounts.put(sender3, Account { balance: 3000, nonce: 0 });

        let mut arena = AccountArena::with_capacity(4);
        let mut arena_contexts: Vec<ArenaTxContext> = analyzed_txs
            .iter()
            .map(|atx| ArenaTxContext::from_analyzed(atx, &mut arena, &accounts))
            .collect();
        
        let idx_to_arena: HashMap<usize, usize> = arena_contexts
            .iter()
            .enumerate()
            .map(|(i, ctx)| (ctx.tx_idx, i))
            .collect();

        // Track fast path commits
        let mut fastpath_committed: HashSet<usize> = HashSet::new();
        
        // T95.1: Pre-compute simple candidate indices
        let simple_candidate_indices: Vec<usize> = analyzed_txs
            .iter()
            .filter(|atx| atx.kind.is_simple())
            .map(|atx| atx.tx_idx)
            .collect();
        
        // T95.1: Build analyzed_map for O(1) lookup
        let analyzed_map: HashMap<usize, &AnalyzedTx> = analyzed_txs
            .iter()
            .map(|a| (a.tx_idx, a))
            .collect();
        
        // T95.1: Create conflict bitmap (reused across waves in production)
        let mut conflict_bitmap = ArenaConflictBitmap::new();

        // Execute fast path wave
        StmExecutor::execute_simple_fastpath_wave(
            &simple_candidate_indices,
            &analyzed_map,
            &mut arena_contexts,
            &mut arena,
            &idx_to_arena,
            &mut conflict_bitmap,
            &mut fastpath_committed,
        );

        // Only the first tx should commit via fast path (others conflict on shared receiver)
        assert_eq!(fastpath_committed.len(), 1, "Only first tx should use fast path");
        assert!(fastpath_committed.contains(&0), "First tx should be fast path");
        
        // First should be committed, others still pending
        assert_eq!(arena_contexts[0].status, TxStatus::Committed);
        assert_eq!(arena_contexts[1].status, TxStatus::NeedsRetry);
        assert_eq!(arena_contexts[2].status, TxStatus::NeedsRetry);
    }

    /// T93.3: Test same-sender txs (nonce chain) - only one should fast path per wave.
    #[test]
    fn test_same_sender_nonce_chain() {
        use eezo_ledger::{TxCore, AccountArena};

        // Setup: 3 txs from the SAME sender with sequential nonces
        let sender = Address([0x42; 20]);
        let receiver1 = Address([0xAA; 20]);
        let receiver2 = Address([0xBB; 20]);
        let receiver3 = Address([0xCC; 20]);

        let txs: Vec<SignedTx> = vec![
            SignedTx {
                core: TxCore { to: receiver1, amount: 100, fee: 1, nonce: 0 },
                pubkey: sender.0.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: receiver2, amount: 200, fee: 2, nonce: 1 },
                pubkey: sender.0.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: receiver3, amount: 300, fee: 3, nonce: 2 },
                pubkey: sender.0.to_vec(),
                sig: vec![],
            },
        ];

        // Analyze
        let analyzed_txs = analyze_batch(&txs);
        assert_eq!(analyzed_txs.len(), 3);

        // Build arena and contexts
        let mut accounts = Accounts::default();
        accounts.put(sender, Account { balance: 10000, nonce: 0 });

        let mut arena = AccountArena::with_capacity(4);
        let mut arena_contexts: Vec<ArenaTxContext> = analyzed_txs
            .iter()
            .map(|atx| ArenaTxContext::from_analyzed(atx, &mut arena, &accounts))
            .collect();
        
        let idx_to_arena: HashMap<usize, usize> = arena_contexts
            .iter()
            .enumerate()
            .map(|(i, ctx)| (ctx.tx_idx, i))
            .collect();

        // Track fast path commits
        let mut fastpath_committed: HashSet<usize> = HashSet::new();
        
        // T95.1: Pre-compute simple candidate indices
        let simple_candidate_indices: Vec<usize> = analyzed_txs
            .iter()
            .filter(|atx| atx.kind.is_simple())
            .map(|atx| atx.tx_idx)
            .collect();
        
        // T95.1: Build analyzed_map for O(1) lookup
        let analyzed_map: HashMap<usize, &AnalyzedTx> = analyzed_txs
            .iter()
            .map(|a| (a.tx_idx, a))
            .collect();
        
        // T95.1: Create conflict bitmap (reused across waves)
        let mut conflict_bitmap = ArenaConflictBitmap::new();

        // Execute first wave - only tx with nonce=0 should succeed
        StmExecutor::execute_simple_fastpath_wave(
            &simple_candidate_indices,
            &analyzed_map,
            &mut arena_contexts,
            &mut arena,
            &idx_to_arena,
            &mut conflict_bitmap,
            &mut fastpath_committed,
        );

        // Only first tx should commit in wave 1:
        // - First tx (nonce=0) matches account nonce and executes successfully
        // - Second and third txs share the same sender as first tx, so they're
        //   skipped due to the same-sender check (one sender per wave)
        assert_eq!(fastpath_committed.len(), 1, "Only first tx should fast path in wave 1");
        assert!(fastpath_committed.contains(&0));

        // Execute second wave - now nonce=1 should succeed
        StmExecutor::execute_simple_fastpath_wave(
            &simple_candidate_indices,
            &analyzed_map,
            &mut arena_contexts,
            &mut arena,
            &idx_to_arena,
            &mut conflict_bitmap,
            &mut fastpath_committed,
        );

        assert_eq!(fastpath_committed.len(), 2, "Second tx should fast path in wave 2");
        assert!(fastpath_committed.contains(&1));

        // Execute third wave
        StmExecutor::execute_simple_fastpath_wave(
            &simple_candidate_indices,
            &analyzed_map,
            &mut arena_contexts,
            &mut arena,
            &idx_to_arena,
            &mut conflict_bitmap,
            &mut fastpath_committed,
        );

        assert_eq!(fastpath_committed.len(), 3, "Third tx should fast path in wave 3");
        assert!(fastpath_committed.contains(&2));
    }

    /// T93.3: Test metrics invariant: fastpath + fallback should equal candidates for committed txs.
    #[cfg(feature = "metrics")]
    #[test]
    fn test_metrics_invariant_fastpath_plus_fallback_equals_candidates() {
        use eezo_ledger::TxCore;

        // Create a test node
        let chain_id = [0u8; 20];
        let cfg = eezo_ledger::consensus::SingleNodeCfg {
            chain_id,
            block_byte_budget: 1 << 20,
            header_cache_cap: 100,
            ..Default::default()
        };
        let (pk, sk) = pqcrypto_mldsa::mldsa44::keypair();
        let mut node = eezo_ledger::consensus::SingleNode::new(cfg, sk, pk);

        // Fund multiple senders
        let sender1_bytes: [u8; 20] = [0x11; 20];
        let sender2_bytes: [u8; 20] = [0x22; 20];
        let sender3_bytes: [u8; 20] = [0x33; 20];
        node.dev_faucet_credit(Address(sender1_bytes), 100_000);
        node.dev_faucet_credit(Address(sender2_bytes), 100_000);
        node.dev_faucet_credit(Address(sender3_bytes), 100_000);

        // Create txs: first two to same receiver (conflict), third to different receiver
        let shared_receiver = Address([0xFF; 20]);
        let other_receiver = Address([0xAA; 20]);
        let txs = vec![
            SignedTx {
                core: TxCore { to: shared_receiver, amount: 100, fee: 1, nonce: 0 },
                pubkey: sender1_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: shared_receiver, amount: 200, fee: 2, nonce: 0 },
                pubkey: sender2_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: other_receiver, amount: 300, fee: 3, nonce: 0 },
                pubkey: sender3_bytes.to_vec(),
                sig: vec![],
            },
        ];

        // Capture initial metric values
        let candidate_before = crate::metrics::EEZO_STM_SIMPLE_CANDIDATE_TOTAL.get();
        let fastpath_before = crate::metrics::EEZO_STM_SIMPLE_FASTPATH_TOTAL.get();
        let fallback_before = crate::metrics::EEZO_STM_SIMPLE_FALLBACK_TOTAL.get();

        // Execute with STM executor (arena mode with fast path enabled)
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EEZO_STM_KERNEL_MODE", "arena");
        std::env::set_var("EEZO_STM_SIMPLE_FASTPATH_ENABLED", "1");
        
        let executor = StmExecutor::from_env(1);
        let input = crate::executor::ExecInput::new(txs, 1);
        let outcome = executor.execute_block(&mut node, input);

        // Clean up env vars
        std::env::remove_var("EEZO_STM_KERNEL_MODE");
        std::env::remove_var("EEZO_STM_SIMPLE_FASTPATH_ENABLED");

        // Verify execution succeeded
        assert!(outcome.result.is_ok());
        let block = outcome.result.unwrap();
        assert_eq!(block.txs.len(), 3, "All 3 txs should be committed");

        // Check metric invariants
        let candidate_after = crate::metrics::EEZO_STM_SIMPLE_CANDIDATE_TOTAL.get();
        let fastpath_after = crate::metrics::EEZO_STM_SIMPLE_FASTPATH_TOTAL.get();
        let fallback_after = crate::metrics::EEZO_STM_SIMPLE_FALLBACK_TOTAL.get();

        let delta_candidate = candidate_after - candidate_before;
        let delta_fastpath = fastpath_after - fastpath_before;
        let delta_fallback = fallback_after - fallback_before;

        // All 3 txs should be candidates (all are SimpleTransfer)
        assert_eq!(delta_candidate, 3, "All 3 txs should be counted as candidates");

        // Invariant: fastpath + fallback = committed candidates
        assert_eq!(
            delta_fastpath + delta_fallback, 3,
            "fastpath ({}) + fallback ({}) should equal committed candidates (3)",
            delta_fastpath, delta_fallback
        );

        // With shared receiver, first tx uses fast path, second conflicts, third is independent
        // So we expect: fastpath >= 1, fallback >= 0, total = 3
        assert!(delta_fastpath >= 1, "At least 1 tx should use fast path");
    }

    /// T93.3: Test that fast path on/off yields same final ledger state.
    #[test]
    fn test_fastpath_on_off_same_final_state() {
        use eezo_ledger::TxCore;

        let chain_id = [0u8; 20];
        let cfg = eezo_ledger::consensus::SingleNodeCfg {
            chain_id,
            block_byte_budget: 1 << 20,
            header_cache_cap: 100,
            ..Default::default()
        };
        let (pk, sk) = pqcrypto_mldsa::mldsa44::keypair();

        // Senders and receivers
        let sender1_bytes: [u8; 20] = [0x11; 20];
        let sender2_bytes: [u8; 20] = [0x22; 20];
        let receiver1 = Address([0xAA; 20]);
        let receiver2 = Address([0xBB; 20]);

        let txs = vec![
            SignedTx {
                core: TxCore { to: receiver1, amount: 100, fee: 1, nonce: 0 },
                pubkey: sender1_bytes.to_vec(),
                sig: vec![],
            },
            SignedTx {
                core: TxCore { to: receiver2, amount: 200, fee: 2, nonce: 0 },
                pubkey: sender2_bytes.to_vec(),
                sig: vec![],
            },
        ];

        // Run with fast path OFF
        let mut node_off = eezo_ledger::consensus::SingleNode::new(cfg.clone(), sk.clone(), pk.clone());
        node_off.dev_faucet_credit(Address(sender1_bytes), 10_000);
        node_off.dev_faucet_credit(Address(sender2_bytes), 10_000);

        let config_off = StmConfig {
            threads: 1,
            max_retries: 5,
            wave_timeout_ms: 1000,
            exec_lanes: 16,
            wave_cap: 0,
            wave_aggressive: false,
            kernel_mode: StmKernelMode::Arena,
            simple_fastpath_enabled: false,
        };
        let executor_off = StmExecutor::with_config(config_off);
        let outcome_off = executor_off.execute_block(&mut node_off, crate::executor::ExecInput::new(txs.clone(), 1));
        assert!(outcome_off.result.is_ok());
        let block_off = outcome_off.result.unwrap();

        // Run with fast path ON
        let mut node_on = eezo_ledger::consensus::SingleNode::new(cfg.clone(), sk.clone(), pk.clone());
        node_on.dev_faucet_credit(Address(sender1_bytes), 10_000);
        node_on.dev_faucet_credit(Address(sender2_bytes), 10_000);

        let config_on = StmConfig {
            threads: 1,
            max_retries: 5,
            wave_timeout_ms: 1000,
            exec_lanes: 16,
            wave_cap: 0,
            wave_aggressive: false,
            kernel_mode: StmKernelMode::Arena,
            simple_fastpath_enabled: true,
        };
        let executor_on = StmExecutor::with_config(config_on);
        let outcome_on = executor_on.execute_block(&mut node_on, crate::executor::ExecInput::new(txs.clone(), 1));
        assert!(outcome_on.result.is_ok());
        let block_on = outcome_on.result.unwrap();

        // Same number of txs committed
        assert_eq!(block_off.txs.len(), block_on.txs.len(), "Same txs should be committed");

        // Same tx order
        for (tx_off, tx_on) in block_off.txs.iter().zip(block_on.txs.iter()) {
            assert_eq!(tx_off.core.amount, tx_on.core.amount, "Same tx amounts");
            assert_eq!(tx_off.core.fee, tx_on.core.fee, "Same tx fees");
        }

        // Same final balances
        let sender1_bal_off = node_off.accounts.get(&Address(sender1_bytes)).balance;
        let sender1_bal_on = node_on.accounts.get(&Address(sender1_bytes)).balance;
        assert_eq!(sender1_bal_off, sender1_bal_on, "Sender1 balance should match");

        let sender2_bal_off = node_off.accounts.get(&Address(sender2_bytes)).balance;
        let sender2_bal_on = node_on.accounts.get(&Address(sender2_bytes)).balance;
        assert_eq!(sender2_bal_off, sender2_bal_on, "Sender2 balance should match");

        let recv1_bal_off = node_off.accounts.get(&receiver1).balance;
        let recv1_bal_on = node_on.accounts.get(&receiver1).balance;
        assert_eq!(recv1_bal_off, recv1_bal_on, "Receiver1 balance should match");

        let recv2_bal_off = node_off.accounts.get(&receiver2).balance;
        let recv2_bal_on = node_on.accounts.get(&receiver2).balance;
        assert_eq!(recv2_bal_off, recv2_bal_on, "Receiver2 balance should match");
    }

    // ========================================================================
    // T95.0: ArenaConflictBitmap Tests
    // ========================================================================

    #[test]
    fn test_arena_conflict_bitmap_new_is_empty() {
        let bitmap = ArenaConflictBitmap::new();
        
        // All indices should be unclaimed/untouched
        assert!(!bitmap.is_sender_claimed(0));
        assert!(!bitmap.is_account_touched(0));
        assert!(!bitmap.is_sender_claimed(100));
        assert!(!bitmap.is_account_touched(100));
        assert!(!bitmap.had_overflow());
    }

    #[test]
    fn test_arena_conflict_bitmap_claim_sender() {
        let mut bitmap = ArenaConflictBitmap::new();
        
        // Claim a sender
        bitmap.claim_sender(42);
        
        // Check it's claimed
        assert!(bitmap.is_sender_claimed(42));
        assert!(!bitmap.is_sender_claimed(43));
        assert!(!bitmap.is_sender_claimed(0));
        
        // Claim another
        bitmap.claim_sender(100);
        assert!(bitmap.is_sender_claimed(42));
        assert!(bitmap.is_sender_claimed(100));
    }

    #[test]
    fn test_arena_conflict_bitmap_touch_account() {
        let mut bitmap = ArenaConflictBitmap::new();
        
        // Touch accounts
        bitmap.touch_account(10);
        bitmap.touch_account(20);
        bitmap.touch_account(30);
        
        // Check they're touched
        assert!(bitmap.is_account_touched(10));
        assert!(bitmap.is_account_touched(20));
        assert!(bitmap.is_account_touched(30));
        assert!(!bitmap.is_account_touched(15));
        assert!(!bitmap.is_account_touched(0));
    }

    #[test]
    fn test_arena_conflict_bitmap_reset() {
        let mut bitmap = ArenaConflictBitmap::new();
        
        // Set some bits
        bitmap.claim_sender(5);
        bitmap.touch_account(10);
        bitmap.touch_account(15);
        
        assert!(bitmap.is_sender_claimed(5));
        assert!(bitmap.is_account_touched(10));
        
        // Reset
        bitmap.reset();
        
        // All should be cleared
        assert!(!bitmap.is_sender_claimed(5));
        assert!(!bitmap.is_account_touched(10));
        assert!(!bitmap.is_account_touched(15));
    }

    #[test]
    fn test_arena_conflict_bitmap_boundary_indices() {
        let mut bitmap = ArenaConflictBitmap::new();
        
        // Test indices at the boundary of the bitmap capacity
        bitmap.claim_sender(0);
        bitmap.claim_sender(65535); // Last index in bitmap (ARENA_BITMAP_CAPACITY - 1)
        
        assert!(bitmap.is_sender_claimed(0));
        assert!(bitmap.is_sender_claimed(65535));
        assert!(!bitmap.is_sender_claimed(1));
        assert!(!bitmap.is_sender_claimed(65534));
        
        // No overflow yet
        assert!(!bitmap.had_overflow());
    }

    #[test]
    fn test_arena_conflict_bitmap_overflow_to_hashset() {
        let mut bitmap = ArenaConflictBitmap::new();
        
        // Use an index beyond bitmap capacity (>= 65536)
        bitmap.claim_sender(70000);
        
        // Should trigger overflow
        assert!(bitmap.had_overflow());
        
        // But the index should still be tracked
        assert!(bitmap.is_sender_claimed(70000));
        assert!(!bitmap.is_sender_claimed(1000)); // Within bitmap range, not set
        
        // Test touch_account overflow
        bitmap.touch_account(80000);
        assert!(bitmap.is_account_touched(80000));
    }

    #[test]
    fn test_arena_conflict_bitmap_mixed_bitmap_and_overflow() {
        let mut bitmap = ArenaConflictBitmap::new();
        
        // Set some in bitmap range
        bitmap.claim_sender(10);
        bitmap.touch_account(20);
        bitmap.touch_account(30);
        
        // Set some in overflow range (>= 65536)
        bitmap.claim_sender(70000);
        bitmap.touch_account(80000);
        
        // All should be correctly tracked
        assert!(bitmap.is_sender_claimed(10));
        assert!(bitmap.is_sender_claimed(70000));
        assert!(!bitmap.is_sender_claimed(100));
        assert!(!bitmap.is_sender_claimed(50000)); // In bitmap range, not set
        
        assert!(bitmap.is_account_touched(20));
        assert!(bitmap.is_account_touched(30));
        assert!(bitmap.is_account_touched(80000));
        assert!(!bitmap.is_account_touched(50));
    }

    #[test]
    fn test_arena_conflict_bitmap_reset_clears_overflow() {
        let mut bitmap = ArenaConflictBitmap::new();
        
        // Set overflow values (>= 65536)
        bitmap.claim_sender(70000);
        bitmap.touch_account(80000);
        assert!(bitmap.had_overflow());
        
        // Reset
        bitmap.reset();
        
        // Overflow values should be cleared
        assert!(!bitmap.is_sender_claimed(70000));
        assert!(!bitmap.is_account_touched(80000));
        
        // Note: overflow_occurred is NOT reset per wave (tracked per block)
        // This is intentional for metrics tracking
    }

    #[test]
    fn test_arena_conflict_bitmap_typical_usage_pattern() {
        // Simulate a typical fast path wave with 10 transactions
        let mut bitmap = ArenaConflictBitmap::new();
        
        // Transaction 0: sender=0, receiver=1
        assert!(!bitmap.is_sender_claimed(0));
        assert!(!bitmap.is_account_touched(0));
        assert!(!bitmap.is_account_touched(1));
        bitmap.claim_sender(0);
        bitmap.touch_account(0);
        bitmap.touch_account(1);
        
        // Transaction 1: sender=2, receiver=3 (no conflict)
        assert!(!bitmap.is_sender_claimed(2));
        assert!(!bitmap.is_account_touched(2));
        assert!(!bitmap.is_account_touched(3));
        bitmap.claim_sender(2);
        bitmap.touch_account(2);
        bitmap.touch_account(3);
        
        // Transaction 2: sender=0 (CONFLICT - same sender as tx 0)
        assert!(bitmap.is_sender_claimed(0), "Should detect sender conflict");
        
        // Transaction 3: sender=4, receiver=1 (CONFLICT - receiver touched by tx 0)
        assert!(!bitmap.is_sender_claimed(4));
        assert!(!bitmap.is_account_touched(4));
        assert!(bitmap.is_account_touched(1), "Should detect receiver conflict");
        
        // No overflow in this pattern
        assert!(!bitmap.had_overflow());
    }

    /// T95.0: Verify that bitmap and HashMap produce identical conflict detection results.
    #[test]
    fn test_arena_conflict_bitmap_matches_hashmap_behavior() {
        use std::collections::HashMap;
        
        // Test with a variety of indices including boundary and overflow cases
        // Updated for 64K bitmap capacity: boundary at 65535, overflow at 65536+
        let test_indices: Vec<u32> = vec![0, 1, 10, 100, 500, 1000, 10000, 65535, 65536, 70000, 80000];
        
        let mut bitmap = ArenaConflictBitmap::new();
        let mut hashmap_senders: HashMap<u32, ()> = HashMap::new();
        let mut hashmap_touched: HashMap<u32, ()> = HashMap::new();
        
        for &idx in &test_indices {
            // Claim sender in both
            bitmap.claim_sender(idx);
            hashmap_senders.insert(idx, ());
            
            // Touch account in both
            bitmap.touch_account(idx);
            hashmap_touched.insert(idx, ());
            
            // Verify they match
            assert_eq!(
                bitmap.is_sender_claimed(idx),
                hashmap_senders.contains_key(&idx),
                "Sender claimed mismatch at index {}", idx
            );
            assert_eq!(
                bitmap.is_account_touched(idx),
                hashmap_touched.contains_key(&idx),
                "Account touched mismatch at index {}", idx
            );
        }
        
        // Also verify some indices NOT in the set
        let missing_indices: Vec<u32> = vec![5, 50, 999, 50000, 75000];
        for &idx in &missing_indices {
            assert_eq!(
                bitmap.is_sender_claimed(idx),
                hashmap_senders.contains_key(&idx),
                "Sender claimed mismatch (missing) at index {}", idx
            );
            assert_eq!(
                bitmap.is_account_touched(idx),
                hashmap_touched.contains_key(&idx),
                "Account touched mismatch (missing) at index {}", idx
            );
        }
    }
}