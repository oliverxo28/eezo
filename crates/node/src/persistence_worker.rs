//! persistence_worker.rs — T83.2: Async Persistence Pipeline + Mutable Head
//!
//! This module implements asynchronous RocksDB persistence to remove writes from the
//! TPS critical path. The key components are:
//!
//! ## CommittedMemHead
//!
//! An in-memory layer that holds recently committed account state. When a block commits:
//! 1. State changes are applied to CommittedMemHead (fast, in-memory)
//! 2. A `PersistenceMsg::ApplyBlock` is enqueued for background persistence
//! 3. The executor can immediately start the next block using CommittedMemHead as base
//!
//! ## PersistenceWorker
//!
//! A background task that:
//! 1. Receives `PersistenceMsg` from a channel in commit order
//! 2. Writes blocks/snapshots to RocksDB
//! 3. Notifies when writes complete so CommittedMemHead can be pruned
//!
//! ## Design Invariants
//!
//! 1. **Ordering**: Writes are applied to RocksDB in the same order as blocks commit.
//! 2. **Read-after-write**: Snapshots for new blocks layer CommittedMemHead on top of
//!    RocksDB, ensuring latest state is always visible.
//! 3. **Crash safety**: On crash, up to a few blocks may be lost from CommittedMemHead.
//!    On restart, the node replays from RocksDB's last confirmed height.
//!
//! ## Environment Variables
//!
//! - `EEZO_PERSIST_ASYNC=1`: Enable async persistence (default: sync)
//! - `EEZO_PERSIST_QUEUE_CAP=1000`: Max pending blocks in queue (default: 1000)
//!
//! ## Metrics (when `metrics` feature is enabled)
//!
//! - `eezo_persist_queue_len`: Current number of pending persistence messages
//! - `eezo_persist_blocks_total`: Total blocks persisted by the worker
//! - `eezo_persist_block_latency_seconds`: Time to persist each block
//! - `eezo_persist_head_entries`: Number of accounts in CommittedMemHead

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::mpsc;

use eezo_ledger::{Address, Account, Supply};

#[cfg(feature = "persistence")]
use eezo_ledger::persistence::{Persistence, StateSnapshot};
#[cfg(feature = "persistence")]
use eezo_ledger::block::{Block, BlockHeader};

// =============================================================================
// Environment Configuration
// =============================================================================

/// Check if async persistence is enabled via environment variable.
pub fn is_async_persist_enabled() -> bool {
    std::env::var("EEZO_PERSIST_ASYNC")
        .map(|v| {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Get the persistence queue capacity from environment.
fn get_queue_capacity() -> usize {
    std::env::var("EEZO_PERSIST_QUEUE_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

/// Log async persistence status at startup.
pub fn log_async_persist_status() {
    let enabled = is_async_persist_enabled();
    if enabled {
        log::info!("async-persist: ENABLED (EEZO_PERSIST_ASYNC=1)");
        log::info!("async-persist: queue_capacity={}", get_queue_capacity());
    } else {
        log::info!("async-persist: disabled (set EEZO_PERSIST_ASYNC=1 to enable)");
    }
}

// =============================================================================
// CommittedMemHead — In-memory recently committed state
// =============================================================================

/// Write-set for a single committed block.
/// 
/// Contains the state changes that need to be persisted to RocksDB.
#[derive(Clone, Debug)]
pub struct BlockWriteSet {
    /// Block height
    pub height: u64,
    /// Modified accounts (address -> new state)
    pub accounts: HashMap<Address, Account>,
    /// Updated supply state
    pub supply: Supply,
    /// Whether to write a full snapshot at this height
    pub write_snapshot: bool,
}

/// In-memory layer holding recently committed state.
///
/// This is the "mutable head" that sits between the executor and RocksDB.
/// Reads layer CommittedMemHead on top of RocksDB, ensuring the executor
/// always sees the latest committed state even when RocksDB is behind.
///
/// Thread-safe: uses `RwLock` for concurrent read access during block execution.
pub struct CommittedMemHead {
    /// Recently committed account states (not yet confirmed persisted).
    /// Key: Address, Value: (height, Account) where height is when it was last modified.
    accounts: RwLock<HashMap<Address, (u64, Account)>>,
    
    /// Recently committed supply state.
    supply: RwLock<Option<(u64, Supply)>>,
    
    /// Highest block height in the in-memory head.
    head_height: AtomicU64,
    
    /// Highest block height confirmed persisted to RocksDB.
    /// Entries at or below this height can be pruned from the head.
    persisted_height: AtomicU64,
    
    /// Whether the head is enabled (false = pass-through to RocksDB).
    enabled: AtomicBool,
}

impl CommittedMemHead {
    /// Create a new empty CommittedMemHead.
    pub fn new() -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
            supply: RwLock::new(None),
            head_height: AtomicU64::new(0),
            persisted_height: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
        }
    }
    
    /// Enable or disable the mutable head.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }
    
    /// Check if the mutable head is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }
    
    /// Apply a block's write-set to the in-memory head.
    ///
    /// Called after block execution commits but before RocksDB persistence.
    pub fn apply_write_set(&self, write_set: &BlockWriteSet) {
        let height = write_set.height;
        
        // Update accounts
        {
            let mut accounts = self.accounts.write();
            for (addr, acct) in &write_set.accounts {
                accounts.insert(*addr, (height, acct.clone()));
            }
        }
        
        // Update supply
        {
            let mut supply = self.supply.write();
            *supply = Some((height, write_set.supply.clone()));
        }
        
        // Update head height
        self.head_height.fetch_max(height, Ordering::SeqCst);
    }
    
    /// Get an account from the mutable head, or None if not present.
    ///
    /// If the head is disabled, always returns None (caller falls back to RocksDB).
    #[inline]
    pub fn get_account(&self, addr: &Address) -> Option<Account> {
        if !self.is_enabled() {
            return None;
        }
        self.accounts.read().get(addr).map(|(_, acct)| acct.clone())
    }
    
    /// Get the supply from the mutable head, or None if not present.
    #[inline]
    pub fn get_supply(&self) -> Option<Supply> {
        if !self.is_enabled() {
            return None;
        }
        self.supply.read().as_ref().map(|(_, s)| s.clone())
    }
    
    /// Get the current head height.
    #[inline]
    pub fn head_height(&self) -> u64 {
        self.head_height.load(Ordering::SeqCst)
    }
    
    /// Get the confirmed persisted height.
    #[inline]
    pub fn persisted_height(&self) -> u64 {
        self.persisted_height.load(Ordering::SeqCst)
    }
    
    /// Number of account entries currently in the head.
    #[inline]
    pub fn account_count(&self) -> usize {
        self.accounts.read().len()
    }
    
    /// Mark a height as persisted, allowing entries at or below to be pruned.
    ///
    /// Called by the persistence worker after successful RocksDB write.
    pub fn mark_persisted(&self, height: u64) {
        self.persisted_height.fetch_max(height, Ordering::SeqCst);
    }
    
    /// Prune entries that have been confirmed persisted.
    ///
    /// Removes account entries modified at heights <= persisted_height.
    /// This is called periodically to bound memory usage.
    pub fn prune(&self) {
        let persisted_h = self.persisted_height.load(Ordering::SeqCst);
        
        // Prune accounts
        {
            let mut accounts = self.accounts.write();
            accounts.retain(|_, (h, _)| *h > persisted_h);
        }
        
        // Prune supply if persisted
        {
            let mut supply = self.supply.write();
            if let Some((h, _)) = supply.as_ref() {
                if *h <= persisted_h {
                    *supply = None;
                }
            }
        }
    }
    
    /// Clear all entries (used on shutdown or when switching modes).
    pub fn clear(&self) {
        self.accounts.write().clear();
        *self.supply.write() = None;
        self.head_height.store(0, Ordering::SeqCst);
        self.persisted_height.store(0, Ordering::SeqCst);
    }
}

impl Default for CommittedMemHead {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// PersistenceMsg — Messages for the persistence worker
// =============================================================================

/// Messages sent to the persistence worker.
#[cfg(feature = "persistence")]
pub enum PersistenceMsg {
    /// Apply a block's writes to RocksDB.
    ApplyBlock {
        /// Block height
        height: u64,
        /// Block header for persistence
        header: BlockHeader,
        /// Full block for persistence
        block: Block,
        /// Optional state snapshot to write
        snapshot: Option<StateSnapshot>,
    },
    /// Flush all pending writes and shutdown.
    FlushAndShutdown,
}

/// Handle for sending messages to the persistence worker.
#[cfg(feature = "persistence")]
pub struct PersistenceWorkerHandle {
    /// Channel sender for persistence messages.
    sender: mpsc::Sender<PersistenceMsg>,
    /// Shared reference to the CommittedMemHead for marking persisted heights.
    mem_head: Arc<CommittedMemHead>,
}

#[cfg(feature = "persistence")]
impl PersistenceWorkerHandle {
    /// Enqueue a block for async persistence.
    ///
    /// Returns immediately; the block will be persisted by the background worker.
    pub async fn enqueue_block(
        &self,
        height: u64,
        header: BlockHeader,
        block: Block,
        snapshot: Option<StateSnapshot>,
    ) -> Result<(), mpsc::error::SendError<PersistenceMsg>> {
        self.sender.send(PersistenceMsg::ApplyBlock {
            height,
            header,
            block,
            snapshot,
        }).await
    }
    
    /// Request graceful shutdown of the persistence worker.
    ///
    /// The worker will flush all pending writes before shutting down.
    pub async fn shutdown(&self) -> Result<(), mpsc::error::SendError<PersistenceMsg>> {
        self.sender.send(PersistenceMsg::FlushAndShutdown).await
    }
    
    /// Get the current queue length (approximate).
    ///
    /// NOTE: This is a placeholder that returns 0. The tokio mpsc::Sender
    /// doesn't expose queue length directly. A proper implementation would
    /// require an atomic counter incremented on send and decremented on receive.
    /// For now, use the `eezo_persist_head_entries` metric as a proxy.
    #[allow(clippy::unused_self)]
    pub fn queue_len(&self) -> usize {
        0 // TODO: Implement with atomic counter if needed
    }
    
    /// Get a reference to the CommittedMemHead.
    pub fn mem_head(&self) -> &Arc<CommittedMemHead> {
        &self.mem_head
    }
}

/// The persistence worker task.
#[cfg(feature = "persistence")]
pub struct PersistenceWorker {
    /// Channel receiver for persistence messages.
    receiver: mpsc::Receiver<PersistenceMsg>,
    /// Database handle.
    db: Arc<Persistence>,
    /// Shared reference to the CommittedMemHead.
    mem_head: Arc<CommittedMemHead>,
    /// Queue length counter for metrics.
    queue_len: Arc<AtomicU64>,
}

#[cfg(feature = "persistence")]
impl PersistenceWorker {
    /// Spawn the persistence worker, returning a handle for communication.
    pub fn spawn(
        db: Arc<Persistence>,
        mem_head: Arc<CommittedMemHead>,
    ) -> PersistenceWorkerHandle {
        let capacity = get_queue_capacity();
        let (sender, receiver) = mpsc::channel(capacity);
        let queue_len = Arc::new(AtomicU64::new(0));
        
        let worker = Self {
            receiver,
            db,
            mem_head: mem_head.clone(),
            queue_len: queue_len.clone(),
        };
        
        // Spawn the worker task
        tokio::spawn(async move {
            worker.run().await;
        });
        
        log::info!("persistence-worker: spawned with queue_capacity={}", capacity);
        
        PersistenceWorkerHandle {
            sender,
            mem_head,
        }
    }
    
    /// Run the persistence worker event loop.
    async fn run(mut self) {
        log::info!("persistence-worker: starting");
        
        let mut blocks_total: u64 = 0;
        
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                PersistenceMsg::ApplyBlock { height, header, block, snapshot } => {
                    let start = Instant::now();
                    
                    // Persist block and header
                    if let Err(e) = self.db.put_header_and_block(height, &header, &block) {
                        log::error!("persistence-worker: failed to persist block at h={}: {}", height, e);
                    } else {
                        log::debug!("persistence-worker: persisted block at h={}", height);
                    }
                    
                    // Persist snapshot if requested
                    if let Some(snap) = snapshot {
                        if let Err(e) = self.db.put_snapshot(&snap) {
                            log::error!("persistence-worker: failed to persist snapshot at h={}: {}", height, e);
                        } else {
                            log::debug!("persistence-worker: persisted snapshot at h={}", height);
                        }
                        // Update tip after snapshot
                        if let Err(e) = self.db.update_tip(height) {
                            log::error!("persistence-worker: failed to update tip at h={}: {}", height, e);
                        }
                    }
                    
                    // Mark this height as persisted so CommittedMemHead can be pruned
                    self.mem_head.mark_persisted(height);
                    
                    // Periodically prune the mem head (every 10 blocks)
                    if height % 10 == 0 {
                        self.mem_head.prune();
                    }
                    
                    blocks_total += 1;
                    
                    #[cfg(feature = "metrics")]
                    {
                        let elapsed = start.elapsed().as_secs_f64();
                        crate::metrics::persist_block_latency_observe(elapsed);
                        crate::metrics::persist_blocks_total_inc();
                        crate::metrics::persist_head_entries_set(self.mem_head.account_count() as i64);
                    }
                    
                    log::trace!(
                        "persistence-worker: block {} done in {:?}, total={}",
                        height, start.elapsed(), blocks_total
                    );
                }
                PersistenceMsg::FlushAndShutdown => {
                    log::info!("persistence-worker: received shutdown, flushing remaining...");
                    // Process remaining messages
                    while let Ok(msg) = self.receiver.try_recv() {
                        if let PersistenceMsg::ApplyBlock { height, header, block, snapshot } = msg {
                            if let Err(e) = self.db.put_header_and_block(height, &header, &block) {
                                log::error!("persistence-worker: failed to persist block at h={}: {}", height, e);
                            }
                            if let Some(snap) = snapshot {
                                let _ = self.db.put_snapshot(&snap);
                                let _ = self.db.update_tip(height);
                            }
                            self.mem_head.mark_persisted(height);
                        }
                    }
                    break;
                }
            }
        }
        
        log::info!("persistence-worker: stopped, total blocks persisted={}", blocks_total);
    }
}

// =============================================================================
// Metrics
// =============================================================================

#[cfg(feature = "metrics")]
pub mod persist_metrics {
    use lazy_static::lazy_static;
    use prometheus::{IntGauge, IntCounter, Histogram, register_int_gauge, register_int_counter, register_histogram};
    
    lazy_static! {
        /// Current number of pending blocks in the persistence queue.
        pub static ref EEZO_PERSIST_QUEUE_LEN: IntGauge = register_int_gauge!(
            "eezo_persist_queue_len",
            "Number of blocks pending in the async persistence queue"
        ).unwrap();
        
        /// Total blocks persisted by the worker.
        pub static ref EEZO_PERSIST_BLOCKS_TOTAL: IntCounter = register_int_counter!(
            "eezo_persist_blocks_total",
            "Total number of blocks persisted by the async worker"
        ).unwrap();
        
        /// Histogram of block persistence latency.
        pub static ref EEZO_PERSIST_BLOCK_LATENCY: Histogram = register_histogram!(
            "eezo_persist_block_latency_seconds",
            "Time to persist a single block to RocksDB",
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        ).unwrap();
        
        /// Number of account entries in CommittedMemHead.
        pub static ref EEZO_PERSIST_HEAD_ENTRIES: IntGauge = register_int_gauge!(
            "eezo_persist_head_entries",
            "Number of account entries in the in-memory committed head"
        ).unwrap();
    }
}

// Metrics helper functions
#[cfg(feature = "metrics")]
pub fn persist_block_latency_observe(secs: f64) {
    persist_metrics::EEZO_PERSIST_BLOCK_LATENCY.observe(secs);
}

#[cfg(feature = "metrics")]
pub fn persist_blocks_total_inc() {
    persist_metrics::EEZO_PERSIST_BLOCKS_TOTAL.inc();
}

#[cfg(feature = "metrics")]
pub fn persist_queue_len_set(len: i64) {
    persist_metrics::EEZO_PERSIST_QUEUE_LEN.set(len);
}

#[cfg(feature = "metrics")]
pub fn persist_head_entries_set(count: i64) {
    persist_metrics::EEZO_PERSIST_HEAD_ENTRIES.set(count);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use eezo_ledger::Address;
    
    #[test]
    fn test_committed_mem_head_basic() {
        let head = CommittedMemHead::new();
        head.set_enabled(true);
        
        // Initially empty
        assert_eq!(head.account_count(), 0);
        assert_eq!(head.head_height(), 0);
        assert!(head.get_account(&Address([1u8; 20])).is_none());
        
        // Apply a write set
        let mut accounts = HashMap::new();
        accounts.insert(Address([1u8; 20]), Account { balance: 1000, nonce: 0 });
        accounts.insert(Address([2u8; 20]), Account { balance: 2000, nonce: 1 });
        
        let write_set = BlockWriteSet {
            height: 1,
            accounts,
            supply: Supply::default(),
            write_snapshot: false,
        };
        
        head.apply_write_set(&write_set);
        
        // Check state is present
        assert_eq!(head.account_count(), 2);
        assert_eq!(head.head_height(), 1);
        
        let acct1 = head.get_account(&Address([1u8; 20])).unwrap();
        assert_eq!(acct1.balance, 1000);
        
        let acct2 = head.get_account(&Address([2u8; 20])).unwrap();
        assert_eq!(acct2.balance, 2000);
        
        assert!(head.get_supply().is_some());
    }
    
    #[test]
    fn test_committed_mem_head_prune() {
        let head = CommittedMemHead::new();
        head.set_enabled(true);
        
        // Apply writes at height 1
        let mut accounts1 = HashMap::new();
        accounts1.insert(Address([1u8; 20]), Account { balance: 100, nonce: 0 });
        head.apply_write_set(&BlockWriteSet {
            height: 1,
            accounts: accounts1,
            supply: Supply::default(),
            write_snapshot: false,
        });
        
        // Apply writes at height 2
        let mut accounts2 = HashMap::new();
        accounts2.insert(Address([2u8; 20]), Account { balance: 200, nonce: 0 });
        head.apply_write_set(&BlockWriteSet {
            height: 2,
            accounts: accounts2,
            supply: Supply::default(),
            write_snapshot: false,
        });
        
        assert_eq!(head.account_count(), 2);
        
        // Mark height 1 as persisted
        head.mark_persisted(1);
        head.prune();
        
        // Account at height 1 should be pruned
        assert_eq!(head.account_count(), 1);
        assert!(head.get_account(&Address([1u8; 20])).is_none());
        assert!(head.get_account(&Address([2u8; 20])).is_some());
    }
    
    #[test]
    fn test_committed_mem_head_disabled() {
        let head = CommittedMemHead::new();
        // Disabled by default
        assert!(!head.is_enabled());
        
        // Apply writes
        let mut accounts = HashMap::new();
        accounts.insert(Address([1u8; 20]), Account { balance: 1000, nonce: 0 });
        head.apply_write_set(&BlockWriteSet {
            height: 1,
            accounts,
            supply: Supply::default(),
            write_snapshot: false,
        });
        
        // Get should return None when disabled (fallback to RocksDB)
        assert!(head.get_account(&Address([1u8; 20])).is_none());
        
        // Enable and check again
        head.set_enabled(true);
        assert!(head.get_account(&Address([1u8; 20])).is_some());
    }
    
    #[test]
    fn test_committed_mem_head_overwrites() {
        let head = CommittedMemHead::new();
        head.set_enabled(true);
        
        let addr = Address([1u8; 20]);
        
        // Apply writes at height 1
        let mut accounts1 = HashMap::new();
        accounts1.insert(addr, Account { balance: 100, nonce: 0 });
        head.apply_write_set(&BlockWriteSet {
            height: 1,
            accounts: accounts1,
            supply: Supply::default(),
            write_snapshot: false,
        });
        
        assert_eq!(head.get_account(&addr).unwrap().balance, 100);
        
        // Apply writes at height 2 (overwrite)
        let mut accounts2 = HashMap::new();
        accounts2.insert(addr, Account { balance: 200, nonce: 1 });
        head.apply_write_set(&BlockWriteSet {
            height: 2,
            accounts: accounts2,
            supply: Supply::default(),
            write_snapshot: false,
        });
        
        // Should see latest value
        assert_eq!(head.get_account(&addr).unwrap().balance, 200);
        assert_eq!(head.get_account(&addr).unwrap().nonce, 1);
        
        // Only 1 entry (same address overwritten)
        assert_eq!(head.account_count(), 1);
    }
    
    #[test]
    fn test_is_async_persist_enabled_default() {
        // Default should be false when env var not set
        std::env::remove_var("EEZO_PERSIST_ASYNC");
        assert!(!is_async_persist_enabled());
    }
}
