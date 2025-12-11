// crates/node/src/mempool_actor.rs
//! T82.2: Mempool "Lock-Free Actor" implementation.
//!
//! This module implements an Actor-based mempool that:
//! - Eliminates lock contention on the internal queues
//! - Uses bucketed structure (virtual sharding) by sender address hash
//! - Tracks in-flight transactions to avoid zombie tx reuse
//! - Supports prefetch for building batches ahead of time
//!
//! The actor owns all mempool state and communicates via async channels.
//! Other parts of the node send messages instead of locking the mempool directly.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    sync::Arc,
    time::Instant,
};

use tokio::sync::{mpsc, oneshot};

#[cfg(feature = "metrics")]
use crate::metrics::{EEZO_MEMPOOL_BYTES, EEZO_MEMPOOL_LEN, EEZO_TX_REJECTED_TOTAL};

/// 32-byte transaction hash.
pub type TxHash = [u8; 32];

/// 20-byte sender address (first 20 bytes of pubkey hash).
pub type SenderAddress = [u8; 20];

/// Number of buckets for virtual sharding (power of 2 for fast modulo).
const NUM_BUCKETS: usize = 256;

/// Default in-flight expiry in seconds (after which in-flight txs are returned to ready).
const IN_FLIGHT_EXPIRY_SECS: u64 = 30;

// ============================================================================
// Core types
// ============================================================================

// T83.4: Import SharedTx for zero-copy tx propagation
use crate::tx_decode_pool::SharedTx;

/// Runtime view of a transaction stored in the mempool.
/// 
/// T83.4: Now includes an optional `Arc<SharedTx>` for zero-copy pipeline.
/// When present, downstream consumers can use the pre-parsed transaction
/// without re-decoding from bytes.
#[derive(Debug, Clone)]
pub struct TxEntry {
    pub hash: TxHash,
    pub sender: SenderAddress,
    pub bytes: Arc<Vec<u8>>,
    pub received_at: Instant,
    pub requeue_count: u32,
    pub nonce: u64,
    pub fee: u64,
    /// T83.4: Optional shared, pre-parsed transaction for zero-copy pipeline.
    /// When set, consumers can use this directly instead of re-parsing bytes.
    pub shared_tx: Option<Arc<SharedTx>>,
}

impl TxEntry {
    /// T83.4: Create a new TxEntry with a pre-parsed SharedTx.
    /// 
    /// This is the preferred constructor for the zero-copy pipeline.
    /// The sender, hash, nonce, and fee are extracted from the SharedTx,
    /// ensuring consistency and avoiding duplicate computation.
    pub fn from_shared_tx(
        shared_tx: Arc<SharedTx>,
        bytes: Vec<u8>,
        received_at: Instant,
    ) -> Self {
        let hash = shared_tx.hash();
        let sender_addr = shared_tx.sender()
            .map(|a| a.0)
            .unwrap_or([0u8; 20]);
        let nonce = shared_tx.core().nonce;
        // T83.4: Convert u128 fee to u64 for priority ordering (saturation on overflow)
        let fee = if shared_tx.core().fee > u64::MAX as u128 {
            u64::MAX
        } else {
            shared_tx.core().fee as u64
        };

        Self {
            hash,
            sender: sender_addr,
            bytes: Arc::new(bytes),
            received_at,
            requeue_count: 0,
            nonce,
            fee,
            shared_tx: Some(shared_tx),
        }
    }

    /// T83.4: Check if this entry has a pre-parsed SharedTx.
    #[inline]
    pub fn has_shared_tx(&self) -> bool {
        self.shared_tx.is_some()
    }

    /// T83.4: Get the pre-parsed SharedTx if available.
    #[inline]
    pub fn get_shared_tx(&self) -> Option<&Arc<SharedTx>> {
        self.shared_tx.as_ref()
    }
}

/// Public status exposed to `/tx/{hash}`.
#[derive(Debug, Clone)]
pub enum TxStatus {
    Pending,
    InFlight,
    Included { block_height: u64 },
    Rejected { error: String },
}

/// Error type for submit operations.
#[derive(Debug)]
pub enum SubmitError {
    RateLimited,
    QueueFull,
    BytesCapReached,
    Duplicate,
    ActorClosed,
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::RateLimited => write!(f, "rate limited"),
            SubmitError::QueueFull => write!(f, "mempool full"),
            SubmitError::BytesCapReached => write!(f, "mempool byte cap reached"),
            SubmitError::Duplicate => write!(f, "duplicate transaction"),
            SubmitError::ActorClosed => write!(f, "mempool actor closed"),
        }
    }
}
impl std::error::Error for SubmitError {}

/// Response for GetBatch request.
#[derive(Debug)]
pub struct BatchResponse {
    /// Transactions in the batch (in priority order).
    pub txs: Vec<Arc<TxEntry>>,
    /// Total size in bytes.
    pub total_bytes: usize,
}

// ============================================================================
// Actor messages
// ============================================================================

/// Messages that can be sent to the mempool actor.
pub enum MempoolMsg {
    /// Submit a new transaction.
    Submit {
        ip: IpAddr,
        entry: TxEntry,
        reply: oneshot::Sender<Result<(), SubmitError>>,
    },
    /// Get a batch of transactions for block building.
    GetBatch {
        max_bytes: usize,
        max_txs: usize,
        reply: oneshot::Sender<BatchResponse>,
    },
    /// Prefetch a batch (prepare ahead of time).
    Prefetch {
        max_bytes: usize,
        max_txs: usize,
    },
    /// Notify that a block was committed with these transaction hashes.
    OnBlockCommit {
        height: u64,
        applied_txs: Vec<TxHash>,
    },
    /// Return in-flight txs back to ready queues (on rollback/failure).
    ReturnInFlight {
        tx_hashes: Vec<TxHash>,
    },
    /// Get status of a transaction.
    GetStatus {
        hash: TxHash,
        reply: oneshot::Sender<Option<TxStatus>>,
    },
    /// Get mempool stats (len, bytes, max_len, max_bytes).
    GetStats {
        reply: oneshot::Sender<MempoolStats>,
    },
    /// Shutdown the actor.
    Shutdown,
}

/// Mempool statistics.
#[derive(Debug, Clone)]
pub struct MempoolStats {
    pub len: usize,
    pub cur_bytes: usize,
    pub max_len: usize,
    pub max_bytes: usize,
    pub in_flight_count: usize,
    pub bucket_count: usize,
}

// ============================================================================
// Internal bucket structure
// ============================================================================

/// A single bucket in the virtual-sharded mempool.
/// Each bucket holds transactions for senders whose address hash maps to this bucket.
#[derive(Debug, Default)]
struct MempoolBucket {
    /// Transactions in this bucket, ordered by (fee desc, received_at asc).
    queue: VecDeque<Arc<TxEntry>>,
}

/// Simple token-bucket per IP for rate limiting.
#[derive(Debug, Clone)]
struct RateBucket {
    capacity: u32,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl RateBucket {
    fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_per_sec,
            last_refill: Instant::now(),
        }
    }

    fn allow(&mut self, cost: u32) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity as f64);
            self.last_refill = now;
        }
        if self.tokens >= cost as f64 {
            self.tokens -= cost as f64;
            true
        } else {
            false
        }
    }
}

/// In-flight entry with timestamp for expiry.
#[derive(Debug)]
struct InFlightEntry {
    entry: Arc<TxEntry>,
    reserved_at: Instant,
}

// ============================================================================
// MempoolActor
// ============================================================================

/// Configuration for the mempool actor.
#[derive(Debug, Clone)]
pub struct MempoolActorConfig {
    pub max_len: usize,
    pub max_bytes: usize,
    pub rate_bucket_capacity: u32,
    pub rate_refill_per_minute: u32,
    pub in_flight_expiry_secs: u64,
}

impl Default for MempoolActorConfig {
    fn default() -> Self {
        Self {
            max_len: 10_000,
            max_bytes: 10 * 1024 * 1024, // 10 MB
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 600,
            in_flight_expiry_secs: IN_FLIGHT_EXPIRY_SECS,
        }
    }
}

/// The mempool actor that owns all internal state.
pub struct MempoolActor {
    /// Bucketed queues by sender address hash.
    buckets: Vec<MempoolBucket>,
    /// Index from tx hash to bucket index (for fast lookup).
    hash_to_bucket: HashMap<TxHash, usize>,
    /// In-flight transactions (reserved for a pending block).
    in_flight: HashMap<TxHash, InFlightEntry>,
    /// Transaction statuses (survives even after tx is removed).
    statuses: HashMap<TxHash, TxStatus>,
    /// Current byte count.
    cur_bytes: usize,
    /// Total pending transaction count (maintained for O(1) access).
    total_len: usize,
    /// Configuration.
    config: MempoolActorConfig,
    /// Per-IP rate buckets.
    ip_buckets: HashMap<IpAddr, RateBucket>,
    /// Prefetched batch (if any).
    prefetched: Option<BatchResponse>,
    /// Channel receiver for messages.
    receiver: mpsc::Receiver<MempoolMsg>,
}

impl MempoolActor {
    /// Create a new mempool actor.
    pub fn new(config: MempoolActorConfig, receiver: mpsc::Receiver<MempoolMsg>) -> Self {
        let mut buckets = Vec::with_capacity(NUM_BUCKETS);
        for _ in 0..NUM_BUCKETS {
            buckets.push(MempoolBucket::default());
        }

        Self {
            buckets,
            hash_to_bucket: HashMap::new(),
            in_flight: HashMap::new(),
            statuses: HashMap::new(),
            cur_bytes: 0,
            total_len: 0,
            config,
            ip_buckets: HashMap::new(),
            prefetched: None,
            receiver,
        }
    }

    /// Get the total number of pending transactions (O(1)).
    #[inline]
    fn len(&self) -> usize {
        self.total_len
    }

    /// Run the actor event loop.
    pub async fn run(mut self) {
        log::info!(
            "mempool-actor: starting (max_len={}, max_bytes={}, buckets={})",
            self.config.max_len,
            self.config.max_bytes,
            NUM_BUCKETS
        );

        while let Some(msg) = self.receiver.recv().await {
            match msg {
                MempoolMsg::Submit { ip, entry, reply } => {
                    let result = self.handle_submit(ip, entry);
                    let _ = reply.send(result);
                }
                MempoolMsg::GetBatch { max_bytes, max_txs, reply } => {
                    let response = self.handle_get_batch(max_bytes, max_txs);
                    let _ = reply.send(response);
                }
                MempoolMsg::Prefetch { max_bytes, max_txs } => {
                    self.handle_prefetch(max_bytes, max_txs);
                }
                MempoolMsg::OnBlockCommit { height, applied_txs } => {
                    self.handle_block_commit(height, &applied_txs);
                }
                MempoolMsg::ReturnInFlight { tx_hashes } => {
                    self.handle_return_in_flight(&tx_hashes);
                }
                MempoolMsg::GetStatus { hash, reply } => {
                    let status = self.statuses.get(&hash).cloned();
                    let _ = reply.send(status);
                }
                MempoolMsg::GetStats { reply } => {
                    let stats = self.get_stats();
                    let _ = reply.send(stats);
                }
                MempoolMsg::Shutdown => {
                    log::info!("mempool-actor: shutting down");
                    break;
                }
            }

            // Periodically expire old in-flight entries
            self.expire_in_flight();
        }

        log::info!("mempool-actor: stopped");
    }

    /// Get bucket index for a sender address using proper hashing.
    /// 
    /// Uses FNV-1a inspired mixing for better distribution across buckets.
    #[inline]
    fn bucket_index(sender: &SenderAddress) -> usize {
        // FNV-1a-inspired mixing for better distribution
        // Uses multiple bytes to avoid patterns in first byte
        let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
        for &byte in sender.iter() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3); // FNV prime
        }
        (hash as usize) % NUM_BUCKETS
    }

    /// Handle submit message.
    fn handle_submit(&mut self, ip: IpAddr, entry: TxEntry) -> Result<(), SubmitError> {
        // Check for duplicates
        if self.hash_to_bucket.contains_key(&entry.hash) || self.in_flight.contains_key(&entry.hash) {
            return Err(SubmitError::Duplicate);
        }
        if self.statuses.contains_key(&entry.hash) {
            return Err(SubmitError::Duplicate);
        }

        // Rate limit check
        let bucket = self.ip_buckets.entry(ip).or_insert_with(|| {
            RateBucket::new(
                self.config.rate_bucket_capacity,
                self.config.rate_refill_per_minute as f64 / 60.0,
            )
        });
        if !bucket.allow(1) {
            return Err(SubmitError::RateLimited);
        }

        // Capacity checks (O(1) using total_len counter)
        if self.total_len >= self.config.max_len {
            return Err(SubmitError::QueueFull);
        }

        let entry_bytes = entry.bytes.len();
        if self.cur_bytes + entry_bytes > self.config.max_bytes {
            return Err(SubmitError::BytesCapReached);
        }

        // Insert into bucket
        let bucket_idx = Self::bucket_index(&entry.sender);
        let entry_arc = Arc::new(entry.clone());
        
        self.buckets[bucket_idx].queue.push_back(entry_arc);
        self.hash_to_bucket.insert(entry.hash, bucket_idx);
        self.statuses.insert(entry.hash, TxStatus::Pending);
        self.cur_bytes += entry_bytes;
        self.total_len += 1;

        // Invalidate prefetch (new tx may change optimal batch)
        self.prefetched = None;

        #[cfg(feature = "metrics")]
        self.refresh_gauges();

        log::debug!(
            "mempool-actor: submitted tx hash=0x{} bucket={} total_len={}",
            hex::encode(&entry.hash[..4]),
            bucket_idx,
            self.total_len
        );

        Ok(())
    }

    /// Handle get batch message.
    fn handle_get_batch(&mut self, max_bytes: usize, max_txs: usize) -> BatchResponse {
        // Check if we have a valid prefetched batch
        if let Some(prefetched) = self.prefetched.take() {
            if prefetched.total_bytes <= max_bytes && prefetched.txs.len() <= max_txs {
                // Move prefetched txs to in-flight
                for tx in &prefetched.txs {
                    self.move_to_in_flight(tx.clone());
                }
                return prefetched;
            }
        }

        // Build a new batch
        self.build_batch(max_bytes, max_txs)
    }

    /// Build a batch from ready queues.
    fn build_batch(&mut self, max_bytes: usize, max_txs: usize) -> BatchResponse {
        let mut txs = Vec::new();
        let mut total_bytes = 0;

        // Collect candidates from all buckets (round-robin for fairness)
        let mut candidates: Vec<Arc<TxEntry>> = Vec::new();
        for bucket in &self.buckets {
            candidates.extend(bucket.queue.iter().cloned());
        }

        // Sort by fee (descending), then by received_at (ascending)
        candidates.sort_by(|a, b| {
            b.fee.cmp(&a.fee)
                .then_with(|| a.received_at.cmp(&b.received_at))
        });

        // Pick txs up to limits
        for entry in candidates {
            // Skip if already in-flight (shouldn't happen, but defensive)
            if self.in_flight.contains_key(&entry.hash) {
                continue;
            }

            let entry_bytes = entry.bytes.len();
            if txs.len() >= max_txs {
                break;
            }
            if total_bytes + entry_bytes > max_bytes && !txs.is_empty() {
                break;
            }

            // Move to in-flight
            self.move_to_in_flight(entry.clone());

            total_bytes += entry_bytes;
            txs.push(entry);
        }

        log::debug!(
            "mempool-actor: built batch with {} txs, {} bytes",
            txs.len(),
            total_bytes
        );

        BatchResponse { txs, total_bytes }
    }

    /// Move a transaction from ready queue to in-flight.
    fn move_to_in_flight(&mut self, entry: Arc<TxEntry>) {
        let hash = entry.hash;
        
        // Remove from bucket
        if let Some(bucket_idx) = self.hash_to_bucket.remove(&hash) {
            let bucket = &mut self.buckets[bucket_idx];
            bucket.queue.retain(|e| e.hash != hash);
            self.total_len = self.total_len.saturating_sub(1);
        }

        // Add to in-flight
        self.in_flight.insert(hash, InFlightEntry {
            entry,
            reserved_at: Instant::now(),
        });

        // Update status
        self.statuses.insert(hash, TxStatus::InFlight);
    }

    /// Handle prefetch message.
    fn handle_prefetch(&mut self, max_bytes: usize, max_txs: usize) {
        // Build prefetched batch WITHOUT moving to in-flight
        let mut txs = Vec::new();
        let mut total_bytes = 0;

        // Collect candidates from all buckets
        let mut candidates: Vec<Arc<TxEntry>> = Vec::new();
        for bucket in &self.buckets {
            candidates.extend(bucket.queue.iter().cloned());
        }

        // Sort by fee (descending), then by received_at (ascending)
        candidates.sort_by(|a, b| {
            b.fee.cmp(&a.fee)
                .then_with(|| a.received_at.cmp(&b.received_at))
        });

        // Pick txs up to limits (but don't include in-flight txs)
        for entry in candidates {
            if self.in_flight.contains_key(&entry.hash) {
                continue;
            }

            let entry_bytes = entry.bytes.len();
            if txs.len() >= max_txs {
                break;
            }
            if total_bytes + entry_bytes > max_bytes && !txs.is_empty() {
                break;
            }

            total_bytes += entry_bytes;
            txs.push(entry);
        }

        log::debug!(
            "mempool-actor: prefetched batch with {} txs, {} bytes",
            txs.len(),
            total_bytes
        );

        self.prefetched = Some(BatchResponse { txs, total_bytes });
    }

    /// Handle block commit message.
    fn handle_block_commit(&mut self, height: u64, applied_txs: &[TxHash]) {
        for hash in applied_txs {
            // Remove from in-flight
            if let Some(entry) = self.in_flight.remove(hash) {
                self.cur_bytes = self.cur_bytes.saturating_sub(entry.entry.bytes.len());
            }

            // Remove from ready queues (in case it wasn't in-flight)
            if let Some(bucket_idx) = self.hash_to_bucket.remove(hash) {
                let bucket = &mut self.buckets[bucket_idx];
                if let Some(pos) = bucket.queue.iter().position(|e| &e.hash == hash) {
                    if let Some(entry) = bucket.queue.remove(pos) {
                        self.cur_bytes = self.cur_bytes.saturating_sub(entry.bytes.len());
                        self.total_len = self.total_len.saturating_sub(1);
                    }
                }
            }

            // Update status
            self.statuses.insert(*hash, TxStatus::Included { block_height: height });
        }

        // Invalidate prefetch (state changed)
        self.prefetched = None;

        #[cfg(feature = "metrics")]
        self.refresh_gauges();

        log::debug!(
            "mempool-actor: block commit h={}, removed {} txs",
            height,
            applied_txs.len()
        );
    }

    /// Handle return in-flight message (on rollback/failure).
    fn handle_return_in_flight(&mut self, tx_hashes: &[TxHash]) {
        for hash in tx_hashes {
            if let Some(in_flight_entry) = self.in_flight.remove(hash) {
                let entry = in_flight_entry.entry;
                let bucket_idx = Self::bucket_index(&entry.sender);

                // Return to bucket
                self.buckets[bucket_idx].queue.push_back(entry.clone());
                self.hash_to_bucket.insert(*hash, bucket_idx);
                self.statuses.insert(*hash, TxStatus::Pending);
                self.total_len += 1;

                log::debug!(
                    "mempool-actor: returned in-flight tx hash=0x{} to bucket={}",
                    hex::encode(&hash[..4]),
                    bucket_idx
                );
            }
        }

        // Invalidate prefetch
        self.prefetched = None;
    }

    /// Expire old in-flight entries.
    fn expire_in_flight(&mut self) {
        let now = Instant::now();
        let expiry_duration = std::time::Duration::from_secs(self.config.in_flight_expiry_secs);

        let expired: Vec<TxHash> = self.in_flight
            .iter()
            .filter(|(_, e)| now.duration_since(e.reserved_at) > expiry_duration)
            .map(|(h, _)| *h)
            .collect();

        if !expired.is_empty() {
            log::warn!(
                "mempool-actor: expiring {} stale in-flight txs",
                expired.len()
            );
            self.handle_return_in_flight(&expired);
        }
    }

    /// Get mempool stats.
    fn get_stats(&self) -> MempoolStats {
        MempoolStats {
            len: self.total_len,
            cur_bytes: self.cur_bytes,
            max_len: self.config.max_len,
            max_bytes: self.config.max_bytes,
            in_flight_count: self.in_flight.len(),
            bucket_count: NUM_BUCKETS,
        }
    }

    /// Refresh Prometheus gauges.
    #[cfg(feature = "metrics")]
    fn refresh_gauges(&self) {
        EEZO_MEMPOOL_LEN.set(self.total_len as i64);
        EEZO_MEMPOOL_BYTES.set(self.cur_bytes as i64);
    }
}

// ============================================================================
// MempoolActorHandle
// ============================================================================

/// Handle for sending messages to the mempool actor.
/// 
/// This is the main interface used by other parts of the node.
/// All operations are essentially wait-free (just channel send).
#[derive(Clone)]
pub struct MempoolActorHandle {
    sender: mpsc::Sender<MempoolMsg>,
}

impl MempoolActorHandle {
    /// Create a new mempool actor and return the handle.
    /// 
    /// The actor is spawned as a background Tokio task.
    pub fn spawn(config: MempoolActorConfig) -> Self {
        // Use bounded channel with reasonable backpressure
        let (sender, receiver) = mpsc::channel(1024);
        
        let actor = MempoolActor::new(config, receiver);
        tokio::spawn(actor.run());

        Self { sender }
    }

    /// Submit a new transaction to the mempool.
    pub async fn submit(&self, ip: IpAddr, entry: TxEntry) -> Result<(), SubmitError> {
        let (tx, rx) = oneshot::channel();
        
        if self.sender.send(MempoolMsg::Submit { ip, entry, reply: tx }).await.is_err() {
            return Err(SubmitError::ActorClosed);
        }

        rx.await.unwrap_or(Err(SubmitError::ActorClosed))
    }

    /// Submit a new transaction using raw bytes (compatible with SharedMempool interface).
    /// 
    /// This is a convenience method that creates a TxEntry with default values for
    /// sender, nonce, and fee. 
    /// 
    /// **NOTE (T82.2b):** The sender, nonce, and fee fields use placeholder values.
    /// The mempool actor currently tracks transactions by hash for in-flight/duplicate
    /// detection. The actual transaction parsing (extracting sender/nonce/fee) happens
    /// when the tx is processed in the proposer loop. If proper fee-ordering or
    /// sender-based sharding is needed, the caller should use `submit()` with a
    /// fully-populated TxEntry instead.
    pub async fn submit_raw(
        &self,
        ip: IpAddr,
        hash: TxHash,
        bytes: Vec<u8>,
    ) -> Result<(), SubmitError> {
        let entry = TxEntry {
            hash,
            sender: [0u8; 20], // Placeholder: actual sender parsed in proposer loop
            bytes: Arc::new(bytes),
            received_at: Instant::now(),
            requeue_count: 0,
            nonce: 0, // Placeholder: actual nonce parsed in proposer loop
            fee: 0,   // Placeholder: actual fee parsed in proposer loop
            shared_tx: None, // T83.4: No pre-parsed tx for raw submit
        };
        self.submit(ip, entry).await
    }

    /// T83.4: Submit a transaction with a pre-parsed SharedTx for zero-copy pipeline.
    ///
    /// This is the preferred method for the zero-copy tx propagation path.
    /// The SharedTx is stored in the TxEntry and passed to downstream consumers,
    /// avoiding re-parsing overhead in the consensus runner and STM executor.
    pub async fn submit_shared(
        &self,
        ip: IpAddr,
        shared_tx: Arc<SharedTx>,
        raw_bytes: Vec<u8>,
    ) -> Result<(), SubmitError> {
        let entry = TxEntry::from_shared_tx(shared_tx, raw_bytes, Instant::now());
        self.submit(ip, entry).await
    }

    /// Get a batch of transactions for block building.
    pub async fn get_batch(&self, max_bytes: usize, max_txs: usize) -> BatchResponse {
        let (tx, rx) = oneshot::channel();
        
        if self.sender.send(MempoolMsg::GetBatch { max_bytes, max_txs, reply: tx }).await.is_err() {
            return BatchResponse { txs: vec![], total_bytes: 0 };
        }

        // T82.2b: increment batches served metric
        #[cfg(feature = "metrics")]
        crate::metrics::mempool_batches_served_inc();

        rx.await.unwrap_or(BatchResponse { txs: vec![], total_bytes: 0 })
    }

    /// Get a batch of transactions for block building (compatibility with SharedMempool::pop_batch).
    /// 
    /// Returns `Vec<Arc<TxEntry>>` which is compatible with the proposer loop.
    /// Note: This uses max_txs = usize::MAX since SharedMempool::pop_batch only has max_bytes.
    pub async fn pop_batch(&self, max_bytes: usize) -> Vec<Arc<TxEntry>> {
        let response = self.get_batch(max_bytes, usize::MAX).await;
        response.txs
    }

    /// Request prefetch of next batch (non-blocking).
    pub fn prefetch(&self, max_bytes: usize, max_txs: usize) {
        let _ = self.sender.try_send(MempoolMsg::Prefetch { max_bytes, max_txs });
    }

    /// Notify that a block was committed.
    pub async fn on_block_commit(&self, height: u64, applied_txs: Vec<TxHash>) {
        let _ = self.sender.send(MempoolMsg::OnBlockCommit { height, applied_txs }).await;
        
        // T82.2b: Update in-flight metrics after block commit
        #[cfg(feature = "metrics")]
        {
            let stats = self.get_stats().await;
            crate::metrics::mempool_inflight_len_set(stats.in_flight_count);
        }
    }

    /// Mark a transaction as included in a block (compatibility with SharedMempool::mark_included).
    /// 
    /// This is a convenience wrapper around on_block_commit for single transaction marking.
    /// The approx_bytes parameter is ignored as the actor tracks bytes internally.
    pub async fn mark_included(&self, hash: &TxHash, height: u64, _approx_bytes: usize) {
        self.on_block_commit(height, vec![*hash]).await;
    }

    /// Mark a transaction as rejected (compatibility with SharedMempool::mark_rejected).
    /// 
    /// **NOTE (T82.2b):** This is intentionally a no-op in the current implementation.
    /// Rejected transactions are handled as follows:
    /// - When a tx fails validation in the proposer loop, it's simply not included in the block
    /// - The tx remains in the actor's in-flight set until the next on_block_commit
    /// - At block commit, in-flight txs not in the applied list are effectively cleared
    /// 
    /// **TODO(T82.3):** Implement proper rejection tracking with a Rejected status and
    /// notification message (MempoolMsg::OnTxRejected) if rejection status needs to be
    /// queryable via get_status().
    pub async fn mark_rejected(&self, _hash: &TxHash, _reason: impl Into<String>, _approx_bytes: usize) {
        // Intentional no-op - see doc comment above for rationale
    }

    /// Return in-flight txs back to ready queues (on rollback).
    pub async fn return_in_flight(&self, tx_hashes: Vec<TxHash>) {
        let _ = self.sender.send(MempoolMsg::ReturnInFlight { tx_hashes }).await;
    }

    /// Get status of a transaction.
    pub async fn get_status(&self, hash: TxHash) -> Option<TxStatus> {
        let (tx, rx) = oneshot::channel();
        
        if self.sender.send(MempoolMsg::GetStatus { hash, reply: tx }).await.is_err() {
            return None;
        }

        rx.await.unwrap_or(None)
    }

    /// Get mempool stats.
    pub async fn get_stats(&self) -> MempoolStats {
        let (tx, rx) = oneshot::channel();
        
        if self.sender.send(MempoolMsg::GetStats { reply: tx }).await.is_err() {
            return MempoolStats {
                len: 0,
                cur_bytes: 0,
                max_len: 0,
                max_bytes: 0,
                in_flight_count: 0,
                bucket_count: 0,
            };
        }

        rx.await.unwrap_or(MempoolStats {
            len: 0,
            cur_bytes: 0,
            max_len: 0,
            max_bytes: 0,
            in_flight_count: 0,
            bucket_count: 0,
        })
    }

    /// Shutdown the actor.
    pub async fn shutdown(&self) {
        let _ = self.sender.send(MempoolMsg::Shutdown).await;
    }

    /// Get the current pending transaction count (for metrics).
    pub async fn len(&self) -> usize {
        self.get_stats().await.len
    }
}

// ============================================================================
// T82.2b: Unified mempool interface
// ============================================================================

/// Check if the mempool actor is enabled via environment variable.
/// 
/// Returns `true` if `EEZO_MEMPOOL_ACTOR_ENABLED=1` or `EEZO_MEMPOOL_ACTOR_ENABLED=true`.
pub fn is_mempool_actor_enabled() -> bool {
    std::env::var("EEZO_MEMPOOL_ACTOR_ENABLED")
        .map(|v| {
            let v = v.to_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

/// Create a MempoolActorHandle with configuration from environment variables.
/// 
/// Environment variables:
/// - `EEZO_MEMPOOL_MAX_LEN`: Maximum number of transactions (default: 10000)
/// - `EEZO_MEMPOOL_MAX_BYTES`: Maximum total bytes (default: 64MB)
/// - `EEZO_MEMPOOL_RATE_CAP`: Rate limit capacity per IP (default: 60)
/// - `EEZO_MEMPOOL_RATE_PER_MIN`: Rate limit refill per minute (default: 600)
/// - `EEZO_MEMPOOL_INFLIGHT_EXPIRY_SECS`: In-flight expiry (default: 30)
pub fn spawn_mempool_actor_from_env() -> MempoolActorHandle {
    fn env_usize(key: &str, default: usize) -> usize {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    let config = MempoolActorConfig {
        max_len: env_usize("EEZO_MEMPOOL_MAX_LEN", 10_000),
        max_bytes: env_usize("EEZO_MEMPOOL_MAX_BYTES", 64 * 1024 * 1024),
        rate_bucket_capacity: env_usize("EEZO_MEMPOOL_RATE_CAP", 60) as u32,
        rate_refill_per_minute: env_usize("EEZO_MEMPOOL_RATE_PER_MIN", 600) as u32,
        in_flight_expiry_secs: env_usize("EEZO_MEMPOOL_INFLIGHT_EXPIRY_SECS", 30) as u64,
    };

    log::info!(
        "mempool-actor: spawning with max_len={}, max_bytes={}, rate_cap={}, inflight_expiry={}s",
        config.max_len,
        config.max_bytes,
        config.rate_bucket_capacity,
        config.in_flight_expiry_secs
    );

    MempoolActorHandle::spawn(config)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_entry(hash_byte: u8, sender_byte: u8, nonce: u64, fee: u64) -> TxEntry {
        let mut hash = [0u8; 32];
        hash[0] = hash_byte;
        
        let mut sender = [0u8; 20];
        sender[0] = sender_byte;

        TxEntry {
            hash,
            sender,
            bytes: Arc::new(vec![0u8; 100]),
            received_at: Instant::now(),
            requeue_count: 0,
            nonce,
            fee,
            shared_tx: None, // T83.4: Tests don't need pre-parsed tx
        }
    }

    #[tokio::test]
    async fn test_submit_and_get_batch() {
        let config = MempoolActorConfig {
            max_len: 100,
            max_bytes: 100_000,
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 6000,
            in_flight_expiry_secs: 30,
        };

        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit some transactions
        for i in 0..5 {
            let entry = test_entry(i, i, i as u64, 100 - i as u64);
            let result = handle.submit(ip, entry).await;
            assert!(result.is_ok(), "Submit {} failed: {:?}", i, result);
        }

        // Get batch
        let batch = handle.get_batch(10_000, 10).await;
        assert_eq!(batch.txs.len(), 5);
        assert!(batch.total_bytes > 0);

        // Txs should be sorted by fee (descending)
        for i in 0..4 {
            assert!(batch.txs[i].fee >= batch.txs[i + 1].fee, 
                "Batch not sorted by fee: {} < {}", batch.txs[i].fee, batch.txs[i + 1].fee);
        }

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_in_flight_tracking() {
        let config = MempoolActorConfig {
            max_len: 100,
            max_bytes: 100_000,
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 6000,
            in_flight_expiry_secs: 30,
        };

        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit transactions
        let entry1 = test_entry(1, 1, 0, 100);
        let entry2 = test_entry(2, 2, 0, 90);
        let hash1 = entry1.hash;
        let hash2 = entry2.hash;

        handle.submit(ip, entry1).await.unwrap();
        handle.submit(ip, entry2).await.unwrap();

        // Get first batch - moves txs to in-flight
        let batch1 = handle.get_batch(10_000, 10).await;
        assert_eq!(batch1.txs.len(), 2);

        // Get second batch - should be empty (txs are in-flight)
        let batch2 = handle.get_batch(10_000, 10).await;
        assert_eq!(batch2.txs.len(), 0, "Second batch should be empty (txs in-flight)");

        // Commit block with tx1
        handle.on_block_commit(1, vec![hash1]).await;

        // tx2 is still in-flight, batch should be empty
        let batch3 = handle.get_batch(10_000, 10).await;
        assert_eq!(batch3.txs.len(), 0);

        // Commit tx2
        handle.on_block_commit(2, vec![hash2]).await;

        // Check statuses
        let status1 = handle.get_status(hash1).await;
        let status2 = handle.get_status(hash2).await;
        assert!(matches!(status1, Some(TxStatus::Included { block_height: 1 })));
        assert!(matches!(status2, Some(TxStatus::Included { block_height: 2 })));

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_no_zombie_tx_across_blocks() {
        let config = MempoolActorConfig {
            max_len: 100,
            max_bytes: 100_000,
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 6000,
            in_flight_expiry_secs: 30,
        };

        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit tx
        let entry = test_entry(1, 1, 0, 100);
        let hash = entry.hash;
        handle.submit(ip, entry).await.unwrap();

        // Block N: get batch containing tx
        let batch_n = handle.get_batch(10_000, 10).await;
        assert_eq!(batch_n.txs.len(), 1);
        assert_eq!(batch_n.txs[0].hash, hash);

        // Block N+1: try to get batch while tx is still in-flight
        // This should NOT include the same tx
        let batch_n1 = handle.get_batch(10_000, 10).await;
        assert_eq!(batch_n1.txs.len(), 0, "Block N+1 should not include in-flight tx");

        // Commit block N
        handle.on_block_commit(1, vec![hash]).await;

        // Block N+2: tx should still not appear (it's committed)
        let batch_n2 = handle.get_batch(10_000, 10).await;
        assert_eq!(batch_n2.txs.len(), 0, "Committed tx should not reappear");

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_return_in_flight_on_failure() {
        let config = MempoolActorConfig {
            max_len: 100,
            max_bytes: 100_000,
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 6000,
            in_flight_expiry_secs: 30,
        };

        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit tx
        let entry = test_entry(1, 1, 0, 100);
        let hash = entry.hash;
        handle.submit(ip, entry).await.unwrap();

        // Get batch (moves to in-flight)
        let batch1 = handle.get_batch(10_000, 10).await;
        assert_eq!(batch1.txs.len(), 1);

        // Simulate failure: return tx to ready queue
        handle.return_in_flight(vec![hash]).await;

        // Get batch again - should include the returned tx
        let batch2 = handle.get_batch(10_000, 10).await;
        assert_eq!(batch2.txs.len(), 1);
        assert_eq!(batch2.txs[0].hash, hash);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_prefetch() {
        let config = MempoolActorConfig {
            max_len: 100,
            max_bytes: 100_000,
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 6000,
            in_flight_expiry_secs: 30,
        };

        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit transactions
        for i in 0..3 {
            let entry = test_entry(i, i, i as u64, 100);
            handle.submit(ip, entry).await.unwrap();
        }

        // Request prefetch
        handle.prefetch(10_000, 10);
        
        // Small delay for prefetch to complete
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Get batch - should use prefetched data
        let batch = handle.get_batch(10_000, 10).await;
        assert_eq!(batch.txs.len(), 3);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_duplicate_rejection() {
        let config = MempoolActorConfig {
            max_len: 100,
            max_bytes: 100_000,
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 6000,
            in_flight_expiry_secs: 30,
        };

        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let entry1 = test_entry(1, 1, 0, 100);
        let entry2 = test_entry(1, 1, 0, 100); // Same hash

        // First submit succeeds
        let result1 = handle.submit(ip, entry1).await;
        assert!(result1.is_ok());

        // Second submit with same hash fails
        let result2 = handle.submit(ip, entry2).await;
        assert!(matches!(result2, Err(SubmitError::Duplicate)));

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_capacity_limits() {
        let config = MempoolActorConfig {
            max_len: 2,
            max_bytes: 100_000,
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 6000,
            in_flight_expiry_secs: 30,
        };

        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Fill to capacity
        handle.submit(ip, test_entry(1, 1, 0, 100)).await.unwrap();
        handle.submit(ip, test_entry(2, 2, 0, 100)).await.unwrap();

        // Third submit should fail
        let result = handle.submit(ip, test_entry(3, 3, 0, 100)).await;
        assert!(matches!(result, Err(SubmitError::QueueFull)));

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_stats() {
        let config = MempoolActorConfig {
            max_len: 100,
            max_bytes: 100_000,
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 6000,
            in_flight_expiry_secs: 30,
        };

        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit 3 transactions
        for i in 0..3 {
            handle.submit(ip, test_entry(i, i, i as u64, 100)).await.unwrap();
        }

        let stats = handle.get_stats().await;
        assert_eq!(stats.len, 3);
        assert_eq!(stats.cur_bytes, 300);
        assert_eq!(stats.max_len, 100);
        assert_eq!(stats.in_flight_count, 0);
        assert_eq!(stats.bucket_count, 256);

        // Get batch (moves to in-flight)
        let _ = handle.get_batch(10_000, 10).await;

        let stats2 = handle.get_stats().await;
        assert_eq!(stats2.len, 0);
        assert_eq!(stats2.in_flight_count, 3);

        handle.shutdown().await;
    }

    // =========================================================================
    // T83.4: SharedTx integration tests
    // =========================================================================

    /// Helper: create a test SharedTx and TxEntry together
    fn make_shared_tx_entry(nonce: u64) -> (Arc<SharedTx>, TxEntry) {
        use eezo_ledger::{Address, TxCore, SignedTx};
        
        let tx = SignedTx {
            core: TxCore {
                to: Address([0xca; 20]),
                amount: 1000,
                fee: 10,
                nonce,
            },
            pubkey: vec![0x42; 32],  // 32-byte pubkey for valid sender derivation
            sig: vec![0xde, 0xad],
        };
        
        let chain_id = [0x01u8; 20];
        let shared_tx = Arc::new(SharedTx::new(tx, chain_id));
        let bytes = vec![0u8; 100]; // Dummy bytes for size tracking
        
        let entry = TxEntry::from_shared_tx(shared_tx.clone(), bytes, Instant::now());
        (shared_tx, entry)
    }

    #[tokio::test]
    async fn test_submit_shared_tx() {
        let config = MempoolActorConfig {
            max_len: 100,
            max_bytes: 100_000,
            rate_bucket_capacity: 100,
            rate_refill_per_minute: 6000,
            in_flight_expiry_secs: 30,
        };

        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Create SharedTx-backed entries
        let (shared1, entry1) = make_shared_tx_entry(0);
        let (shared2, entry2) = make_shared_tx_entry(1);

        // Submit entries with SharedTx
        handle.submit(ip, entry1).await.unwrap();
        handle.submit(ip, entry2).await.unwrap();

        // Get batch and verify SharedTx is preserved
        let batch = handle.get_batch(10_000, 10).await;
        assert_eq!(batch.txs.len(), 2);

        // All entries should have SharedTx
        for tx_entry in &batch.txs {
            assert!(tx_entry.has_shared_tx(), "Entry should have SharedTx");
        }

        // Verify hash consistency
        assert_eq!(batch.txs[0].hash, shared1.hash());
        assert_eq!(batch.txs[1].hash, shared2.hash());

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_shared_tx_entry_fields() {
        let (shared_tx, entry) = make_shared_tx_entry(42);

        // Verify entry fields are derived from SharedTx
        assert_eq!(entry.hash, shared_tx.hash());
        assert_eq!(entry.nonce, 42);
        assert_eq!(entry.fee, 10); // fee from core
        
        // Sender should be derived from pubkey
        let expected_sender = shared_tx.sender()
            .map(|a| a.0)
            .unwrap_or([0u8; 20]);
        assert_eq!(entry.sender, expected_sender);

        // SharedTx should be accessible
        assert!(entry.has_shared_tx());
        assert!(Arc::ptr_eq(&entry.shared_tx.as_ref().unwrap(), &shared_tx));
    }

    #[tokio::test]
    async fn test_submit_shared_uses_actor_handle() {
        let config = MempoolActorConfig::default();
        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Use the new submit_shared method
        use eezo_ledger::{Address, TxCore, SignedTx};
        let tx = SignedTx {
            core: TxCore {
                to: Address([0xab; 20]),
                amount: 500,
                fee: 5,
                nonce: 99,
            },
            pubkey: vec![0x11; 32],
            sig: vec![],
        };
        let shared_tx = Arc::new(SharedTx::new(tx, [0x01; 20]));
        let raw_bytes = vec![0u8; 50];

        // Submit via the new submit_shared method
        let result = handle.submit_shared(ip, shared_tx.clone(), raw_bytes).await;
        assert!(result.is_ok());

        // Verify it's in the batch
        let batch = handle.get_batch(10_000, 10).await;
        assert_eq!(batch.txs.len(), 1);
        assert!(batch.txs[0].has_shared_tx());
        assert_eq!(batch.txs[0].hash, shared_tx.hash());

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_mixed_shared_and_raw_submit() {
        let config = MempoolActorConfig::default();
        let handle = MempoolActorHandle::spawn(config);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit one with SharedTx
        let (_, entry_shared) = make_shared_tx_entry(0);
        handle.submit(ip, entry_shared).await.unwrap();

        // Submit one without SharedTx (raw)
        let entry_raw = test_entry(100, 100, 1, 50);
        handle.submit(ip, entry_raw).await.unwrap();

        // Get batch
        let batch = handle.get_batch(10_000, 10).await;
        assert_eq!(batch.txs.len(), 2);

        // Verify one has SharedTx, one doesn't
        let has_shared_count = batch.txs.iter()
            .filter(|e| e.has_shared_tx())
            .count();
        let no_shared_count = batch.txs.iter()
            .filter(|e| !e.has_shared_tx())
            .count();

        assert_eq!(has_shared_count, 1);
        assert_eq!(no_shared_count, 1);

        handle.shutdown().await;
    }
}