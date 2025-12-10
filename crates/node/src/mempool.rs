// crates/node/src/mempool.rs
//! Minimal in-proc mempool for T30.
//!
//! Goals (T30):
//! - Bounded queue (len + bytes).
//! - Per-IP token-bucket rate limiting.
//! - Tx status tracking: pending / included(height) / rejected(reason).
//! - Zero coupling to ledger types (store opaque bytes + hash).
//!
//! Wire-up plan:
//! - HTTP POST /tx will parse JSON, compute hash, and call `SharedMempool::submit`.
//! - Proposer loop will call `pop_batch()` then try to apply; it will mark included/rejected.
//! - GET /tx/{hash} surfaces `status()`.
//!
//! NOTE: This module intentionally avoids importing eezo_ledger to keep
//! compile order simple. The proposer will handle decoding/apply.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::Arc,
    time::Instant,
};

use tokio::sync::Mutex;
#[cfg(feature = "metrics")]
use crate::metrics::{EEZO_MEMPOOL_BYTES, EEZO_MEMPOOL_LEN, EEZO_TX_REJECTED_TOTAL};

/// 32-byte transaction hash (blake2/sha256/ssz-root etc. — computed by the caller).
pub type TxHash = [u8; 32];

/// Runtime view of a transaction stored in the mempool.
#[derive(Debug, Clone)]
pub struct TxEntry {
    pub hash: TxHash,
    pub bytes: Arc<Vec<u8>>, // opaque payload; proposer will decode
    #[allow(dead_code)]
    pub received_at: Instant,
    pub requeue_count: u32,
}

/// Public status exposed to `/tx/{hash}`.
#[derive(Debug, Clone)]
pub enum TxStatus {
    Pending,
    Included { block_height: u64 },
    Rejected { error: String },
}

#[derive(Debug)]
pub enum SubmitError {
    RateLimited,
    QueueFull,
    BytesCapReached,
    Duplicate, // already known (pending/included/rejected)
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SubmitError::*;
        match self {
            RateLimited => write!(f, "rate limited"),
            QueueFull => write!(f, "mempool full"),
            BytesCapReached => write!(f, "mempool byte cap reached"),
            Duplicate => write!(f, "duplicate transaction"),
        }
    }
}
impl std::error::Error for SubmitError {}

/// Simple token-bucket per IP.
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
            self.tokens =
                (self.tokens + elapsed * self.refill_per_sec).min(self.capacity as f64);
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

/// Core mempool (not thread-safe). Wrap with `SharedMempool` for concurrent use.
pub struct Mempool {
    // Bounded queue of pending entries (FIFO by receive time).
    queue: VecDeque<Arc<TxEntry>>,
    // Quick lookup to avoid duplicates while pending.
    pending_index: HashMap<TxHash, ()>,

    // Status map (includes pending/included/rejected). This survives even after draining from queue.
    statuses: HashMap<TxHash, TxStatus>,

    // Limits
    max_len: usize,
    max_bytes: usize,
    cur_bytes: usize,

    // Per-IP rate buckets
    ip_buckets: HashMap<IpAddr, RateBucket>,
    // Rate params
    bucket_capacity: u32,
    bucket_refill_per_sec: f64,
}

impl Mempool {
    pub fn new(max_len: usize, max_bytes: usize, bucket_capacity: u32, per_minute: u32) -> Self {
        let refill_per_sec = per_minute as f64 / 60.0;
        Self {
            queue: VecDeque::with_capacity(max_len.min(1024)),
            pending_index: HashMap::new(),
            statuses: HashMap::new(),
            max_len,
            max_bytes,
            cur_bytes: 0,
            ip_buckets: HashMap::new(),
            bucket_capacity,
            bucket_refill_per_sec: refill_per_sec,
        }
    }

    fn bucket_mut(&mut self, ip: IpAddr) -> &mut RateBucket {
        self.ip_buckets
            .entry(ip)
            .or_insert_with(|| RateBucket::new(self.bucket_capacity, self.bucket_refill_per_sec))
    }

    /// Try to enqueue a tx. Caller must supply `hash` and raw `bytes`.
    /// On success, status becomes Pending.
    pub fn submit(&mut self, ip: IpAddr, hash: TxHash, bytes: Vec<u8>) -> Result<(), SubmitError> {
        // De-dupe: if we already know about this hash, reject duplicate.
        if self.statuses.contains_key(&hash) || self.pending_index.contains_key(&hash) {
            return Err(SubmitError::Duplicate);
        }

        // Rate limit (cost=1 op)
        if !self.bucket_mut(ip).allow(1) {
            return Err(SubmitError::RateLimited);
        }

        // Capacity checks
        if self.queue.len() >= self.max_len {
            return Err(SubmitError::QueueFull);
        }
        let b = bytes.len();
        if self.cur_bytes + b > self.max_bytes {
            return Err(SubmitError::BytesCapReached);
        }

        let entry = Arc::new(TxEntry {
            hash,
            bytes: Arc::new(bytes),
            received_at: Instant::now(),
            requeue_count: 0,
        });
        self.queue.push_back(entry);
        self.pending_index.insert(hash, ());
        self.statuses.insert(hash, TxStatus::Pending);
        self.cur_bytes += b;
        #[cfg(feature = "metrics")]
        self.refresh_gauges();
        Ok(())
    }

    /// Pop up to `target_bytes` of txs (FIFO). Returns opaque entries to be applied by the proposer.
    pub fn pop_batch(&mut self, target_bytes: usize) -> Vec<Arc<TxEntry>> {
        let mut out = Vec::new();
        let mut used = 0usize;
        while let Some(front) = self.queue.front() {
            let sz = front.bytes.len();
            if !out.is_empty() && used + sz > target_bytes {
                break;
            }
            let entry = self.queue.pop_front().expect("front just checked");
            self.pending_index.remove(&entry.hash);
            // Do not change cur_bytes yet; we only shrink cur_bytes when we finally mark included/rejected.
            used += sz;
            out.push(entry);
        }
        #[cfg(feature = "metrics")]
        self.refresh_gauges();
        out
    }

    /// Mark tx as included at `block_height`. Also shrink the byte accounting.
    pub fn mark_included(&mut self, hash: &TxHash, block_height: u64, approx_bytes: usize) {
        // Guard against callers accidentally passing 0 (genesis) as the height.
        // T32 expects first produced block to be height >= 1.
        let h = if block_height == 0 { 1 } else { block_height };
        self.statuses
            .insert(*hash, TxStatus::Included { block_height: h });

        // Best-effort shrink. If underflow, clamp to 0.
        self.cur_bytes = self.cur_bytes.saturating_sub(approx_bytes);
        #[cfg(feature = "metrics")]
        self.refresh_gauges();
    }

    /// Mark tx as rejected with a reason. Also shrink byte accounting.
    pub fn mark_rejected(&mut self, hash: &TxHash, reason: impl Into<String>, approx_bytes: usize) {
        let reason_str = reason.into();
        self.statuses
            .insert(*hash, TxStatus::Rejected { error: reason_str.clone() });
        self.cur_bytes = self.cur_bytes.saturating_sub(approx_bytes);
        #[cfg(feature = "metrics")]
        {
            EEZO_TX_REJECTED_TOTAL
                .with_label_values(&[reason_str.as_str()])
                .inc();
            self.refresh_gauges();
        }
    }

    /// Reinsert a pending entry back into the FIFO queue without changing its status.
    ///
    /// Used by the proposer when a tx has a nonce that is **too high**:
    /// we want to keep it Pending instead of marking it Rejected.
    ///
    /// Returns Some(new_count) if requeued successfully, None if rejected due to too many requeues.
    /// The caller should check the return value and mark the tx as rejected if None is returned.
    pub fn requeue(&mut self, entry: Arc<TxEntry>, max_requeues: u32) -> Option<u32> {
        // If the queue is already at capacity, just drop the requeue request.
        // The original submit() call already accounted for this tx in cur_bytes.
        if self.queue.len() >= self.max_len {
            return Some(entry.requeue_count);
        }

        // If we somehow already have this hash in the pending index, don't double-insert.
        if self.pending_index.contains_key(&entry.hash) {
            return Some(entry.requeue_count);
        }

        // Check if we've exceeded the max requeue count
        let new_count = entry.requeue_count.saturating_add(1);
        if new_count > max_requeues {
            // Too many requeues - caller should reject this tx
            return None;
        }

        // Create a new entry with incremented requeue count
        let updated_entry = Arc::new(TxEntry {
            hash: entry.hash,
            bytes: entry.bytes.clone(),
            received_at: entry.received_at,
            requeue_count: new_count,
        });

        self.pending_index.insert(entry.hash, ());
        self.queue.push_back(updated_entry);

        #[cfg(feature = "metrics")]
        self.refresh_gauges();

        Some(new_count)
    }


    pub fn status(&self, hash: &TxHash) -> Option<TxStatus> {
        self.statuses.get(hash).cloned()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    // Keep Prometheus gauges in sync with current queue contents.
    #[cfg(feature = "metrics")]
    fn refresh_gauges(&self) {
        EEZO_MEMPOOL_LEN.set(self.queue.len() as i64);
        let bytes: usize = self.queue.iter().map(|e| e.bytes.len()).sum();
        EEZO_MEMPOOL_BYTES.set(bytes as i64);
    }

    pub fn cur_bytes(&self) -> usize {
        self.cur_bytes
    }

    pub fn max_len(&self) -> usize {
        self.max_len
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// return up to `max` pending tx hashes from the front of the queue.
    ///
    /// this is read-only and does not modify ordering, status, or accounting.
    /// intended for debug / dag "shadow payload" sampling.
    pub fn sample_hashes(&self, max: usize) -> Vec<TxHash> {
        if max == 0 {
            return Vec::new();
        }

        self.queue
            .iter()
            .take(max)
            .map(|entry| entry.hash)
            .collect()
    }

    /// Return raw bytes for the given tx hashes, in the same order as the input.
    ///
    /// This is debug/inspection only; it does NOT remove entries or change any status.
    /// Used by DAG block preview to fetch tx data for decoding.
    ///
    /// Note: Uses O(n*m) nested loop for simplicity since this is a debug-only path
    /// with typically small numbers of hashes. If performance becomes an issue,
    /// consider building a temporary HashMap for O(1) lookup.
    pub fn get_bytes_for_hashes(&self, hashes: &[TxHash]) -> Vec<(TxHash, Arc<Vec<u8>>)> {
        let mut out = Vec::with_capacity(hashes.len());
        'outer: for h in hashes {
            for entry in self.queue.iter() {
                if &entry.hash == h {
                    out.push((entry.hash, Arc::clone(&entry.bytes)));
                    continue 'outer;
                }
            }
        }
        out
    }
}

/// Concurrent wrapper used by the HTTP layer & proposer.
#[derive(Clone)]
pub struct SharedMempool {
    inner: Arc<Mutex<Mempool>>,
    /// T76.3b: Separate cache for tx bytes indexed by canonical tx hash.
    /// This allows the DAG hybrid consumer to look up bytes using the
    /// canonical SignedTx.hash(), which differs from the raw envelope hash
    /// used by the mempool queue.
    tx_bytes_cache: Arc<parking_lot::RwLock<HashMap<TxHash, Arc<Vec<u8>>>>>,
}

impl SharedMempool {
    pub fn new(inner: Mempool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            tx_bytes_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }
    
    /// T76.3b: Insert tx bytes into the canonical hash cache.
    /// 
    /// This is called after decoding a tx to store its bytes indexed by
    /// the canonical SignedTx.hash() (not the raw envelope hash).
    pub fn insert_tx_bytes(&self, canonical_hash: TxHash, bytes: Vec<u8>) {
        let mut cache = self.tx_bytes_cache.write();
        cache.insert(canonical_hash, Arc::new(bytes));
    }
    
    /// T76.3b: Get tx bytes from the canonical hash cache.
    /// 
    /// Returns bytes for hashes that are found in the cache.
    /// This is used by the hybrid DAG consumer to resolve tx bytes.
    pub fn get_tx_bytes_by_canonical_hash(&self, hashes: &[TxHash]) -> Vec<(TxHash, Arc<Vec<u8>>)> {
        let cache = self.tx_bytes_cache.read();
        hashes.iter()
            .filter_map(|h| cache.get(h).map(|b| (*h, Arc::clone(b))))
            .collect()
    }
    
    /// T76.3b: Clear entries from the canonical hash cache.
    /// 
    /// Called when txs are included in a block and no longer needed.
    pub fn evict_tx_bytes(&self, hashes: &[TxHash]) {
        let mut cache = self.tx_bytes_cache.write();
        for h in hashes {
            cache.remove(h);
        }
    }
    
    /// T76.3b: Get current size of the tx bytes cache.
    pub fn tx_bytes_cache_len(&self) -> usize {
        self.tx_bytes_cache.read().len()
    }

    pub async fn submit(
        &self,
        ip: IpAddr,
        hash: TxHash,
        bytes: Vec<u8>,
    ) -> Result<(), SubmitError> {
        let mut g = self.inner.lock().await;
        g.submit(ip, hash, bytes)
    }

    pub async fn pop_batch(&self, target_bytes: usize) -> Vec<Arc<TxEntry>> {
        let mut g = self.inner.lock().await;
        g.pop_batch(target_bytes)
    }

    pub async fn requeue(&self, entry: Arc<TxEntry>, max_requeues: u32) -> Option<u32> {
        let mut g = self.inner.lock().await;
        g.requeue(entry, max_requeues)
    }

    pub async fn mark_included(&self, hash: &TxHash, height: u64, approx_bytes: usize) {
        let mut g = self.inner.lock().await;
        g.mark_included(hash, height, approx_bytes);
    }

    pub async fn mark_rejected(&self, hash: &TxHash, reason: impl Into<String>, approx_bytes: usize) {
        let mut g = self.inner.lock().await;
        g.mark_rejected(hash, reason, approx_bytes);
    }

    pub async fn status(&self, hash: &TxHash) -> Option<TxStatus> {
        let g = self.inner.lock().await;
        g.status(hash)
    }

    pub async fn stats(&self) -> (usize, usize, usize, usize) {
        let g = self.inner.lock().await;
        (g.len(), g.cur_bytes(), g.max_len(), g.max_bytes())
    }

    /// return up to `max` pending tx hashes from the current mempool view.
    ///
    /// this is read-only: it does not pop, mark, or mutate any entries.
    /// dag uses this for "shadow" payload construction without affecting
    /// the legacy path or mempool behaviour.
    pub async fn sample_hashes(&self, max: usize) -> Vec<TxHash> {
        let g = self.inner.lock().await;
        g.sample_hashes(max)
    }

    /// Return the number of transactions currently in the mempool.
    pub async fn len(&self) -> usize {
        let g = self.inner.lock().await;
        g.len()
    }

    /// Return raw bytes for the given tx hashes, in the same order as the input.
    ///
    /// This is debug/inspection only; it does NOT remove entries or change any status.
    /// Used by DAG block preview to fetch tx data for decoding.
    pub async fn get_bytes_for_hashes(&self, hashes: &[TxHash]) -> Vec<(TxHash, Arc<Vec<u8>>)> {
        let g = self.inner.lock().await;
        g.get_bytes_for_hashes(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn h(n: u8) -> TxHash {
        let mut x = [0u8; 32];
        x[0] = n;
        x
    }

    #[tokio::test]
    async fn basic_submit_and_pop() {
        let mp = SharedMempool::new(Mempool::new(4, 10_000, 10, 600));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        mp.submit(ip, h(1), vec![0u8; 100]).await.unwrap();
        mp.submit(ip, h(2), vec![0u8; 200]).await.unwrap();
        assert_eq!(mp.stats().await.0, 2);
        assert_eq!(mp.len().await, 2); // test the new len() method

        let batch = mp.pop_batch(150).await;
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].hash, h(1));

        // mark included / bytes shrink
        mp.mark_included(&h(1), 42, 100).await;
        let (_, cur, _, _) = mp.stats().await;
        assert!((200..1000).contains(&cur)); // only best-effort accounting remained

        // status checks
        assert!(matches!(mp.status(&h(1)).await, Some(TxStatus::Included { block_height: 42 })));
        assert!(matches!(mp.status(&h(2)).await, Some(TxStatus::Pending)));
    }

    #[tokio::test]
    async fn capacity_and_duplicate() {
        let mp = SharedMempool::new(Mempool::new(1, 1024, 10, 600));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        mp.submit(ip, h(1), vec![0u8; 100]).await.unwrap();
        // full by len
        let e = mp.submit(ip, h(2), vec![0u8; 100]).await.err().unwrap();
        assert!(matches!(e, SubmitError::QueueFull));

        // duplicate
        let e = mp.submit(ip, h(1), vec![0u8; 100]).await.err().unwrap();
        assert!(matches!(e, SubmitError::Duplicate));
    }

    #[tokio::test]
    async fn rate_limit_and_bytes_cap() {
        let mp = SharedMempool::new(Mempool::new(10, 128, 1, 60)); // capacity=1 token, refill 1/sec
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        mp.submit(ip, h(1), vec![0u8; 64]).await.unwrap();
        let e = mp.submit(ip, h(2), vec![0u8; 64]).await.err().unwrap();
        assert!(matches!(e, SubmitError::RateLimited));

        // wait ~1.1s to refill
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // second submit fits under the byte cap: 64 + 48 = 112 <= 128
        mp.submit(ip, h(2), vec![0u8; 48]).await.unwrap();

        // bytes cap reached now (64 + 48 + 64 > 128) on a third submit
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let e = mp.submit(ip, h(3), vec![0u8; 64]).await.err().unwrap();
        assert!(matches!(e, SubmitError::BytesCapReached));
    }

    #[tokio::test]
    async fn basic_requeue() {
        let mp = SharedMempool::new(Mempool::new(3, 10_000, 10, 600));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit three transactions
        mp.submit(ip, h(1), vec![0u8; 100]).await.unwrap();
        mp.submit(ip, h(2), vec![0u8; 200]).await.unwrap();
        mp.submit(ip, h(3), vec![0u8; 300]).await.unwrap();
        assert_eq!(mp.len().await, 3);

        // Pop with target_bytes=1000 - since all 3 txs fit (100+200+300=600 < 1000), all are popped
        let mut batch = mp.pop_batch(1000).await;
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].hash, h(1));
        assert_eq!(batch[1].hash, h(2));
        assert_eq!(batch[2].hash, h(3));
        assert_eq!(mp.len().await, 0); // All popped

        // Proposer sees h2 has too high a nonce and requeues it.
        // It's removed from the pending index by pop_batch, but still in statuses as Pending.
        let tx_h2 = batch.remove(1); // Remove h2 (the middle one)
        let requeue_result = mp.requeue(tx_h2, 100).await;
        assert!(requeue_result.is_some()); // Should succeed
        assert_eq!(requeue_result.unwrap(), 1); // First requeue, count = 1
        assert_eq!(mp.len().await, 1); // Just h2 requeued

        // Pop again: should get the requeued h2
        let batch_requeued = mp.pop_batch(1000).await;
        assert_eq!(batch_requeued.len(), 1);
        assert_eq!(batch_requeued[0].hash, h(2));
        assert_eq!(batch_requeued[0].requeue_count, 1); // Verify requeue count

        // Statuses: h1 and h3 were in original batch but not explicitly marked, h2 is still Pending
        assert!(matches!(mp.status(&h(2)).await, Some(TxStatus::Pending)));
    }

    #[tokio::test]
    async fn requeue_capacity_check() {
        let mp = SharedMempool::new(Mempool::new(1, 10_000, 10, 600));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Fill mempool
        mp.submit(ip, h(1), vec![0u8; 100]).await.unwrap();
        // Submit fails because full
        let e = mp.submit(ip, h(2), vec![0u8; 200]).await.err().unwrap();
        assert!(matches!(e, SubmitError::QueueFull));

        // Pop h1
        let batch = mp.pop_batch(1000).await;
        let tx_h1 = batch[0].clone();
        assert_eq!(mp.len().await, 0);

        // Submit h2 (now fits)
        mp.submit(ip, h(2), vec![0u8; 200]).await.unwrap();
        assert_eq!(mp.len().await, 1);

        // Mempool is full again (len=1, max_len=1). Requeuing h1 should be dropped.
        let requeue_result = mp.requeue(tx_h1, 100).await;
        assert!(requeue_result.is_some()); // Returns Some even if not actually queued due to capacity
        assert_eq!(mp.len().await, 1);
        // h1 is still in statuses as Pending, but not in the queue.
        assert!(matches!(mp.status(&h(1)).await, Some(TxStatus::Pending)));

        // Pop h2
        mp.pop_batch(1000).await;
        assert_eq!(mp.len().await, 0);

        // Now requeuing h1 should succeed.
        let requeue_result = mp.requeue(batch[0].clone(), 100).await;
        assert!(requeue_result.is_some());
        assert_eq!(mp.len().await, 1);
        assert!(mp.pop_batch(1000).await[0].hash == h(1));
    }

    #[tokio::test]
    async fn requeue_duplicate_check() {
        let mp = SharedMempool::new(Mempool::new(2, 10_000, 10, 600));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit h1
        mp.submit(ip, h(1), vec![0u8; 100]).await.unwrap();
        assert_eq!(mp.len().await, 1);

        // Pop h1 (now removed from queue/pending_index)
        let batch = mp.pop_batch(1000).await;
        let tx_h1 = batch[0].clone();
        assert_eq!(mp.len().await, 0);

        // Requeue h1 (success)
        let requeue_result = mp.requeue(tx_h1.clone(), 100).await;
        assert!(requeue_result.is_some());
        assert_eq!(mp.len().await, 1);

        // Requeue h1 again (should be rejected by pending_index check)
        let requeue_result = mp.requeue(tx_h1, 100).await;
        assert!(requeue_result.is_some()); // Still returns Some, but doesn't actually double-insert
        assert_eq!(mp.len().await, 1);
    }

    #[tokio::test]
    async fn requeue_max_count() {
        let mp = SharedMempool::new(Mempool::new(10, 10_000, 10, 600));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit a transaction
        mp.submit(ip, h(1), vec![0u8; 100]).await.unwrap();
        assert_eq!(mp.len().await, 1);

        // Pop it
        let batch = mp.pop_batch(1000).await;
        let mut tx = batch[0].clone();
        assert_eq!(mp.len().await, 0);

        // Requeue it multiple times up to the limit (max_requeues = 3)
        for i in 1..=3 {
            // Pop if it's in the queue
            if mp.len().await > 0 {
                let batch = mp.pop_batch(1000).await;
                tx = batch[0].clone();
            }
            
            let result = mp.requeue(tx.clone(), 3).await;
            assert!(result.is_some(), "Requeue {} should succeed", i);
            assert_eq!(result.unwrap(), i, "Requeue count should be {}", i);
            assert_eq!(mp.len().await, 1);
        }

        // Pop it one more time
        let batch = mp.pop_batch(1000).await;
        tx = batch[0].clone();

        // Try to requeue again - should fail (count would be 4 > max 3)
        let result = mp.requeue(tx, 3).await;
        assert!(result.is_none(), "Requeue should fail after max count");
        assert_eq!(mp.len().await, 0); // Should not be requeued
    }

    #[tokio::test]
    async fn sample_hashes_is_read_only() {
        let mp = SharedMempool::new(Mempool::new(4, 10_000, 10, 600));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        mp.submit(ip, h(1), vec![0u8; 10]).await.unwrap();
        mp.submit(ip, h(2), vec![0u8; 10]).await.unwrap();
        mp.submit(ip, h(3), vec![0u8; 10]).await.unwrap();

        // sample fewer than we have
        let hashes = mp.sample_hashes(2).await;
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], h(1));
        assert_eq!(hashes[1], h(2));

        // mempool contents unchanged
        assert_eq!(mp.len().await, 3);

        // sample more than we have just returns all of them
        let hashes_all = mp.sample_hashes(10).await;
        assert_eq!(hashes_all.len(), 3);
        assert_eq!(hashes_all[0], h(1));
        assert_eq!(hashes_all[1], h(2));
        assert_eq!(hashes_all[2], h(3));
    }

    #[tokio::test]
    async fn get_bytes_for_hashes_returns_matching_entries() {
        let mp = SharedMempool::new(Mempool::new(4, 10_000, 10, 600));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Submit txs with known bytes
        let bytes1 = vec![1u8, 2, 3];
        let bytes2 = vec![4u8, 5, 6];
        let bytes3 = vec![7u8, 8, 9];
        mp.submit(ip, h(1), bytes1.clone()).await.unwrap();
        mp.submit(ip, h(2), bytes2.clone()).await.unwrap();
        mp.submit(ip, h(3), bytes3.clone()).await.unwrap();

        // Query a subset of hashes
        let result = mp.get_bytes_for_hashes(&[h(1), h(3)]).await;
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, h(1));
        assert_eq!(*result[0].1, bytes1);
        assert_eq!(result[1].0, h(3));
        assert_eq!(*result[1].1, bytes3);

        // Query with a hash that doesn't exist
        let unknown = h(99);
        let result2 = mp.get_bytes_for_hashes(&[h(2), unknown]).await;
        // Only h(2) should be returned since h(99) doesn't exist
        assert_eq!(result2.len(), 1);
        assert_eq!(result2[0].0, h(2));
        assert_eq!(*result2[0].1, bytes2);

        // Mempool unchanged (read-only)
        assert_eq!(mp.len().await, 3);
    }

    /// T76.3b: Test the canonical hash cache for DAG hybrid consumer.
    #[tokio::test]
    async fn canonical_hash_cache_insert_and_lookup() {
        let mp = SharedMempool::new(Mempool::new(4, 10_000, 10, 600));
        
        // Insert tx bytes with canonical hashes
        let bytes1 = vec![1u8, 2, 3];
        let bytes2 = vec![4u8, 5, 6];
        let canonical_hash1 = h(10);
        let canonical_hash2 = h(20);
        
        mp.insert_tx_bytes(canonical_hash1, bytes1.clone());
        mp.insert_tx_bytes(canonical_hash2, bytes2.clone());
        
        // Cache should have 2 entries
        assert_eq!(mp.tx_bytes_cache_len(), 2);
        
        // Lookup by canonical hash should succeed
        let result = mp.get_tx_bytes_by_canonical_hash(&[canonical_hash1, canonical_hash2]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, canonical_hash1);
        assert_eq!(*result[0].1, bytes1);
        assert_eq!(result[1].0, canonical_hash2);
        assert_eq!(*result[1].1, bytes2);
        
        // Lookup unknown hash should return empty
        let unknown = h(99);
        let result2 = mp.get_tx_bytes_by_canonical_hash(&[unknown]);
        assert_eq!(result2.len(), 0);
        
        // Evict one entry
        mp.evict_tx_bytes(&[canonical_hash1]);
        assert_eq!(mp.tx_bytes_cache_len(), 1);
        
        // Evicted entry should not be found
        let result3 = mp.get_tx_bytes_by_canonical_hash(&[canonical_hash1]);
        assert_eq!(result3.len(), 0);
        
        // Other entry still present
        let result4 = mp.get_tx_bytes_by_canonical_hash(&[canonical_hash2]);
        assert_eq!(result4.len(), 1);
    }
}