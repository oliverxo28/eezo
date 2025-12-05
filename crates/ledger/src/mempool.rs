#![cfg(feature = "pq44-runtime")]
use crate::{
    block::{tx_size_bytes, HEADER_BUDGET_BYTES},
    cert_store::CertLookupT4,
    consensus::SignedConsensusMsg,
    consensus_sig, sender_from_pubkey_first20,
    tx::TxWitness,
    tx_types::validate_tx_shape,
    validate_tx_stateful, verify_signed_tx, Accounts, Address, SignedTx, TxCore, TxStateError,
};
#[cfg(feature = "pq44-runtime")]
#[allow(unused_imports)]
use crate::consensus::SigBytes;

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("witness too large: {0} bytes")]
    WitnessTooLarge(usize),
    #[error("invalid signature")]
    InvalidSignature,
}

pub trait VerifyCache {
    fn verify_witness(&mut self, payload_hash: &[u8], witness: &TxWitness) -> bool;
}

/// Hard cap to avoid DoS with giant witnesses (tune in config)
pub const MAX_WITNESS_BYTES: usize = 4096;

// T77.SAFE-2: Use centralized dev-unsafe gate instead of inline function.
// This ensures that the env var only has effect when dev-unsafe feature is enabled.
fn dev_allow_unsigned_tx() -> bool {
    crate::dev_unsafe::allow_unsigned_tx()
}

#[cfg(feature = "mempool-batch-verify")]
const MP_BATCH_MIN: usize = 64;

/// SSZ-like size for TxWitness:
/// - payload_hash: 32 bytes (fixed)
/// - sigs: u32 count + each signature as `encode_bytes` = 4-byte len prefix + bytes
fn witness_size_bytes(w: &TxWitness) -> usize {
    // payload_hash (fixed 32) + vec length (u32)
    let mut sz = 32 + 4;
    for sig in &w.sigs {
        #[cfg(feature = "pq44-runtime")]
        let slen = sig.0.len();
        #[cfg(not(feature = "pq44-runtime"))]
        let slen = sig.len();
        sz += 4 + slen; // SSZ: u32 length + bytes
    }
    sz
}

pub fn validate_witness(
    payload_hash: &[u8],
    w: &TxWitness,
    cache: &mut impl VerifyCache,
) -> Result<(), MempoolError> {
    let sz = witness_size_bytes(w);
    if sz > MAX_WITNESS_BYTES {
        return Err(MempoolError::WitnessTooLarge(sz));
    }
    if !cache.verify_witness(payload_hash, w) {
        return Err(MempoolError::InvalidSignature);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct AdmissionOk {
    pub sender: Address,
    pub core: TxCore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    BadShape,
    BadSig,
    InvalidSender,
    BadNonce { expected: u64, got: u64 },
    InsufficientFunds { have: u128, need: u128 },
}

// T77.SAFE-3: Import Instant for TTL tracking
use std::time::Instant;

#[derive(Debug)]
pub struct MempoolEntry {
    tx: SignedTx,
    size_bytes: usize, // set at admit time from encoder (120 today)
    /// T77.SAFE-3: Timestamp when the tx was first seen.
    /// Used for TTL expiration. Does not survive restarts (devnet/single-node friendly).
    first_seen: Instant,
}

use std::sync::Arc;
use std::collections::{BTreeMap, HashMap};
// T77.SAFE-3: AtomicU64 for thread-safe expired tx counter
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

/// T77.SAFE-3: Configuration for mempool TTL behavior.
#[derive(Debug, Clone, Copy)]
pub struct MempoolTtlConfig {
    /// TTL duration in seconds. 0 = disabled (no expiry).
    /// Default is 0 for backwards compatibility.
    pub ttl_secs: u64,
}

impl Default for MempoolTtlConfig {
    fn default() -> Self {
        Self { ttl_secs: 0 }
    }
}

impl MempoolTtlConfig {
    /// Create a new TTL config with the given seconds value.
    /// A value of 0 disables TTL expiration.
    pub fn new(ttl_secs: u64) -> Self {
        Self { ttl_secs }
    }

    /// Check if TTL is enabled (non-zero).
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.ttl_secs > 0
    }
}

#[derive(Debug, Default)]
struct SenderQueue {
    /// Pending transactions for this sender keyed by nonce.
    /// Only the smallest nonce is considered "ready" at drain time.
    pending: BTreeMap<u64, MempoolEntry>,
}

pub struct Mempool {
    chain_id: [u8; 20],
    cert_store: Arc<dyn CertLookupT4 + Sync + Send>,
    /// Per-sender pending transactions keyed by nonce.
    ///
    /// This lets us keep higher-nonce transactions as "future" without
    /// dropping them; only the lowest nonce per sender is considered
    /// ready when building blocks.
    per_sender: HashMap<Address, SenderQueue>,
    /// T77.SAFE-3: TTL configuration for mempool entries.
    /// When ttl_secs > 0, entries older than TTL are purged during drain.
    ttl_config: MempoolTtlConfig,
    /// T77.SAFE-3: Counter of transactions expired due to TTL.
    /// Exposed via `expired_count()` for metrics integration.
    expired_total: AtomicU64,
}

impl Mempool {
    /// Create a new mempool with default TTL (disabled).
    pub fn new(chain_id: [u8; 20], cert_store: Arc<dyn CertLookupT4 + Sync + Send>) -> Self {
        Self::new_with_ttl(chain_id, cert_store, MempoolTtlConfig::default())
    }

    /// T77.SAFE-3: Create a new mempool with explicit TTL configuration.
    /// 
    /// # Arguments
    /// * `chain_id` - 20-byte chain identifier
    /// * `cert_store` - Certificate store for signature verification
    /// * `ttl_config` - TTL configuration (ttl_secs = 0 disables expiry)
    pub fn new_with_ttl(
        chain_id: [u8; 20],
        cert_store: Arc<dyn CertLookupT4 + Sync + Send>,
        ttl_config: MempoolTtlConfig,
    ) -> Self {
        if ttl_config.is_enabled() {
            log::info!(
                "mempool: TTL enabled with {} seconds expiry (T77.SAFE-3)",
                ttl_config.ttl_secs
            );
        } else {
            log::debug!("mempool: TTL disabled (T77.SAFE-3)");
        }
        Mempool {
            chain_id,
            cert_store,
            per_sender: HashMap::new(),
            ttl_config,
            expired_total: AtomicU64::new(0),
        }
    }

    pub fn admit_incoming(&mut self, msgs: Vec<SignedConsensusMsg>) {
        #[cfg(all(feature = "pq44-runtime", feature = "mempool-batch-verify"))]
        {
            if msgs.len() >= MP_BATCH_MIN {
                let flags = consensus_sig::verify_many(
                    &msgs,
                    self.chain_id,
                    &*self.cert_store,
                );
                let mut kept = Vec::with_capacity(msgs.len());
                for (i, m) in msgs.into_iter().enumerate() {
                    if flags[i] {
                        kept.push(m);
                    }
                }
                self.enqueue_all(kept);
                return;
            }
        }

        // default path: single-message verify
        for m in msgs {
            if self.verify_single(&m) {
                self.enqueue(m);
            }
        }
    }

    fn verify_single(&self, msg: &SignedConsensusMsg) -> bool {
        #[cfg(feature = "pq44-runtime")]
        {
            consensus_sig::verify_core(msg, &self.chain_id, &*self.cert_store).is_ok()
        }
        #[cfg(not(feature = "pq44-runtime"))]
        {
            consensus_sig::verify_core::<eezo_crypto::sig::ml_dsa::MlDsa2>(
                msg,
                &self.chain_id,
                &*self.cert_store,
            )
            .is_ok()
        }
    }

    fn enqueue(&mut self, _msg: SignedConsensusMsg) {
        // Placeholder: implement actual enqueue logic
    }

    #[cfg(all(feature = "pq44-runtime", feature = "mempool-batch-verify"))]
    fn enqueue_all(&mut self, msgs: Vec<SignedConsensusMsg>) {
        for msg in msgs {
            self.enqueue(msg);
        }
    }

    /// Enqueue a signed transaction into the mempool.
    ///
    /// This is sender/nonce-aware: for each sender we maintain a map keyed
    /// by nonce, and only the smallest nonce for that sender is considered
    /// ready during draining. Higher nonces are kept as futures and will
    /// be proposed only after the lower ones have been taken.
    pub fn enqueue_tx(&mut self, tx: SignedTx) {
        let size_bytes = tx_size_bytes(&tx);

        // Derive sender address from the pubkey. If this fails we simply
        // drop the transaction; higher layers (/tx endpoint) are expected
        // to perform proper validation and should not feed such txs under
        // normal operation.
        match sender_from_pubkey_first20(&tx) {
            Some(sender) => {
                let nonce = tx.core.nonce;
                // T77.SAFE-3: Record first_seen timestamp for TTL tracking
                let entry = MempoolEntry { tx, size_bytes, first_seen: Instant::now() };

                // Fix 1: Use or_default() instead of or_insert_with(SenderQueue::default)
                // and pass sender by move instead of clone.
                let q = self
                    .per_sender
                    .entry(sender)
                    .or_default();

                let existed = q.pending.contains_key(&nonce);
                if !existed {
                    q.pending.insert(nonce, entry);
                    log::debug!(
                        "ledger-mempool: enqueued tx sender={:?} nonce={}",
                        sender,
                        nonce
                    );
                } else {
                    log::debug!(
                        "ledger-mempool: duplicate nonce tx ignored sender={:?} nonce={}",
                        sender,
                        nonce
                    );
                }
            }
            None => {
                log::warn!(
                    "ledger-mempool: dropping tx with invalid pubkey (len={})",
                    tx.pubkey.len()
                );
            }
        }
    }

    // -------------------------
    // NEW: enqueue_admitted()
    // -------------------------
    pub fn enqueue_admitted(&mut self, ok: AdmissionOk, signed: SignedTx) {
        let size_bytes = tx_size_bytes(&signed);

        // Fix 2: Use or_default() instead of or_insert_with(SenderQueue::default)
        // and pass ok.sender by move instead of clone.
        // Insert into per-sender queue under the admitted nonce
        let q = self
            .per_sender
            .entry(ok.sender)
            .or_default();

        let existed = q.pending.contains_key(&ok.core.nonce);
        if !existed {
            q.pending.insert(
                ok.core.nonce,
                MempoolEntry {
                    tx: signed,
                    size_bytes,
                    // T77.SAFE-3: Record first_seen timestamp for TTL tracking
                    first_seen: Instant::now(),
                },
            );
            log::info!(
                "ledger-mempool: admitted tx sender={:?} nonce={} (queue now has {} tx(s))",
                ok.sender,
                ok.core.nonce,
                q.pending.len()
            );
        } else {
            log::debug!(
                "ledger-mempool: duplicate admitted nonce ignored sender={:?} nonce={}",
                ok.sender,
                ok.core.nonce
            );
        }
    }

    /// Drain fee-ordered candidates within the byte budget.
    ///
    /// Global order across all *ready* txs:
    ///   fee desc -> nonce asc.
    ///
    /// For each sender, only the transaction with the smallest nonce is
    /// considered ready at any given time. Higher nonces remain in the
    /// per-sender queue as futures and will be considered once the lower
    /// nonces have been removed by inclusion.
    pub fn drain_for_block(&mut self, max_bytes: usize) -> Vec<SignedTx> {
        // T77.SAFE-3: Purge expired transactions before building a block.
        // This ensures stale/zombie txs don't accumulate and cause confusion.
        let expired = self.purge_expired(Instant::now());
        if expired > 0 {
            log::debug!(
                "mempool: purged {} expired tx(s) before drain (T77.SAFE-3)",
                expired
            );
        }

        let mut used = HEADER_BUDGET_BYTES;
        let mut taken = Vec::new();

        // Log the initial mempool state before draining
        log::info!(
            "mempool: drain_for_block called, {} senders with pending txs, max_bytes={}",
            self.per_sender.len(),
            max_bytes
        );
        for (sender, q) in &self.per_sender {
            log::debug!(
                "mempool: sender {:?} has {} pending tx(s), lowest nonce: {:?}",
                sender,
                q.pending.len(),
                q.pending.iter().next().map(|(n, _)| n)
            );
        }

        loop {
            // Collect the current "ready" candidate (lowest nonce) for each sender.
            // Fix 3: Use *sender instead of sender.clone() to avoid cloning Address (which is Copy)
            let mut candidates: Vec<(Address, u64, &MempoolEntry)> = self
                .per_sender
                .iter()
                .filter_map(|(sender, q)| {
                    q.pending
                        .iter()
                        .next()
                        .map(|(nonce, entry)| (*sender, *nonce, entry))
                })
                .collect();

            if candidates.is_empty() {
                break;
            }

            // Sort by fee desc, then nonce asc.
            candidates.sort_by(|a, b| {
                let fee_a = a.2.tx.core.fee;
                let fee_b = b.2.tx.core.fee;
                fee_b
                    .cmp(&fee_a)
                    .then_with(|| a.1.cmp(&b.1))
            });

            // Pick the best candidate that still fits in the remaining budget.
            let mut picked: Option<(Address, u64)> = None;
            for (sender, nonce, entry) in candidates.into_iter() {
                let cost = entry.size_bytes;
                if used + cost <= max_bytes {
                    picked = Some((sender, nonce));
                    break;
                }
            }

            let Some((sender, nonce)) = picked else {
                break;
            };

            // Remove the picked tx from the per-sender queue.
            if let Some(q) = self.per_sender.get_mut(&sender) {
                if let Some(entry) = q.pending.remove(&nonce) {
                    used += entry.size_bytes;
                    taken.push(entry.tx);
                }
            }

            // Clean up empty sender queues.
            self.per_sender.retain(|_, q| !q.pending.is_empty());
        }

        log::info!(
            "mempool: drained {} transaction(s) for block (used {} bytes)",
            taken.len(),
            used - HEADER_BUDGET_BYTES
        );
        taken
    }

    pub fn len(&self) -> usize {
        self.per_sender
            .values()
            .map(|q| q.pending.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bytes_used(&self) -> usize {
        self.per_sender
            .values()
            .flat_map(|q| q.pending.values())
            .map(|entry| entry.size_bytes)
            .sum()
    }

    /// Remove committed transactions from the mempool by sender/nonce pairs.
    ///
    /// This is used to clean up transactions that were committed via the hybrid
    /// DAG path, which bypasses the normal drain_for_block mechanism.
    ///
    /// Each entry in `committed` is a (sender, nonce) pair.
    ///
    /// Returns the number of transactions actually removed.
    pub fn remove_committed_txs(&mut self, committed: &[(Address, u64)]) -> usize {
        let mut removed = 0;
        for &(sender, nonce) in committed {
            if let Some(q) = self.per_sender.get_mut(&sender) {
                if q.pending.remove(&nonce).is_some() {
                    removed += 1;
                }
            }
        }
        
        if removed > 0 {
            log::debug!(
                "mempool: removed {} committed txs (cleanup after hybrid block)",
                removed
            );
        }
        
        // Clean up empty sender queues after logging the removal count.
        self.per_sender.retain(|_, q| !q.pending.is_empty());
        
        removed
    }

    // =========================================================================
    // T77.SAFE-3: TTL expiration logic
    // =========================================================================

    /// T77.SAFE-3: Purge expired transactions from the mempool.
    ///
    /// Scans all sender queues and removes any transaction whose age exceeds
    /// the configured TTL. Empty sender queues are cleaned up afterwards.
    ///
    /// # Arguments
    /// * `now` - Current timestamp for age calculation
    ///
    /// # Returns
    /// Number of transactions removed due to TTL expiration.
    ///
    /// # Safety
    /// - TTL expiry can only delete transactions; it never resurrects or re-enqueues.
    /// - Does not change nonce rules: dropping a pending tx that was never committed is safe.
    /// - If TTL is 0 (disabled), returns immediately with 0.
    pub fn purge_expired(&mut self, now: Instant) -> usize {
        // Fast path: if TTL is disabled, do nothing
        if !self.ttl_config.is_enabled() {
            return 0;
        }

        let ttl_duration = std::time::Duration::from_secs(self.ttl_config.ttl_secs);
        let mut expired_count = 0;

        // Iterate over all senders and their queues
        for (_sender, queue) in self.per_sender.iter_mut() {
            // Collect nonces of expired entries to remove
            let expired_nonces: Vec<u64> = queue
                .pending
                .iter()
                .filter_map(|(nonce, entry)| {
                    // Use saturating_duration_since to handle clock drift safely
                    let age = now.saturating_duration_since(entry.first_seen);
                    if age > ttl_duration {
                        Some(*nonce)
                    } else {
                        None
                    }
                })
                .collect();

            // Remove expired entries
            for nonce in expired_nonces {
                queue.pending.remove(&nonce);
                expired_count += 1;
            }
        }

        // Clean up empty sender queues
        self.per_sender.retain(|_, q| !q.pending.is_empty());

        // Update the atomic counter for metrics
        if expired_count > 0 {
            self.expired_total.fetch_add(expired_count as u64, AtomicOrdering::Relaxed);
            // T77.SAFE-3: Also increment the Prometheus metric if metrics feature is enabled
            #[cfg(feature = "metrics")]
            crate::metrics::inc_mempool_expired(expired_count as u64);
            log::info!(
                "mempool: purged {} expired tx(s) due to TTL (T77.SAFE-3)",
                expired_count
            );
        }

        expired_count
    }

    /// T77.SAFE-3: Get the total count of transactions expired due to TTL.
    ///
    /// This counter is intended for metrics/observability (e.g., `eezo_mempool_expired_total`).
    /// The counter is monotonically increasing and survives across purge calls.
    #[inline]
    pub fn expired_count(&self) -> u64 {
        self.expired_total.load(AtomicOrdering::Relaxed)
    }

    /// T77.SAFE-3: Get the current TTL configuration.
    #[inline]
    pub fn ttl_config(&self) -> &MempoolTtlConfig {
        &self.ttl_config
    }
}

/// Stateless → signature → sender → stateful checks.
/// Note: this does **not** mutate state; use `apply_tx` in the block path.
pub fn admit_signed_tx(
    chain_id: [u8; 20],
    accts: &Accounts,
    tx: &SignedTx,
) -> Result<AdmissionOk, RejectReason> {
    // 1) shape
    if validate_tx_shape(&tx.core).is_err() {
        return Err(RejectReason::BadShape);
    }

    let dev_mode = dev_allow_unsigned_tx();

    // 2) signature (can be skipped in dev mode)
    if !dev_mode {
        // strict path – testnet / mainnet
        if !verify_signed_tx(chain_id, tx) {
            return Err(RejectReason::BadSig);
        }
    } else {
        // dev-only: skip signature verification, but log loudly
        log::warn!(
            "dev-mode: skipping signature verification for tx (nonce={} pubkey_len={})",
            tx.core.nonce,
            tx.pubkey.len()
        );
    }

    // 3) derive sender from pubkey (First 20 bytes logic)
    // usage: must match tx.rs::apply_signed_tx logic
    let sender = sender_from_pubkey_first20(tx).ok_or(RejectReason::InvalidSender)?;

    // 4) stateful checks (nonce, funds, etc.) ALWAYS enforced
    match validate_tx_stateful(accts, sender, &tx.core) {
        Ok(()) => Ok(AdmissionOk {
            sender,
            core: tx.core.clone(),
        }),
        Err(TxStateError::BadNonce { expected, got }) => {
            if got > expected {
                // Allow future nonces (gaps) for burst submissions
                Ok(AdmissionOk {
                    sender,
                    core: tx.core.clone(),
                })
            } else {
                Err(RejectReason::BadNonce { expected, got })
            }
        }
        Err(TxStateError::InsufficientFunds { have, need }) => {
            Err(RejectReason::InsufficientFunds { have, need })
        }
        Err(TxStateError::InvalidSender) => Err(RejectReason::InvalidSender),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::cert_store::ValidatedPk;
    use std::time::Duration;

    /// Stub cert lookup for testing (always returns None).
    struct StubCertLookup;
    impl CertLookupT4 for StubCertLookup {
        fn get_pk(&self, _signer: &[u8; 20], _at_height: u64) -> Option<ValidatedPk> {
            None
        }
    }

    fn test_mempool() -> Mempool {
        Mempool::new([0u8; 20], Arc::new(StubCertLookup))
    }

    /// T77.SAFE-3: Create a mempool with a specific TTL for testing.
    fn test_mempool_with_ttl(ttl_secs: u64) -> Mempool {
        Mempool::new_with_ttl(
            [0u8; 20],
            Arc::new(StubCertLookup),
            MempoolTtlConfig::new(ttl_secs),
        )
    }

    fn test_tx(sender_byte: u8, nonce: u64) -> (SignedTx, Address) {
        // Create a test tx with a deterministic sender address
        let mut pubkey = vec![0u8; 32];
        pubkey[0] = sender_byte;
        
        let mut addr_bytes = [0u8; 20];
        addr_bytes[0] = sender_byte;
        let sender = Address(addr_bytes);

        let mut to_bytes = [0u8; 20];
        to_bytes[0] = 0x01;
        let tx = SignedTx {
            core: TxCore {
                to: Address(to_bytes),
                amount: 100,
                fee: 1,
                nonce,
            },
            pubkey,
            sig: vec![],
        };

        (tx, sender)
    }

    /// T77.SAFE-3: Helper to create a MempoolEntry with a specific first_seen time.
    fn make_entry(tx: SignedTx, size_bytes: usize, first_seen: Instant) -> MempoolEntry {
        MempoolEntry { tx, size_bytes, first_seen }
    }

    /// T77.SAFE-3: Helper to create a MempoolEntry with first_seen = now.
    fn make_entry_now(tx: SignedTx, size_bytes: usize) -> MempoolEntry {
        make_entry(tx, size_bytes, Instant::now())
    }

    #[test]
    fn test_remove_committed_txs_basic() {
        let mut mp = test_mempool();
        
        // Enqueue some txs from sender A
        let (tx1, sender_a) = test_tx(0xAA, 0);
        let (tx2, _) = test_tx(0xAA, 1);
        let (tx3, _) = test_tx(0xAA, 2);
        
        // Manually insert into per_sender map (bypassing admission checks)
        let q = mp.per_sender.entry(sender_a).or_default();
        q.pending.insert(0, make_entry_now(tx1, 100));
        q.pending.insert(1, make_entry_now(tx2, 100));
        q.pending.insert(2, make_entry_now(tx3, 100));
        
        assert_eq!(mp.len(), 3);
        
        // Remove nonces 0 and 1
        let committed = vec![(sender_a, 0), (sender_a, 1)];
        let removed = mp.remove_committed_txs(&committed);
        
        assert_eq!(removed, 2);
        assert_eq!(mp.len(), 1);
        
        // Verify nonce 2 is still there
        assert!(mp.per_sender.get(&sender_a).is_some());
        assert!(mp.per_sender.get(&sender_a).unwrap().pending.contains_key(&2));
    }

    #[test]
    fn test_remove_committed_txs_multiple_senders() {
        let mut mp = test_mempool();
        
        let (tx_a0, sender_a) = test_tx(0xAA, 0);
        let (tx_a1, _) = test_tx(0xAA, 1);
        let (tx_b0, sender_b) = test_tx(0xBB, 0);
        
        // Insert txs from two senders
        let q_a = mp.per_sender.entry(sender_a).or_default();
        q_a.pending.insert(0, make_entry_now(tx_a0, 100));
        q_a.pending.insert(1, make_entry_now(tx_a1, 100));
        
        let q_b = mp.per_sender.entry(sender_b).or_default();
        q_b.pending.insert(0, make_entry_now(tx_b0, 100));
        
        assert_eq!(mp.len(), 3);
        
        // Remove one from each sender
        let committed = vec![(sender_a, 0), (sender_b, 0)];
        let removed = mp.remove_committed_txs(&committed);
        
        assert_eq!(removed, 2);
        assert_eq!(mp.len(), 1);
        
        // Sender A still has nonce 1
        assert!(mp.per_sender.get(&sender_a).is_some());
        // Sender B queue should be cleaned up (empty)
        assert!(mp.per_sender.get(&sender_b).is_none());
    }

    #[test]
    fn test_remove_committed_txs_nonexistent() {
        let mut mp = test_mempool();
        
        let (tx, sender) = test_tx(0xAA, 5);
        let q = mp.per_sender.entry(sender).or_default();
        q.pending.insert(5, make_entry_now(tx, 100));
        
        assert_eq!(mp.len(), 1);
        
        // Try to remove nonexistent nonces
        let committed = vec![
            (sender, 0),  // doesn't exist
            (sender, 10), // doesn't exist
            (Address([0xCC; 20]), 0), // sender doesn't exist
        ];
        let removed = mp.remove_committed_txs(&committed);
        
        assert_eq!(removed, 0);
        assert_eq!(mp.len(), 1); // Nothing was removed
    }

    #[test]
    fn test_remove_committed_txs_empty() {
        let mut mp = test_mempool();
        
        // Empty committed list
        let removed = mp.remove_committed_txs(&[]);
        assert_eq!(removed, 0);
        
        // Empty mempool
        let (_, sender) = test_tx(0xAA, 0);
        let removed = mp.remove_committed_txs(&[(sender, 0)]);
        assert_eq!(removed, 0);
    }

    // =========================================================================
    // T77.SAFE-3: TTL expiration tests
    // =========================================================================

    /// T77.SAFE-3: With TTL = 0 (disabled), nothing expires even if we simulate time passing.
    #[test]
    fn ttl_disabled_no_effect() {
        let mut mp = test_mempool(); // Default TTL = 0 (disabled)
        assert!(!mp.ttl_config().is_enabled());

        let (tx1, sender) = test_tx(0xAA, 0);
        
        // Insert with a very old first_seen (simulating an old tx)
        let old_time = Instant::now() - Duration::from_secs(3600); // 1 hour ago
        let q = mp.per_sender.entry(sender).or_default();
        q.pending.insert(0, make_entry(tx1, 100, old_time));
        
        assert_eq!(mp.len(), 1);
        
        // Purge should be a no-op when TTL is disabled
        let expired = mp.purge_expired(Instant::now());
        assert_eq!(expired, 0);
        assert_eq!(mp.len(), 1); // Still there
        assert_eq!(mp.expired_count(), 0);
    }

    /// T77.SAFE-3: Old txs are removed when TTL is enabled and they exceed the TTL.
    #[test]
    fn ttl_expires_old_txs() {
        let mut mp = test_mempool_with_ttl(60); // 60 second TTL
        assert!(mp.ttl_config().is_enabled());

        let (tx_old, sender_a) = test_tx(0xAA, 0);
        let (tx_new, sender_b) = test_tx(0xBB, 0);
        
        // Insert one old tx (2 minutes ago) and one new tx (just now)
        let old_time = Instant::now() - Duration::from_secs(120); // 2 minutes ago
        let new_time = Instant::now();
        
        let q_a = mp.per_sender.entry(sender_a).or_default();
        q_a.pending.insert(0, make_entry(tx_old, 100, old_time));
        
        let q_b = mp.per_sender.entry(sender_b).or_default();
        q_b.pending.insert(0, make_entry(tx_new, 100, new_time));
        
        assert_eq!(mp.len(), 2);
        
        // Purge with current time
        let expired = mp.purge_expired(Instant::now());
        assert_eq!(expired, 1); // Only the old one should be removed
        assert_eq!(mp.len(), 1); // Only the new one remains
        assert_eq!(mp.expired_count(), 1);
        
        // The old sender's queue should be cleaned up
        assert!(mp.per_sender.get(&sender_a).is_none());
        // The new sender's tx should still be there
        assert!(mp.per_sender.get(&sender_b).is_some());
    }

    /// T77.SAFE-3: Tx whose age is just under TTL is kept; one just over TTL is dropped.
    #[test]
    fn ttl_respects_boundary() {
        let ttl_secs = 60;
        let mut mp = test_mempool_with_ttl(ttl_secs);

        let (tx_under, sender_a) = test_tx(0xAA, 0);
        let (tx_over, sender_b) = test_tx(0xBB, 0);
        
        let now = Instant::now();
        
        // One tx is 59 seconds old (under TTL)
        let under_time = now - Duration::from_secs(59);
        // One tx is 61 seconds old (over TTL)
        let over_time = now - Duration::from_secs(61);
        
        let q_a = mp.per_sender.entry(sender_a).or_default();
        q_a.pending.insert(0, make_entry(tx_under, 100, under_time));
        
        let q_b = mp.per_sender.entry(sender_b).or_default();
        q_b.pending.insert(0, make_entry(tx_over, 100, over_time));
        
        assert_eq!(mp.len(), 2);
        
        // Purge at 'now'
        let expired = mp.purge_expired(now);
        assert_eq!(expired, 1); // Only the over-TTL one
        assert_eq!(mp.len(), 1);
        
        // The under-TTL tx should still be there
        assert!(mp.per_sender.get(&sender_a).is_some());
        // The over-TTL tx should be gone
        assert!(mp.per_sender.get(&sender_b).is_none());
    }

    /// T77.SAFE-3: When all txs for a sender expire, that sender's queue is removed.
    #[test]
    fn ttl_cleans_empty_senders() {
        let mut mp = test_mempool_with_ttl(60);

        let (tx1, sender) = test_tx(0xAA, 0);
        let (tx2, _) = test_tx(0xAA, 1);
        let (tx3, _) = test_tx(0xAA, 2);
        
        // All txs are old
        let old_time = Instant::now() - Duration::from_secs(120);
        
        let q = mp.per_sender.entry(sender).or_default();
        q.pending.insert(0, make_entry(tx1, 100, old_time));
        q.pending.insert(1, make_entry(tx2, 100, old_time));
        q.pending.insert(2, make_entry(tx3, 100, old_time));
        
        assert_eq!(mp.len(), 3);
        assert_eq!(mp.per_sender.len(), 1); // 1 sender
        
        // Purge all
        let expired = mp.purge_expired(Instant::now());
        assert_eq!(expired, 3);
        assert_eq!(mp.len(), 0);
        assert_eq!(mp.per_sender.len(), 0); // Sender queue cleaned up
        assert_eq!(mp.expired_count(), 3);
    }

    /// T77.SAFE-3: Expired counter accumulates across multiple purge calls.
    #[test]
    fn ttl_expired_count_accumulates() {
        let mut mp = test_mempool_with_ttl(60);

        // First batch: 2 old txs
        let (tx1, sender_a) = test_tx(0xAA, 0);
        let (tx2, _) = test_tx(0xAA, 1);
        let old_time = Instant::now() - Duration::from_secs(120);
        
        let q = mp.per_sender.entry(sender_a).or_default();
        q.pending.insert(0, make_entry(tx1, 100, old_time));
        q.pending.insert(1, make_entry(tx2, 100, old_time));
        
        let expired1 = mp.purge_expired(Instant::now());
        assert_eq!(expired1, 2);
        assert_eq!(mp.expired_count(), 2);

        // Second batch: 1 old tx
        let (tx3, sender_b) = test_tx(0xBB, 0);
        let q_b = mp.per_sender.entry(sender_b).or_default();
        q_b.pending.insert(0, make_entry(tx3, 100, old_time));
        
        let expired2 = mp.purge_expired(Instant::now());
        assert_eq!(expired2, 1);
        assert_eq!(mp.expired_count(), 3); // Accumulated
    }

    /// T77.SAFE-3: Empty mempool purge returns 0.
    #[test]
    fn ttl_purge_empty_mempool() {
        let mut mp = test_mempool_with_ttl(60);
        assert_eq!(mp.len(), 0);
        
        let expired = mp.purge_expired(Instant::now());
        assert_eq!(expired, 0);
        assert_eq!(mp.expired_count(), 0);
    }

    /// T77.SAFE-3: MempoolTtlConfig defaults and methods work correctly.
    #[test]
    fn ttl_config_basics() {
        // Default is disabled
        let default_cfg = MempoolTtlConfig::default();
        assert_eq!(default_cfg.ttl_secs, 0);
        assert!(!default_cfg.is_enabled());

        // Explicit 0 is disabled
        let zero_cfg = MempoolTtlConfig::new(0);
        assert!(!zero_cfg.is_enabled());

        // Non-zero is enabled
        let enabled_cfg = MempoolTtlConfig::new(300);
        assert!(enabled_cfg.is_enabled());
        assert_eq!(enabled_cfg.ttl_secs, 300);
    }
}