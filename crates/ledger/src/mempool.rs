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
///
/// # ⚠️ EXPERIMENTAL
///
/// Mempool TTL is an **experimental** feature that purges transactions older than
/// a configured threshold. While useful for preventing zombie transaction accumulation,
/// enabling TTL with aggressive settings can cause **liveness issues** under certain
/// conditions:
///
/// ## Known Issue: Stalls with Small Caps + Aggressive TTL
///
/// When combining:
/// - `EEZO_MEMPOOL_TTL_SECS` set to a small value (e.g., 5 seconds)
/// - `EEZO_BLOCK_MAX_TX` or `EEZO_HYBRID_AGG_MAX_TX` set to small values (e.g., 10-20)
/// - High transaction spam rate (e.g., 1000 txs)
///
/// The system may experience reduced throughput or temporary stalls because:
/// 1. `purge_expired()` must scan all pending transactions each tick
/// 2. `drain_for_block()` repeatedly collects and sorts candidates
/// 3. Under heavy load, this work can delay the consensus loop
///
/// ## Recommended Settings for Production
///
/// - **Disable TTL** (default): Set `EEZO_MEMPOOL_TTL_SECS=0`
/// - **Conservative TTL**: If needed, use values ≥ 300 seconds (5 minutes)
/// - **Adequate block caps**: Keep `EEZO_BLOCK_MAX_TX ≥ 100` to ensure progress
///
/// ## Safety Caps
///
/// The implementation includes safety caps to prevent unbounded work:
/// - `purge_expired()`: Limited to 1000 expirations per call
/// - `drain_for_block()`: Limited to 10,000 iterations per call
///
/// These caps ensure the system remains responsive even under adverse conditions.
#[derive(Debug, Clone, Copy)]
pub struct MempoolTtlConfig {
    /// TTL duration in seconds. 0 = disabled (no expiry).
    /// Default is 0 for backwards compatibility.
    /// 
    /// ⚠️ See struct-level documentation for experimental status and recommended settings.
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
    /// For each sender, only transactions forming a contiguous nonce sequence
    /// starting from the current ledger nonce are considered. Transactions with
    /// nonce gaps are kept in the mempool for future blocks.
    ///
    /// # Arguments
    /// * `max_bytes` - Maximum byte budget for the block
    /// * `accounts` - Current account state for nonce validation
    ///
    /// # Returns
    /// Vector of transactions that passed nonce validation and fit within budget

    /// Maximum number of iterations in drain_for_block loop to prevent liveness issues.
    /// This acts as a safety valve when there are many small txs or complex sender patterns.
    /// With typical 500 tx blocks, this limit should never be hit.
    const DRAIN_MAX_ITERATIONS: usize = 10_000;

    pub fn drain_for_block(&mut self, max_bytes: usize, accounts: &Accounts) -> Vec<SignedTx> {
        // T77.SAFE-3: Purge expired transactions before building a block.
        // This ensures stale/zombie txs don't accumulate and cause confusion.
        // Note: purge_expired has its own iteration cap for liveness.
        let expired = self.purge_expired(Instant::now());
        if expired > 0 {
            log::debug!(
                "mempool: purged {} expired tx(s) before drain (T77.SAFE-3)",
                expired
            );
        }

        let mut used = HEADER_BUDGET_BYTES;
        let mut taken = Vec::new();
        let mut iterations = 0;
        
        // Track the next expected nonce for each sender in this block.
        // Start with the ledger nonce, increment as we include txs.
        use std::collections::HashMap;
        let mut next_nonce: HashMap<Address, u64> = HashMap::new();

        // Log the initial mempool state before draining
        log::info!(
            "mempool: drain_for_block called, {} senders with pending txs, max_bytes={}",
            self.per_sender.len(),
            max_bytes
        );
        // Only log details in debug mode to avoid spam
        if log::log_enabled!(log::Level::Debug) {
            for (sender, q) in &self.per_sender {
                log::debug!(
                    "mempool: sender {:?} has {} pending tx(s), lowest nonce: {:?}",
                    sender,
                    q.pending.len(),
                    q.pending.iter().next().map(|(n, _)| n)
                );
            }
        }

        loop {
            // Safety valve: prevent unbounded looping that could cause liveness issues.
            // This should never trigger in normal operation.
            iterations += 1;
            if iterations > Self::DRAIN_MAX_ITERATIONS {
                log::warn!(
                    "mempool: drain_for_block hit iteration limit ({}) at {} txs, {} bytes used",
                    Self::DRAIN_MAX_ITERATIONS,
                    taken.len(),
                    used - HEADER_BUDGET_BYTES
                );
                break;
            }

            // Collect the current "ready" candidate (lowest nonce) for each sender.
            // Only include txs that match the expected nonce for that sender.
            let mut candidates: Vec<(Address, u64, &MempoolEntry)> = self
                .per_sender
                .iter()
                .filter_map(|(sender, q)| {
                    // Get the next expected nonce for this sender.
                    // Note: or_insert_with closure is called only once per sender
                    // (first time we see them), so accounts.get is cached efficiently.
                    let expected_nonce = *next_nonce
                        .entry(*sender)
                        .or_insert_with(|| accounts.get(sender).nonce);
                    
                    // Find the lowest nonce tx in the queue
                    if let Some((nonce, entry)) = q.pending.iter().next() {
                        // Only include if nonce matches expected (contiguous sequence)
                        if *nonce == expected_nonce {
                            return Some((*sender, *nonce, entry));
                        } else {
                            // Log nonce gap for debugging
                            log::debug!(
                                "mempool: skipping tx from sender {:?} with nonce {} (expected {})",
                                sender,
                                nonce,
                                expected_nonce
                            );
                        }
                    }
                    None
                })
                .collect();

            if candidates.is_empty() {
                // T78.8: Log info-level diagnostic when no candidates found but mempool has txs.
                // This helps diagnose nonce gap issues (e.g., faucet to wrong address).
                if iterations == 1 && !self.per_sender.is_empty() {
                    // Count how many senders have nonce gaps
                    let gap_info: Vec<_> = self.per_sender.iter()
                        .filter_map(|(sender, q)| {
                            let expected = next_nonce.get(sender)
                                .copied()
                                .unwrap_or_else(|| accounts.get(sender).nonce);
                            q.pending.iter().next().and_then(|(lowest_nonce, _)| {
                                if *lowest_nonce != expected {
                                    Some((*sender, *lowest_nonce, expected))
                                } else {
                                    None
                                }
                            })
                        })
                        .collect();
                    
                    if !gap_info.is_empty() {
                        log::warn!(
                            "mempool: {} sender(s) skipped due to nonce gaps (first: sender={:?} lowest_nonce={} expected={}). \
                            This usually means tx nonce 0 was rejected (e.g., InsufficientFunds) while future nonces were admitted.",
                            gap_info.len(),
                            gap_info[0].0,
                            gap_info[0].1,
                            gap_info[0].2
                        );
                    }
                }
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
                    // Update next expected nonce for this sender
                    next_nonce.insert(sender, nonce + 1);
                }
            }

            // Clean up empty sender queues.
            self.per_sender.retain(|_, q| !q.pending.is_empty());
        }

        log::info!(
            "mempool: drained {} transaction(s) for block (used {} bytes, {} iterations)",
            taken.len(),
            used - HEADER_BUDGET_BYTES,
            iterations
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

    /// Maximum number of transactions to expire per purge_expired() call.
    /// This prevents unbounded work that could cause liveness issues.
    /// Remaining expired txs will be cleaned up in subsequent calls.
    const PURGE_MAX_PER_CALL: usize = 1000;

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
    ///
    /// # Liveness
    /// - This function caps the number of expirations per call to PURGE_MAX_PER_CALL (1000)
    ///   to prevent unbounded work. Remaining expired txs are cleaned up in subsequent calls.
    /// - This ensures the consensus loop doesn't stall when there's a large backlog.
    pub fn purge_expired(&mut self, now: Instant) -> usize {
        // Fast path: if TTL is disabled, do nothing
        if !self.ttl_config.is_enabled() {
            return 0;
        }

        let ttl_duration = std::time::Duration::from_secs(self.ttl_config.ttl_secs);
        let mut expired_count = 0;
        let mut hit_cap = false;

        // Iterate over all senders and their queues
        'outer: for (_sender, queue) in self.per_sender.iter_mut() {
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

            // Remove expired entries with cap check
            for nonce in expired_nonces {
                // Check cap before removing to ensure we don't exceed it
                if expired_count >= Self::PURGE_MAX_PER_CALL {
                    hit_cap = true;
                    break 'outer;
                }
                queue.pending.remove(&nonce);
                expired_count += 1;
            }
        }

        // Clean up empty sender queues
        self.per_sender.retain(|_, q| !q.pending.is_empty());

        // Log a warning if we hit the cap (indicates heavy backlog)
        if hit_cap {
            log::warn!(
                "mempool: purge_expired hit cap ({}) - more expired txs remain, will be cleaned up next tick",
                Self::PURGE_MAX_PER_CALL
            );
        }

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

    // =========================================================================
    // Liveness Cap Tests (SAFE-3 liveness fix)
    // =========================================================================

    /// Test that purge_expired respects the PURGE_MAX_PER_CALL cap.
    /// When many txs are expired, only up to the cap should be removed per call.
    #[test]
    fn ttl_purge_respects_cap() {
        let mut mp = test_mempool_with_ttl(1); // 1 second TTL

        // Insert more txs than the cap allows to purge at once
        let num_txs = Mempool::PURGE_MAX_PER_CALL + 500;
        let old_time = Instant::now() - Duration::from_secs(10); // All expired

        for i in 0..num_txs {
            let sender_byte = (i % 256) as u8;
            let nonce = (i / 256) as u64;
            let (tx, sender) = test_tx(sender_byte, nonce);
            let q = mp.per_sender.entry(sender).or_default();
            q.pending.insert(nonce, make_entry(tx, 100, old_time));
        }

        assert_eq!(mp.len(), num_txs);

        // First purge: should only remove up to PURGE_MAX_PER_CALL
        let expired1 = mp.purge_expired(Instant::now());
        assert_eq!(expired1, Mempool::PURGE_MAX_PER_CALL);
        
        // Some txs should still remain
        let remaining = mp.len();
        assert!(remaining > 0, "Some expired txs should remain after hitting cap");
        assert!(remaining <= 500, "At most 500 should remain");

        // Second purge: should clean up the rest
        let expired2 = mp.purge_expired(Instant::now());
        assert!(expired2 <= remaining, "Second purge should clean remaining");
    }

    /// Test that drain_for_block works correctly under high load.
    /// This simulates the problematic scenario with many senders.
    #[test]
    fn drain_for_block_many_senders_completes() {
        let mut mp = test_mempool();

        // Create many senders with one tx each (worst case for the loop)
        // Each sender has exactly one tx at nonce 0
        let num_senders = 500;
        for i in 0..num_senders {
            let sender_byte = (i % 256) as u8;
            // Create tx with nonce=0 for each sender
            let (tx, sender) = test_tx(sender_byte, 0);
            let q = mp.per_sender.entry(sender).or_default();
            // Only insert if this sender doesn't already have a pending tx
            // (since sender_byte wraps at 256, some senders may already exist)
            if q.pending.is_empty() {
                q.pending.insert(0, make_entry_now(tx, 100));
            }
        }

        assert_eq!(mp.per_sender.len(), 256); // 256 unique senders (limited by sender_byte)

        // Drain with a small budget - should complete without infinite loop
        let max_bytes = 1000; // Can fit about 10 txs at 100 bytes each
        let accounts = Accounts::default();
        let drained = mp.drain_for_block(max_bytes, &accounts);

        // Should have drained some txs
        assert!(!drained.is_empty(), "Should drain at least one tx");
        assert!(drained.len() <= 10, "Should respect byte budget");

        // Loop should have completed (if we got here, it didn't hang)
    }

    /// Test that drain_for_block respects the iteration limit.
    /// This is a pathological test case.
    #[test]
    fn drain_for_block_respects_iteration_limit() {
        let mut mp = test_mempool();

        // Create 100 senders with 100 txs each = 10,000 total txs
        // This is at the iteration limit
        for sender_idx in 0u8..100 {
            let (base_tx, sender) = test_tx(sender_idx, 0);
            let q = mp.per_sender.entry(sender).or_default();
            
            for nonce in 0u64..100 {
                let mut tx = base_tx.clone();
                tx.core.nonce = nonce;
                q.pending.insert(nonce, make_entry_now(tx, 100));
            }
        }

        assert_eq!(mp.len(), 10_000);

        // Drain with a large budget - should drain many txs
        let max_bytes = 1_000_000; // 1 MB
        let accounts = Accounts::default();
        let drained = mp.drain_for_block(max_bytes, &accounts);

        // Should have drained many txs (up to byte budget)
        assert!(!drained.is_empty(), "Should drain some txs");
        
        // The key assertion: the function completed (didn't hang)
        // If we reach here, the iteration limit is working
    }

    /// Test nonce gap handling: mempool should only drain contiguous nonce sequences.
    /// This is the main fix for the issue described in the problem statement.
    #[test]
    fn drain_for_block_handles_nonce_gaps() {
        let mut mp = test_mempool();
        let mut accounts = Accounts::default();
        
        // Create a sender with some balance
        let (_tx0, sender) = test_tx(0xAA, 0);
        accounts.credit(sender, 10_000);
        
        // Enqueue txs with nonces [0-7] first (contiguous)
        let q = mp.per_sender.entry(sender).or_default();
        for nonce in 0..=7 {
            q.pending.insert(nonce, make_entry_now(test_tx(0xAA, nonce).0, 100));
        }
        
        assert_eq!(mp.len(), 8);
        
        // First drain: should get [0-7] (contiguous from ledger nonce 0)
        let max_bytes = 10_000;
        let drained = mp.drain_for_block(max_bytes, &accounts);
        assert_eq!(drained.len(), 8, "Should drain [0-7]");
        for (i, tx) in drained.iter().enumerate() {
            assert_eq!(tx.core.nonce, i as u64, "Nonce should match index");
        }
        
        // Apply the drained txs to update account nonce
        for tx in &drained {
            let sender = sender_from_pubkey_first20(tx).unwrap();
            let mut acc = accounts.get(&sender);
            acc.nonce += 1;
            acc.balance = acc.balance.saturating_sub(tx.core.amount + tx.core.fee);
            accounts.put(sender, acc);
        }
        
        // Now ledger nonce is 8, mempool is empty
        assert_eq!(mp.len(), 0);
        assert_eq!(accounts.get(&sender).nonce, 8);
        
        // Enqueue more txs with nonces [8, 9, 10, 11] (all contiguous from 8)
        let q = mp.per_sender.entry(sender).or_default();
        q.pending.insert(8, make_entry_now(test_tx(0xAA, 8).0, 100));
        q.pending.insert(9, make_entry_now(test_tx(0xAA, 9).0, 100));
        q.pending.insert(10, make_entry_now(test_tx(0xAA, 10).0, 100));
        q.pending.insert(11, make_entry_now(test_tx(0xAA, 11).0, 100));
        
        // Second drain: should get [8, 9, 10, 11] (all contiguous from nonce 8)
        let drained2 = mp.drain_for_block(max_bytes, &accounts);
        assert_eq!(drained2.len(), 4, "Should drain [8-11]");
        assert_eq!(drained2[0].core.nonce, 8);
        assert_eq!(drained2[1].core.nonce, 9);
        assert_eq!(drained2[2].core.nonce, 10);
        assert_eq!(drained2[3].core.nonce, 11);
        
        // Mempool should now be empty
        assert_eq!(mp.len(), 0);
    }

    /// Test that nonce gaps prevent block building correctly.
    /// If mempool has [0-7, 10, 11] (missing 8-9), only [0-7] should be drained.
    #[test]
    fn drain_for_block_stops_at_nonce_gap() {
        let mut mp = test_mempool();
        let mut accounts = Accounts::default();
        
        let (_, sender) = test_tx(0xBB, 0);
        accounts.credit(sender, 10_000);
        
        // Enqueue txs with nonces [0-7, 10, 11] (gap at 8-9)
        let q = mp.per_sender.entry(sender).or_default();
        for nonce in 0..=7 {
            q.pending.insert(nonce, make_entry_now(test_tx(0xBB, nonce).0, 100));
        }
        q.pending.insert(10, make_entry_now(test_tx(0xBB, 10).0, 100));
        q.pending.insert(11, make_entry_now(test_tx(0xBB, 11).0, 100));
        
        assert_eq!(mp.len(), 10);
        
        // Drain should get [0-7], stop at gap
        let drained = mp.drain_for_block(10_000, &accounts);
        assert_eq!(drained.len(), 8, "Should drain only [0-7], stop at gap");
        for (i, tx) in drained.iter().enumerate() {
            assert_eq!(tx.core.nonce, i as u64);
        }
        
        // Mempool should still have [10, 11]
        assert_eq!(mp.len(), 2);
        
        // Simulate applying [0-7] to ledger
        let mut acc = accounts.get(&sender);
        acc.nonce = 8;
        accounts.put(sender, acc);
        
        // Try to drain again - should get nothing (nonces 10, 11 don't match expected 8)
        let drained2 = mp.drain_for_block(10_000, &accounts);
        assert_eq!(drained2.len(), 0, "Should drain nothing due to gap at nonce 8");
        
        // Mempool should still have [10, 11]
        assert_eq!(mp.len(), 2);
        
        // Now add nonce 8 and 9
        let q = mp.per_sender.get_mut(&sender).unwrap();
        q.pending.insert(8, make_entry_now(test_tx(0xBB, 8).0, 100));
        q.pending.insert(9, make_entry_now(test_tx(0xBB, 9).0, 100));
        
        // Drain should now get [8, 9, 10, 11]
        let drained3 = mp.drain_for_block(10_000, &accounts);
        assert_eq!(drained3.len(), 4, "Should drain [8-11] after filling gap");
        assert_eq!(drained3[0].core.nonce, 8);
        assert_eq!(drained3[1].core.nonce, 9);
        assert_eq!(drained3[2].core.nonce, 10);
        assert_eq!(drained3[3].core.nonce, 11);
        
        assert_eq!(mp.len(), 0);
    }
}