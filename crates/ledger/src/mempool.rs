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

fn dev_allow_unsigned_tx() -> bool {
    match std::env::var("EEZO_DEV_ALLOW_UNSIGNED_TX") {
        Ok(v) => {
            let v = v.to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        }
        Err(_) => false,
    }
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

#[derive(Debug)]
pub struct MempoolEntry {
    tx: SignedTx,
    size_bytes: usize, // set at admit time from encoder (120 today)
}

use std::sync::Arc;
use std::collections::{BTreeMap, HashMap};

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
}

impl Mempool {
    pub fn new(chain_id: [u8; 20], cert_store: Arc<dyn CertLookupT4 + Sync + Send>) -> Self {
        Mempool {
            chain_id,
            cert_store,
            per_sender: HashMap::new(),
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
                let entry = MempoolEntry { tx, size_bytes };

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

    #[test]
    fn test_remove_committed_txs_basic() {
        let mut mp = test_mempool();
        
        // Enqueue some txs from sender A
        let (tx1, sender_a) = test_tx(0xAA, 0);
        let (tx2, _) = test_tx(0xAA, 1);
        let (tx3, _) = test_tx(0xAA, 2);
        
        // Manually insert into per_sender map (bypassing admission checks)
        let q = mp.per_sender.entry(sender_a).or_default();
        q.pending.insert(0, MempoolEntry { tx: tx1, size_bytes: 100 });
        q.pending.insert(1, MempoolEntry { tx: tx2, size_bytes: 100 });
        q.pending.insert(2, MempoolEntry { tx: tx3, size_bytes: 100 });
        
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
        q_a.pending.insert(0, MempoolEntry { tx: tx_a0, size_bytes: 100 });
        q_a.pending.insert(1, MempoolEntry { tx: tx_a1, size_bytes: 100 });
        
        let q_b = mp.per_sender.entry(sender_b).or_default();
        q_b.pending.insert(0, MempoolEntry { tx: tx_b0, size_bytes: 100 });
        
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
        q.pending.insert(5, MempoolEntry { tx, size_bytes: 100 });
        
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
}