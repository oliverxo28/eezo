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

pub struct MempoolEntry {
    tx: SignedTx,
    size_bytes: usize, // set at admit time from encoder (120 today)
}

use std::sync::Arc;

pub struct Mempool {
    chain_id: [u8; 20],
    cert_store: Arc<dyn CertLookupT4 + Sync + Send>,
    // Pending user transactions (simple queue for now)
    txs: Vec<MempoolEntry>,
}

impl Mempool {
    pub fn new(chain_id: [u8; 20], cert_store: Arc<dyn CertLookupT4 + Sync + Send>) -> Self {
        Mempool {
            chain_id,
            cert_store,
            txs: Vec::new(),
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

    /// Stateless enqueue: quick checks optional; full state is re-validated during block validate.
    /// Calls existing admit_signed_tx for validation before push.
    pub fn enqueue_tx(&mut self, tx: SignedTx) {
        let size_bytes = tx_size_bytes(&tx);
        self.txs.push(MempoolEntry { tx, size_bytes });
    }

    /// Drain fee-ordered candidates within the byte budget.
    /// Order: fee desc -> nonce asc -> (stable arrival order as tie-break).
    pub fn drain_for_block(&mut self, max_bytes: usize) -> Vec<SignedTx> {
        if self.txs.is_empty() {
            return Vec::new();
        }

        // Sort in place (stable to preserve arrival order as final tie-break)
        self.txs.sort_by(|a, b| {
            // Fee and nonce fields assumed as a.core.fee (u64) and a.core.nonce (u64)
            b.tx.core
                .fee
                .cmp(&a.tx.core.fee)
                .then_with(|| a.tx.core.nonce.cmp(&b.tx.core.nonce))
        });

        let mut used = HEADER_BUDGET_BYTES;
        let mut taken = Vec::new();
        let mut keep = Vec::new();

        for entry in self.txs.drain(..) {
            let cost = entry.size_bytes;
            if used + cost <= max_bytes {
                used += cost;
                taken.push(entry.tx);
            } else {
                keep.push(entry);
            }
        }
        self.txs = keep;
        taken
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
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
    // 2) signature
    if !verify_signed_tx(chain_id, tx) {
        return Err(RejectReason::BadSig);
    }
    // 3) derive sender (temporary: first 20 bytes of pubkey)
    let sender = sender_from_pubkey_first20(tx).ok_or(RejectReason::InvalidSender)?;

    // 4) stateful checks
    match validate_tx_stateful(accts, sender, &tx.core) {
        Ok(()) => Ok(AdmissionOk {
            sender,
            core: tx.core.clone(),
        }),
        Err(TxStateError::BadNonce { expected, got }) => {
            Err(RejectReason::BadNonce { expected, got })
        }
        Err(TxStateError::InsufficientFunds { have, need }) => {
            Err(RejectReason::InsufficientFunds { have, need })
        }
        Err(TxStateError::InvalidSender) => Err(RejectReason::InvalidSender),
    }
}
