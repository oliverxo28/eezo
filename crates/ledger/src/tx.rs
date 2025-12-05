#[cfg(feature = "pq44-runtime")]
use crate::consensus::{SigBytes, SIG_LEN};

#[cfg(feature = "pq44-runtime")]
use std::convert::TryInto;

#[cfg(feature = "pq44-runtime")]
pub type SigBytesCompat = SigBytes;

#[cfg(not(feature = "pq44-runtime"))]
pub type SigBytesCompat = Vec<u8>;

use crate::{tx_types::{validate_tx_shape, tx_domain_bytes}, Accounts, Address, Supply, TxCore};
use eezo_serde::ssz::{decode_bytes, encode_bytes};
use crate::SignedTx;

// Only import/enable sig verification when we actually use it (non-testing, non-skip builds).
#[cfg(all(feature = "pq44-runtime", not(feature = "skip-sig-verify"), not(feature = "testing")))]
use crate::tx_sig::verify_signed_tx;

// ====== PARALLEL EXECUTOR: ACCESS LIST TYPES ======
/// What piece of state a tx touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessTarget {
    /// An account (sender/receiver), keyed by address.
    Account(Address),
    /// Global supply bucket (fee burn currently writes here).
    Supply,
    /// Deterministic bucket derived from an address (sharding signal).
    Bucket(u16),
}

/// Whether a target is read or written. We conservatively mark writes for safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessKind {
    Read,
    Write,
}

/// One access entry used by the executor for conflict detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Access {
    pub target: AccessTarget,
    pub kind: AccessKind,
}

// T77.SAFE-2: Helper for dev-only unsigned transaction mode.
// This is now gated by the dev-unsafe feature at compile time.
// The environment variable EEZO_DEV_ALLOW_UNSIGNED_TX has no effect
// unless the build was compiled with the dev-unsafe feature.
#[inline]
pub fn dev_allow_unsigned_tx() -> bool {
    crate::dev_unsafe::allow_unsigned_tx()
}

/// Parse optional bucket count from env (`EEZO_EXEC_BUCKETS`). 0 or unset disables buckets.
fn exec_bucket_count() -> u16 {
    std::env::var("EEZO_EXEC_BUCKETS")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

/// A tiny, deterministic 16-bit mix over an Address to pick a bucket in [0, buckets).
#[inline]
fn bucket_for(addr: &Address, buckets: u16) -> u16 {
    if buckets == 0 { return 0; }
    // simple portable mixer (no new deps)
    let mut acc: u32 = 0x9E37_79B9;
    for b in addr.0 {
        acc ^= b as u32;
        acc = acc.rotate_left(5).wrapping_mul(0x85EB_CA6B);
    }
    (acc as u16) % buckets.max(1)
}

/// Helper: produce an ML-DSA signature for a TxCore using the canonical
/// tx_domain_bytes(chain_id20, &core) message.
///
/// This is intended for wallets / tx generators that want to construct
/// SignedTx objects compatible with the node.
#[cfg(feature = "pq44-runtime")]
pub fn sign_tx_core_mldsa(
    chain_id20: [u8; 20],
    core: &TxCore,
    sk_bytes: &[u8],
) -> anyhow::Result<SigBytesCompat> {
    use eezo_crypto::sig::ml_dsa::sign_single;

    // 1) Compute the canonical signing message:
    //    b"EEZO-TX\0" || chain_id(20) || nonce(u64 LE)
    //    || amount(u128 LE) || fee(u128 LE) || to(20)
    let msg = tx_domain_bytes(chain_id20, core);

    // 2) Use the crypto helper from T52.PQ1 (returns its own SigBytes wrapper)
    let sig = sign_single(sk_bytes, &msg)?;

    // 3) Convert into the ledger's SigBytesCompat ([u8; SIG_LEN]).
    let raw = sig.0;
    if raw.len() != SIG_LEN {
        return Err(anyhow::anyhow!("signature length mismatch"));
    }

    let mut arr = [0u8; SIG_LEN];
    arr.copy_from_slice(&raw);
    Ok(SigBytes(arr))
}

/// Minimal transaction witness container.
/// Flesh out later when we wire real tx verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxWitness {
    /// 32-byte hash (tx hash or merkle root)
    pub payload_hash: [u8; 32],
    /// ML-DSA detached signatures over a bound domain (placeholder here)
    pub sigs: Vec<SigBytesCompat>,
}

impl TxWitness {
    pub fn new(payload_hash: [u8; 32]) -> Self {
        Self {
            payload_hash,
            sigs: Vec::new(),
        }
    }
    pub fn add_sig(&mut self, sig: SigBytesCompat) {
        self.sigs.push(sig);
    }
    pub fn len(&self) -> usize {
        self.sigs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // payload_hash (32)
        out.extend_from_slice(&self.payload_hash);

        // sigs: SSZ list<bytes> as (u32 count + each length-prefixed)
        out.extend_from_slice(&(self.sigs.len() as u32).to_le_bytes());
        for s in &self.sigs {
            // PQ build: SigBytes(pub [u8; SIG_LEN]); non-PQ: s is Vec<u8>
            #[cfg(feature = "pq44-runtime")]
            {
                encode_bytes(&mut out, &s.0);
            }
            #[cfg(not(feature = "pq44-runtime"))]
            {
                encode_bytes(&mut out, s);
            }
        }
        out
    }

    pub fn from_ssz_bytes(b: &[u8]) -> Option<Self> {
        let mut off = 0usize;
        if b.len() < 32 {
            return None;
        }
        let mut ph = [0u8; 32];
        ph.copy_from_slice(&b[off..off + 32]);
        off += 32;

        if off + 4 > b.len() {
            return None;
        }
        let n = u32::from_le_bytes(b[off..off + 4].try_into().ok()?) as usize;
        off += 4;

        let mut sigs = Vec::with_capacity(n);
        for _ in 0..n {
            let raw = decode_bytes(b, &mut off);
            #[cfg(feature = "pq44-runtime")]
            {
                let arr: [u8; SIG_LEN] = raw.try_into().expect("signature length mismatch");
                sigs.push(SigBytes(arr));
            }
            #[cfg(not(feature = "pq44-runtime"))]
            {
                sigs.push(raw);
            }
        }

        Some(Self {
            payload_hash: ph,
            sigs,
        })
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TxStateError {
    #[error("invalid sender")]
    InvalidSender,
    #[error("bad nonce: expected {expected}, got {got}")]
    BadNonce { expected: u64, got: u64 },
    #[error("insufficient funds: have {have}, need {need}")]
    InsufficientFunds { have: u128, need: u128 },
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TxApplyError {
    #[error("invalid sender (pubkey too short)")]
    InvalidSender,
    #[error("bad signature")]
    BadSignature,
    #[error(transparent)]
    State(#[from] TxStateError),
}

/// TEMP helper: derive an Address from the first 20 bytes of the pubkey.
/// Replace with your canonical wallet address derivation later.
pub fn sender_from_pubkey_first20(tx: &crate::SignedTx) -> Option<Address> {
    if tx.pubkey.len() < 20 {
        return None;
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&tx.pubkey[..20]);
    Some(Address(a))
}

/// Pure stateful checks (balance/fees/nonce). Caller must already do shape + signature.
pub fn validate_tx_stateful(
    accts: &Accounts,
    sender: Address,
    core: &TxCore,
) -> Result<(), TxStateError> {
    // stateless shape guard (cheap sanity)
    validate_tx_shape(core).map_err(|_| TxStateError::InvalidSender)?; // reuse; error content not exposed here

    let acc = accts.get(&sender);
    // Nonce must match the CURRENT account nonce (first tx uses 0)
    let expected = acc.nonce;
    if core.nonce != expected {
        return Err(TxStateError::BadNonce {
            expected,
            got: core.nonce,
        });
    }

    // Balance must cover amount + fee
    let need = core.amount.saturating_add(core.fee);
    if acc.balance < need {
        return Err(TxStateError::InsufficientFunds {
            have: acc.balance,
            need,
        });
    }
    Ok(())
}

/// Apply state changes (deduct sender amount+fee, increment nonce, credit receiver, burn fee)
pub fn apply_tx(
    accts: &mut Accounts,
    supply: &mut Supply,
    sender: Address,
    core: &TxCore,
) -> Result<(), TxStateError> {
    // Log before validation - accounts.get() always returns a valid Account (zero balance if new)
    let sender_before = accts.get(&sender);
    log::info!(
        "apply_tx: sender={:?} nonce={} (current_nonce={}, balance={}) amount={} fee={} to={:?}",
        sender,
        core.nonce,
        sender_before.nonce,
        sender_before.balance,
        core.amount,
        core.fee,
        core.to
    );
    
    validate_tx_stateful(accts, sender, core)?;

    let need = core.amount.saturating_add(core.fee);

    // debit sender
    let mut s = accts.get(&sender);
    s.balance = s.balance.saturating_sub(need);
    s.nonce = s.nonce.saturating_add(1);
    accts.put(sender, s.clone());

    // credit receiver
    let mut r = accts.get(&core.to);
    r.balance = r.balance.saturating_add(core.amount);
    accts.put(core.to, r);

    // For now: burn the fee (operator policy; can redirect to reward pool later)
    supply.apply_burn(core.fee);

    // Log after application - use the saved sender state to avoid redundant lookup
    log::info!(
        "apply_tx: ✅ success, sender={:?} new_nonce={} new_balance={}",
        sender,
        s.nonce,
        s.balance
    );

    Ok(())
}

/// Verify and apply a SignedTx:
///  - derive sender from pubkey (temporary first-20-bytes address)
///  - verify signature against domain(chain_id || core)
///  - run stateful checks (nonce/balances) and apply
pub fn apply_signed_tx(
    accts: &mut Accounts,
    supply: &mut Supply,
    chain_id: [u8; 20],
    stx: &SignedTx,
) -> Result<(), TxApplyError> {
    // 1) derive sender
    let sender = sender_from_pubkey_first20(stx).ok_or(TxApplyError::InvalidSender)?;

    // 2) Signature verification (domain-binds to chain_id) — skip in tests/skip-sig-verify.
    #[cfg(all(feature = "pq44-runtime", not(feature = "skip-sig-verify"), not(feature = "testing")))]
    {
        // --- FIX START: Skip verification if env var is set ---
        if !dev_allow_unsigned_tx() && !verify_signed_tx(chain_id, stx) {
            return Err(TxApplyError::BadSignature);
        }
        // --- FIX END ---
    }
    // silence unused param in testing/skip builds
    #[cfg(any(feature = "skip-sig-verify", feature = "testing"))]
    let _ = chain_id;

    // 3) stateful checks + apply using existing helpers
    validate_tx_stateful(accts, sender, &stx.core)?;
    apply_tx(accts, supply, sender, &stx.core)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecheckErr {
    InvalidSender,
    BadSignature,
    BadNonce { expected: u64, got: u64 },
    InsufficientFunds { have: u128, need: u128 },
}

// ====== PARALLEL EXECUTOR: SIGNED TX ACCESS LIST ======
impl SignedTx {
    /// Returns a conservative access list used by the parallel executor.
    ///
    /// Current model (safe over-approximation for conflict detection):
    /// - **Writes** sender account (nonce+balance)
    /// - **Writes** receiver account (balance)
    /// - **Writes** global supply (fee burn)
    /// - **Writes** optional deterministic buckets (when EEZO_EXEC_BUCKETS > 0)
    ///
    /// If the sender address cannot be derived (invalid pubkey), we omit it here;
    /// such txs should be rejected during precheck before scheduling.
    pub fn access_list(&self) -> Vec<Access> {
        let mut v = Vec::with_capacity(5);

        // core per-tx accesses (conservative writes for safety)
        if let Some(sender) = sender_from_pubkey_first20(self) {
            v.push(Access {
                target: AccessTarget::Account(sender),
                kind: AccessKind::Write,
            });
        }
        v.push(Access {
            target: AccessTarget::Account(self.core.to),
            kind: AccessKind::Write,
        });
        v.push(Access {
            target: AccessTarget::Supply,
            kind: AccessKind::Write,
        });

        // optional deterministic buckets (future sharded executor; off by default)
        let buckets = exec_bucket_count();
        if buckets > 0 {
            if let Some(sender) = sender_from_pubkey_first20(self) {
                let sb = bucket_for(&sender, buckets);
                v.push(Access {
                    target: AccessTarget::Bucket(sb),
                    kind: AccessKind::Write,
                });
            }
            let rb = bucket_for(&self.core.to, buckets);
            v.push(Access {
                target: AccessTarget::Bucket(rb),
                kind: AccessKind::Write,
            });
        }

        v
    }
}

pub fn precheck_tx(accts: &Accounts, chain_id: [u8;20], stx: &SignedTx) -> Result<(), PrecheckErr> {
    let sender = sender_from_pubkey_first20(stx).ok_or(PrecheckErr::InvalidSender)?;
    #[cfg(all(feature = "pq44-runtime", not(feature = "skip-sig-verify"), not(feature = "testing")))]
    {
        // --- FIX START: Skip verification if env var is set ---
        if !dev_allow_unsigned_tx() && !verify_signed_tx(chain_id, stx) {
            return Err(PrecheckErr::BadSignature);
        }
        // --- FIX END ---
    }
    #[cfg(any(feature = "skip-sig-verify", feature = "testing"))]
    let _ = chain_id;
    // reuse your stateful check to keep single source of truth
    validate_tx_stateful(accts, sender, &stx.core).map_err(|e| match e {
        TxStateError::BadNonce{expected,got} => PrecheckErr::BadNonce{expected,got},
        TxStateError::InsufficientFunds{have,need} => PrecheckErr::InsufficientFunds{have,need},
        TxStateError::InvalidSender => PrecheckErr::InvalidSender,
    })
}


// ====== STATE SYNC: SPARSE MERKLE PROOF HELPERS ======
#[cfg(feature = "state-sync")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMerkleProof {
    /// 32-byte key whose bit-path determines left/right at each tree level (LSB-first).
    pub key: [u8; 32],
    /// Leaf/value commitment (32-byte hash) for the key.
    pub value_hash: [u8; 32],
    /// Sibling nodes from leaf level upwards (each 32 bytes).
    pub siblings: Vec<[u8; 32]>,
}

#[cfg(feature = "state-sync")]
fn ssz_hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Fallback: SHA3-256(left || right)
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verify a Sparse-Merkle inclusion proof against `root`.
#[cfg(feature = "state-sync")]
pub fn verify_sparse_merkle_proof(root: &[u8; 32], proof: &SparseMerkleProof) -> bool {
    let mut acc = proof.value_hash;
    // Interpret key bits LSB-first (bit i decides position at level i).
    for (i, sib) in proof.siblings.iter().enumerate() {
        let byte = proof.key[i / 8];
        let bit = (byte >> (i % 8)) & 1;
        acc = if bit == 0 {
            ssz_hash_pair(&acc, sib)
        } else {
            ssz_hash_pair(sib, &acc)
        };
    }
    &acc == root
}