use crate::tx::{apply_tx, validate_tx_stateful, TxStateError};
use crate::tx_types::{validate_tx_shape, TxStatelessError};
use crate::{sender_from_pubkey_first20, Accounts, SignedTx, Supply};
use eezo_serde::ssz::encode_bytes;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
// During tests we skip signature verification so assembly doesn't filter out txs.
// In non-test builds (unless skip-sig-verify is set), we verify.
#[cfg(all(not(feature = "skip-sig-verify"), not(feature = "testing")))]
use crate::tx_sig::verify_signed_tx;
use std::collections::HashMap;

#[cfg(feature = "pq44-runtime")]
type MaybeVerifyCache<'a> = Option<&'a crate::verify_cache::VerifyCache>;
#[cfg(not(feature = "pq44-runtime"))]
type MaybeVerifyCache<'a> = Option<()>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub tx_root: [u8; 32],
    #[cfg(feature = "eth-ssz")]
    #[serde(default)]
    pub tx_root_v2: [u8; 32],
    pub fee_total: u128,
    pub tx_count: u32,
    pub timestamp_ms: u64,
    #[cfg(feature = "checkpoints")]
    #[serde(default)]
    pub qc_hash: [u8; 32],
}
#[cfg(feature = "checkpoints")]
impl BlockHeader {
    /// Accessor for the QC hash (used by tests and future APIs).
    pub fn qc_hash(&self) -> &[u8; 32] {
        &self.qc_hash
    }

    /// Builder-style helper (handy for tests/tooling; unused in core paths).
    pub fn with_qc_hash(mut self, qc_hash: [u8; 32]) -> Self {
        self.qc_hash = qc_hash;
        self
    }
}

// --- T27: BlockId newtype and BlockHeader helpers ---
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId(pub [u8; 32]);

impl From<[u8; 32]> for BlockId {
    fn from(b: [u8; 32]) -> Self {
        BlockId(b)
    }
}
impl From<BlockId> for [u8; 32] {
    fn from(id: BlockId) -> [u8; 32] {
        id.0
    }
}
impl AsRef<[u8; 32]> for BlockId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl BlockHeader {
    /// Canonical 32-byte hash (domain-separated; see `header_hash` below).
    #[inline]
    pub fn hash(&self) -> [u8; 32] {
        header_hash(self)
    }

    /// Canonical identifier (alias for `hash()` wrapped in `BlockId`).
    #[inline]
    pub fn id(&self) -> BlockId {
        BlockId(self.hash())
    }

    /// Optional convenience if you want a typed parent pointer in consensus.
    #[inline]
    pub fn parent_id(&self) -> BlockId {
        BlockId(self.prev_hash)
    }
}
// --- end T27 additions ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<SignedTx>,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    #[error("no transactions fit in the block")]
    Empty,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BlockError {
    #[error("transaction too large")]
    OversizedTx,
    #[error("other error: {0}")]
    Other(String),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BlockValidationError {
    #[error("tx_root mismatch")]
    TxRootMismatch,
    #[cfg(feature = "eth-ssz")]
    #[error("tx_root_v2 mismatch")]
    TxRootV2Mismatch,
    #[error("fee_total mismatch (expected {expected}, got {got})")]
    FeeTotalMismatch { expected: u128, got: u128 },
    #[error("tx_count mismatch (expected {expected}, got {got})")]
    TxCountMismatch { expected: u32, got: u32 },
    #[error("bad signature at tx #{idx}")]
    BadSignature { idx: usize },
    #[error("stateless shape error at tx #{idx}: {err}")]
    Shape { idx: usize, err: TxStatelessError },
    #[error("invalid sender at tx #{idx}")]
    InvalidSender { idx: usize },
    #[error("stateful error at tx #{idx}: {err}")]
    Stateful { idx: usize, err: TxStateError },
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BlockApplyError {
    #[error(transparent)]
    Invalid(#[from] BlockValidationError),
    #[error("stateful error at tx #{idx}: {err}")]
    Stateful { idx: usize, err: TxStateError },
    #[error("invalid sender at tx #{idx}")]
    InvalidSender { idx: usize },
}

fn hash256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

// deterministic local encoding for size/hash
pub fn encode_signed_tx(tx: &SignedTx) -> Vec<u8> {
    let mut out: Vec<u8> =
        Vec::with_capacity(20 + 16 + 16 + 8 + 4 + tx.pubkey.len() + 4 + tx.sig.len());
    out.extend_from_slice(tx.core.to.as_bytes());
    out.extend_from_slice(&tx.core.amount.to_le_bytes());
    out.extend_from_slice(&tx.core.fee.to_le_bytes());
    out.extend_from_slice(&tx.core.nonce.to_le_bytes());
    out.extend_from_slice(&(tx.pubkey.len() as u32).to_le_bytes());
    out.extend_from_slice(&tx.pubkey);
    out.extend_from_slice(&(tx.sig.len() as u32).to_le_bytes());
    out.extend_from_slice(&tx.sig);
    out
}

fn ssz_encode_signed_tx(tx: &SignedTx) -> Vec<u8> {
    let mut out = Vec::new();
    // Fixed fields in TxCore
    out.extend_from_slice(tx.core.to.as_bytes());
    out.extend(&tx.core.amount.to_le_bytes());
    out.extend(&tx.core.fee.to_le_bytes());
    out.extend(&tx.core.nonce.to_le_bytes());
    // Variable: pubkey and sig
    encode_bytes(&mut out, &tx.pubkey);
    encode_bytes(&mut out, &tx.sig);
    out
}

fn ssz_encode_block(blk: &Block) -> Vec<u8> {
    let mut out = Vec::new();
    // Header: fixed size fields
    out.extend(&blk.header.height.to_le_bytes());
    out.extend(&blk.header.prev_hash);
    out.extend(&blk.header.tx_root);
    out.extend(&blk.header.fee_total.to_le_bytes());
    out.extend(&blk.header.tx_count.to_le_bytes());
    out.extend(&blk.header.timestamp_ms.to_le_bytes());
    // txs: variable list, with offsets (no length prefix for list, assuming fixed tx_count in header)
    let tx_count = blk.txs.len();
    let offset_size = tx_count * 4; // u32 offsets
    let offsets_start = out.len();
    out.resize(out.len() + offset_size, 0); // placeholders
    let mut current_offset = out.len() as u32;
    for (i, tx) in blk.txs.iter().enumerate() {
        let tx_bytes = ssz_encode_signed_tx(tx);
        out[offsets_start + i * 4..offsets_start + (i + 1) * 4]
            .copy_from_slice(&current_offset.to_le_bytes());
        out.extend(&tx_bytes);
        current_offset += tx_bytes.len() as u32;
    }
    out
}

pub fn encoded_len_ssz(blk: &Block) -> usize {
    ssz_encode_block(blk).len()
}

pub fn tx_size_bytes(tx: &SignedTx) -> usize {
    ssz_encode_signed_tx(tx).len()
}
fn tx_hash(tx: &SignedTx) -> [u8; 32] {
    hash256(&encode_signed_tx(tx))
}

pub fn txs_root(txs: &[SignedTx]) -> [u8; 32] {
    if txs.is_empty() {
        return [0u8; 32]; // canonical empty root
    }
    let mut cat = Vec::with_capacity(txs.len() * 32);
    for tx in txs {
        cat.extend_from_slice(&tx_hash(tx));
    }
    hash256(&cat)
}

// --- begin: public budget helpers for mempool & assembly to share ---
#[cfg(not(feature = "checkpoints"))]
pub const HEADER_BUDGET_BYTES: usize = 100; // height(8) + prev_hash(32) + tx_root(32) + fee_total(16) + tx_count(4) + timestamp_ms(8)

#[cfg(feature = "checkpoints")]
pub const HEADER_BUDGET_BYTES: usize = 132;
// --- end: public budget helpers ---

// count only the block header fields in the fixed base
#[inline]
pub fn header_base_bytes() -> u64 {
	#[allow(unused_mut)]
    // height(8) + prev_hash(32) + tx_root(32) + fee_total(16) + tx_count(4) + timestamp_ms(8)
    let mut base = (8 + 32 + 32 + 16 + 4 + 8) as u64; // = 100
                                                     // Add tx_root_v2 when eth-ssz is enabled.
    #[cfg(feature = "eth-ssz")]
    {
        base += 32;
    }
    // --- PATCH (a) START ---
    #[cfg(feature = "checkpoints")]
    {
        base + 32 // qc_hash
    }
    #[cfg(not(feature = "checkpoints"))]
    {
        base
    }
    // --- PATCH (a) END ---
}

// count only the core tx fields (no pubkey/sig) for budget purposes
#[inline]
pub fn tx_budget_bytes(_tx: &SignedTx) -> u64 {
    // to(20) + amount(16) + fee(16) + nonce(8) = 60 bytes
    20 + 16 + 16 + 8
}

/// Helper to establish the canonical ordering of transactions for block assembly.
/// Groups by sender, sorts each group by nonce, then sorts groups by fee-density.
fn canonical_tx_order(candidates: Vec<SignedTx>) -> Vec<SignedTx> {
    // Group transactions by sender
    let mut sender_groups: HashMap<Option<crate::Address>, Vec<SignedTx>> = HashMap::new();
    for tx in candidates {
        let sender = sender_from_pubkey_first20(&tx);
        sender_groups.entry(sender).or_default().push(tx);
    }

    let mut fee_groups: Vec<(u128, u64, Vec<SignedTx>)> = Vec::new();

    for (_sender, mut txs) in sender_groups {
        // Sort transactions from same sender by a fully deterministic order:
        // nonce ASC, then higher fee first (paranoid), then pubkey, then sig, then tx hash.
        txs.sort_by(|a, b| {
            a.core
                .nonce
                .cmp(&b.core.nonce)
                .then_with(|| a.core.fee.cmp(&b.core.fee).reverse())
                .then_with(|| a.pubkey.cmp(&b.pubkey))
                .then_with(|| a.sig.cmp(&b.sig))
                .then_with(|| tx_hash(a).cmp(&tx_hash(b)))
        });

        // Rank groups by total_fee / total_bytes without floats: store (total_fee, total_bytes, txs)
        let total_fee: u128 = txs.iter().map(|tx| tx.core.fee).sum();
        // --- PATCH (b) START ---
        let total_bytes: u64 = txs.iter().map(tx_budget_bytes).sum();
        // --- PATCH (b) END ---
        fee_groups.push((total_fee, total_bytes, txs));
    }

    // Sort by total_fee/total_bytes (DESC) without division, then fully deterministic ties.
    // Compare a.total_fee * b.total_bytes vs b.total_fee * a.total_bytes
    fee_groups.sort_by(|(af, ab, atxs), (bf, bb, btxs)| {
        // Primary key: fee density (DESC) via cross-multiplication
        let lhs = U256::from(*af) * U256::from(*bb as u128);
        let rhs = U256::from(*bf) * U256::from(*ab as u128);
        rhs.cmp(&lhs) // DESC
            // Secondary: sender (first 20 bytes of pubkey) of the first tx in each group
            .then_with(|| {
                // --- PATCH (b) START ---
                let sa = atxs.first().and_then(sender_from_pubkey_first20);
                let sb = btxs.first().and_then(sender_from_pubkey_first20);
                // --- PATCH (b) END ---
                sa.cmp(&sb)
            })
            // Tertiary: first tx nonce (ASC)
            .then_with(|| {
                let na = atxs.first().map(|t| t.core.nonce).unwrap_or(0);
                let nb = btxs.first().map(|t| t.core.nonce).unwrap_or(0);
                na.cmp(&nb)
            })
            // Quaternary: first tx pubkey bytes
            .then_with(|| {
                let pa = atxs.first().map(|t| t.pubkey.as_slice()).unwrap_or(&[]);
                let pb = btxs.first().map(|t| t.pubkey.as_slice()).unwrap_or(&[]);
                pa.cmp(pb)
            })
            // Quinary: first tx signature bytes
            .then_with(|| {
                let sa = atxs.first().map(|t| t.sig.as_slice()).unwrap_or(&[]);
                let sb = btxs.first().map(|t| t.sig.as_slice()).unwrap_or(&[]);
                sa.cmp(sb)
            })
            // Final symmetry breakers in case fee density and first-tx keys match:
            // prefer smaller byte group first (packs better), then larger fee.
            .then_with(|| ab.cmp(bb)) // smaller total_bytes first
            .then_with(|| bf.cmp(af)) // larger total_fee first (DESC)
    });

    // Rebuild the final flat list of transactions in their canonical order
    let mut ordered_txs = Vec::new();
    for (_, _, txs) in fee_groups {
        ordered_txs.extend(txs);
    }
    ordered_txs
}

/// Deterministic assembler over *already mempool-admitted* candidates.
/// Re-checks signature + stateless shape for safety.
pub fn assemble_block(
    accounts: &Accounts, // NEW: for stateful nonce/balance checks
    chain_id: [u8; 20],
    prev_hash: [u8; 32],
    height: u64,
    max_bytes: usize,
    mut candidates: Vec<SignedTx>,
    now_ms: u64,
) -> Result<Block, AssembleError> {
    // chain_id is only used when sig verification is compiled in.
    #[cfg(any(feature = "skip-sig-verify", feature = "testing"))]
    let _ = chain_id;
    if max_bytes < header_base_bytes() as usize {
        return Err(AssembleError::Empty);
    }

    // reject oversized transactions (basic DoS guard)
    candidates.retain(|tx| bincode::serialized_size(tx).unwrap_or(u64::MAX) <= 1_000_000);

    // Establish the single, canonical transaction order.
    let ordered_candidates = canonical_tx_order(candidates);
    let candidate_count = ordered_candidates.len();

    let mut picked = Vec::new();
    let mut used = header_base_bytes();
    let max_u64 = max_bytes as u64;
    // Shadow state: advance nonce/balance as we include txs
    let mut shadow_accounts = accounts.clone();
    // Using a fresh supply for the assembly dry-run is fine; header.fee_total is computed from txs.
    let mut shadow_supply = Supply::default();

    // Greedily pick transactions from the canonical list that are valid and fit the budget.
    for (idx, tx) in ordered_candidates.into_iter().enumerate() {
        let size = tx_budget_bytes(&tx);
        if used + size > max_u64 {
            log::debug!("assemble_block: tx[{}] nonce={} rejected: exceeds byte budget", idx, tx.core.nonce);
            continue;
        }
        // Re-check sig (skip in tests and when skip-sig-verify is on)
        #[cfg(all(not(feature = "skip-sig-verify"), not(feature = "testing")))]
        if !verify_signed_tx(chain_id, &tx) {
            log::warn!("assemble_block: tx[{}] nonce={} rejected: invalid signature", idx, tx.core.nonce);
            continue;
        }
        if validate_tx_shape(&tx.core).is_err() {
            log::warn!("assemble_block: tx[{}] nonce={} rejected: invalid shape", idx, tx.core.nonce);
            continue;
        }
        // --- Stateful validation (on shadow) to filter gap/replay/insufficient funds
        let Some(sender) = sender_from_pubkey_first20(&tx) else {
            log::warn!("assemble_block: tx[{}] nonce={} rejected: cannot resolve sender", idx, tx.core.nonce);
            continue; // cannot resolve sender -> skip
        };
        
        // Log the validation attempt
        let shadow_acct = shadow_accounts.get(&sender);
        if let Err(e) = validate_tx_stateful(&shadow_accounts, sender, &tx.core) {
            log::info!(
                "assemble_block: tx[{}] sender={:?} nonce={} rejected: stateful validation failed: {:?} (shadow nonce={}, balance={})",
                idx, sender, tx.core.nonce, e, shadow_acct.nonce, shadow_acct.balance
            );
            continue; // e.g., BadNonce { expected: .., got: .. } or insufficient funds
        }
        // Advance shadow state so the next tx sees updated nonce/balance
        if let Err(e) = apply_tx(&mut shadow_accounts, &mut shadow_supply, sender, &tx.core) {
            log::warn!("assemble_block: tx[{}] nonce={} rejected: shadow apply failed: {:?}", idx, tx.core.nonce, e);
            continue;
        }

        log::info!("assemble_block: tx[{}] sender={:?} nonce={} INCLUDED in block", idx, sender, tx.core.nonce);
        picked.push(tx);
        used += size;
    }

    // Allow empty blocks for liveness. tx_root over empty set is [0u8; 32].
    log::info!(
        "assemble_block: height={} finished - picked {} tx(s) from {} candidate(s)",
        height,
        picked.len(),
        candidate_count
    );
    
    let tx_root = txs_root(&picked);
    let fee_total: u128 = picked.iter().map(|t| t.core.fee).sum();

    #[cfg(feature = "eth-ssz")]
    let tx_root_v2 = crate::eth_ssz::txs_root_v2(&picked);

    let header = BlockHeader {
        height,
        prev_hash,
        tx_root,
        #[cfg(feature = "eth-ssz")]
        tx_root_v2,
        fee_total,
        tx_count: picked.len() as u32,
        timestamp_ms: now_ms,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    };

    // NEW: budget observability
    #[cfg(feature = "metrics")]
    {
        let used_u64 = used; // includes header
        let hdr = header_base_bytes();
        let tx_used = used_u64.saturating_sub(hdr);
        let wasted = (max_bytes as u64).saturating_sub(used_u64);

        // --- PATCH (c) START ---
        crate::metrics::BLOCK_BYTES_USED.inc_by(tx_used);
        crate::metrics::BLOCK_BYTES_WASTED.inc_by(wasted);
        // --- PATCH (c) END ---
    }

    Ok(Block {
        header,
        txs: picked,
    })
}

/// Full validation: header integrity, tx_count/fees, shape, PQC sigs, and stateful rules (dry-run).
pub fn validate_block(
    accounts: &Accounts,
    supply: &Supply,
    chain_id: [u8; 20],
    blk: &Block,
) -> Result<(), BlockValidationError> {
    #[cfg(feature = "skip-sig-verify")]
    let _ = chain_id;
    // Header integrity
    let recomputed_root = txs_root(&blk.txs);
    if recomputed_root != blk.header.tx_root {
        return Err(BlockValidationError::TxRootMismatch);
    }

    #[cfg(feature = "eth-ssz")]
    {
        // Recompute canonical ETH-SSZ v2 tx root and compare.
        let tx_root_v2 = crate::eth_ssz::txs_root_v2(&blk.txs);
        if tx_root_v2 != blk.header.tx_root_v2 {
            return Err(BlockValidationError::TxRootV2Mismatch);
        }
    }

    let expected_fee_total: u128 = blk.txs.iter().map(|t| t.core.fee).sum();
    if expected_fee_total != blk.header.fee_total {
        return Err(BlockValidationError::FeeTotalMismatch {
            expected: expected_fee_total,
            got: blk.header.fee_total,
        });
    }

    let expected_tx_count = blk.txs.len() as u32;
    if expected_tx_count != blk.header.tx_count {
        return Err(BlockValidationError::TxCountMismatch {
            expected: expected_tx_count,
            got: blk.header.tx_count,
        });
    }

    // Use SHADOW copies so validation doesn't mutate live state
    let mut shadow_accounts = accounts.clone();
    let mut shadow_supply = supply.clone();

    // Tx-by-tx checks (stateless + stateful dry-run)
    for (i, tx) in blk.txs.iter().enumerate() {
        if let Err(err) = validate_tx_shape(&tx.core) {
            return Err(BlockValidationError::Shape { idx: i, err });
        }

        // Re-check sig (skip in tests and when skip-sig-verify is on)
        #[cfg(all(not(feature = "skip-sig-verify"), not(feature = "testing")))]
        if !verify_signed_tx(chain_id, tx) {
            return Err(BlockValidationError::BadSignature { idx: i });
        }

        let sender =
            sender_from_pubkey_first20(tx).ok_or(BlockValidationError::InvalidSender { idx: i })?;

        validate_tx_stateful(&shadow_accounts, sender, &tx.core)
            .map_err(|err| BlockValidationError::Stateful { idx: i, err })?;

        apply_tx(&mut shadow_accounts, &mut shadow_supply, sender, &tx.core)
            .map_err(|err| BlockValidationError::Stateful { idx: i, err })?;
    }

    Ok(())
}

/// Apply a previously validated block to state (balances, nonces, and fee burn).
pub fn apply_block(
    chain_id: [u8; 20],
    accounts: &mut Accounts,
    supply: &mut Supply,
    blk: &Block,
) -> Result<(), BlockApplyError> {
    // Always validate first for defense-in-depth
    validate_block(accounts, supply, chain_id, blk)?;

    // Apply each tx statefully (nonce, funds), then fees are burned as part of `apply_tx`
    for (i, tx) in blk.txs.iter().enumerate() {
        let sender =
            sender_from_pubkey_first20(tx).ok_or(BlockApplyError::InvalidSender { idx: i })?;
        // No need to re-validate stateful rules here, `validate_block` already did it on a shadow state.
        // We just apply directly.
        apply_tx(accounts, supply, sender, &tx.core)
            .map_err(|err| BlockApplyError::Stateful { idx: i, err })?;
    }
	// T32: chain height gauge — reflect committed height after successful apply
	#[cfg(feature = "metrics")]
	{
		crate::metrics::EEZO_CHAIN_HEIGHT_GAUGE.set(blk.header.height as i64);
	}

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderErr {
    BadSig,
    HashMismatch,
    Replay,
}

/// Deterministic canonical bytes for header signing.
/// b"EEZO-BLOCK\0" || chain_id(20) || height(u64 LE) || prev_hash(32) || tx_root(32)
/// || fee_total(u128 LE) || tx_count(u32 LE) || timestamp_ms(u64 LE)
/// #[cfg(feature = "checkpoints")] || qc_hash(32)
pub fn header_domain_bytes(chain_id: [u8; 20], h: &BlockHeader) -> Vec<u8> {
    // include qc_hash(32) capacity when feature is on (purely a hint)
    let mut out: Vec<u8> = Vec::with_capacity(
        11 + 20 + 8 + 32 + 32 + 16 + 4 + 8 + if cfg!(feature = "checkpoints") { 32 } else { 0 },
    );
    out.extend_from_slice(b"EEZO-BLOCK\0");
    out.extend_from_slice(&chain_id);
    out.extend_from_slice(&h.height.to_le_bytes());
    out.extend_from_slice(&h.prev_hash);
    out.extend_from_slice(&h.tx_root);
    out.extend_from_slice(&h.fee_total.to_le_bytes());
    out.extend_from_slice(&h.tx_count.to_le_bytes());
    out.extend_from_slice(&h.timestamp_ms.to_le_bytes());
    #[cfg(feature = "checkpoints")]
    {
        out.extend_from_slice(&h.qc_hash);
    }
    out
}

/// Deterministic header hash (domain-separated)
pub fn header_hash(h: &BlockHeader) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"EEZO-HDR\0");
    // --- PATCH (d) START ---
    hasher.update(h.height.to_le_bytes());
    hasher.update(h.prev_hash);
    hasher.update(h.tx_root);
    hasher.update(h.fee_total.to_le_bytes());
    hasher.update(h.tx_count.to_le_bytes());
    hasher.update(h.timestamp_ms.to_le_bytes());
    #[cfg(feature = "checkpoints")]
    {
        hasher.update(h.qc_hash);
    }
    // --- PATCH (d) END ---
    let out = hasher.finalize();
    let mut h32 = [0u8; 32];
    h32.copy_from_slice(&out);
    h32
}

/// Validate a block header against an expected hash, PQC-signature, and replay cache.
/// Returns the computed hash on success.
#[cfg_attr(not(feature = "pq44-runtime"), allow(unused_variables))]
pub fn validate_header(
    chain_id: [u8; 20],
    expected_hash: [u8; 32],
    header: &BlockHeader,
    proposer_pubkey: &[u8],
    signature: &[u8],
    cache: MaybeVerifyCache,
) -> Result<[u8; 32], HeaderErr> {
    let h = header_hash(header);
    if h != expected_hash {
        return Err(HeaderErr::HashMismatch);
    }

    #[cfg(feature = "pq44-runtime")]
    if let Some(c) = cache {
        // Check replay *before* expensive work
        if c.get(&h).unwrap_or(false) {
            return Err(HeaderErr::Replay);
        }
    }

    // PQC verify (ML-DSA-44)
    #[cfg(feature = "pq44-runtime")]
    {
        use pqcrypto_mldsa::mldsa44::{verify_detached_signature, DetachedSignature, PublicKey};
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

        let msg = header_domain_bytes(chain_id, header);

        match (
            PublicKey::from_bytes(proposer_pubkey),
            DetachedSignature::from_bytes(signature),
        ) {
            (Ok(pk), Ok(sig)) => {
                // --- PATCH (e) START ---
                if verify_detached_signature(&sig, &msg, &pk).is_err() {
                    return Err(HeaderErr::BadSig);
                }
                // --- PATCH (e) END ---
            }
            _ => return Err(HeaderErr::BadSig),
        }
    }

    // On success, mark as seen
    #[cfg(feature = "pq44-runtime")]
    if let Some(c) = cache {
        c.put(h.to_vec(), true);
    }

    // Non-PQ builds: hash/replay still enforced; signature skipped.
    Ok(h)
}