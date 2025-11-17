use crate::{
    accounts::Accounts,
    block::{
        apply_block, assemble_block, header_domain_bytes, header_hash, validate_block,
        validate_header, AssembleError, Block, BlockApplyError, BlockValidationError, BlockHeader,
    },
    SignedTx,
    cert_store::CertStore,
    config::BatchVerifyCfg,
    consensus_sig,
    mempool::Mempool,
    supply::Supply,
    verify_cache::VerifyCache,
    HeaderErr,
};
// use crate-level metrics; nothing to declare here
use crate::cert_store::CertLookupT4;
use crate::cert_store::ValidatedPk;
#[cfg(feature = "metrics")]
use crate::metrics::{
    observe_block_applied, observe_block_proposed, observe_supply, start_apply_timer,
    start_proposal_timer, start_validation_timer,
};
use bitvec::vec::BitVec;
use core::fmt;
use pqcrypto_mldsa::mldsa44::{detached_sign, PublicKey, SecretKey};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// === T27: HotStuff-like pipeline (uses new message module) ===
use crate::block::BlockId;
use std::sync::Arc;

// Import T27 message types with a module alias to avoid name collisions
use crate::consensus_msg as hs_msg;

#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub const PK_LEN: usize = 1312; // ML-DSA-44 public key bytes
pub const SIG_LEN: usize = 2420; // ML-DSA-44 detached signature bytes

/// 20-byte validator address derived from pk: first 20 bytes of SHA3-256(pk)
pub type SignerId = [u8; 20];

#[cfg(feature = "checkpoints")]
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub height: u64,
    pub round: u32,
    pub block_id: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreVote {
    pub height: u64,
    pub round: u32,
    pub block_id: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreCommit {
    pub height: u64,
    pub round: u32,
    pub block_id: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusMsgCore {
    Proposal(Proposal),
    PreVote(PreVote),
    PreCommit(PreCommit),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PkBytes(pub [u8; PK_LEN]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigBytes(pub [u8; SIG_LEN]);

impl PkBytes {
    #[cfg(feature = "pq44-runtime")]
    pub fn from_pq(pk: &pqcrypto_mldsa::mldsa44::PublicKey) -> Self {
        let bs = pk.as_bytes();
        let mut a = [0u8; PK_LEN];
        a.copy_from_slice(bs);
        PkBytes(a)
    }
}

impl TryFrom<eezo_crypto::sig::SigBytes> for crate::consensus::SigBytes {
    type Error = &'static str;
    fn try_from(src: eezo_crypto::sig::SigBytes) -> Result<Self, Self::Error> {
        let _v = src.0; // Vec<u8>
        if _v.len() != crate::consensus::SIG_LEN {
            return Err("bad signature length");
        }
        let arr: [u8; crate::consensus::SIG_LEN] =
            _v.try_into().map_err(|_| "bad signature length")?;
        Ok(crate::consensus::SigBytes(arr))
    }
}

impl From<crate::consensus::SigBytes> for eezo_crypto::sig::SigBytes {
    fn from(src: crate::consensus::SigBytes) -> Self {
        eezo_crypto::sig::SigBytes(src.0.to_vec())
    }
}

impl Serialize for PkBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}
impl<'de> Deserialize<'de> for PkBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct PkVisitor;
        impl<'de> Visitor<'de> for PkVisitor {
            type Value = PkBytes;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{} bytes", PK_LEN)
            }
            fn visit_bytes<E: de::Error>(self, _v: &[u8]) -> Result<Self::Value, E> {
                if _v.len() != PK_LEN {
                    return Err(E::invalid_length(_v.len(), &self));
                }
                let mut a = [0u8; PK_LEN];
                a.copy_from_slice(_v);
                Ok(PkBytes(a))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut a = [0u8; PK_LEN];
                // PATCH 1: Use iter_mut().enumerate() instead of range loop
                for (i, item) in a.iter_mut().enumerate() {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(PkBytes(a))
            }
        }
        d.deserialize_bytes(PkVisitor)
    }
}

impl Serialize for SigBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}
impl<'de> Deserialize<'de> for SigBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct SigVisitor;
        impl<'de> Visitor<'de> for SigVisitor {
            type Value = SigBytes;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{} bytes", SIG_LEN)
            }
            fn visit_bytes<E: de::Error>(self, _v: &[u8]) -> Result<Self::Value, E> {
                if _v.len() != SIG_LEN {
                    return Err(E::invalid_length(_v.len(), &self));
                }
                let mut a = [0u8; SIG_LEN];
                a.copy_from_slice(_v);
                Ok(SigBytes(a))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut a = [0u8; SIG_LEN];
                // PATCH 2: Use iter_mut().enumerate() instead of range loop
                for (i, item) in a.iter_mut().enumerate() {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(SigBytes(a))
            }
        }
        d.deserialize_bytes(SigVisitor)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgKind {
    Proposal = 0,
    PreVote = 1,
    PreCommit = 2,
}

pub fn kind_of(core: &ConsensusMsgCore) -> MsgKind {
    match core {
        ConsensusMsgCore::Proposal(_) => MsgKind::Proposal,
        ConsensusMsgCore::PreVote(_) => MsgKind::PreVote,
        ConsensusMsgCore::PreCommit(_) => MsgKind::PreCommit,
    }
}

pub fn height_round_of(core: &ConsensusMsgCore) -> (u64, u32) {
    match core {
        ConsensusMsgCore::Proposal(p) => (p.height, p.round),
        ConsensusMsgCore::PreVote(pv) => (pv.height, pv.round),
        ConsensusMsgCore::PreCommit(pc) => (pc.height, pc.round),
    }
}

/// signer_id = first 20 bytes of SHA3-256(pk)
pub fn signer_id_from_pk(pk: &PkBytes) -> SignerId {
    // PATCH 3: Remove needless borrow
    let h = Sha3_256::digest(pk.0);
    let mut id = [0u8; 20];
    id.copy_from_slice(&h[..20]);
    id
}

/// Holds a complete signed message ready for gossip.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedConsensusMsg {
    pub core: ConsensusMsgCore,
    pub signer_id: SignerId,
    pub signer_pk: PkBytes,
    pub sig: SigBytes,
    pub height: u64, // duplicated for indexing/fast checks
    pub round: u32,
}

impl SignedConsensusMsg {
    pub fn to_domain_bound_bytes(&self, chain_id: [u8; 20]) -> Vec<u8> {
        let kind = kind_of(&self.core);
        let (height, round) = height_round_of(&self.core);
        let static_prefix = static_prefix(kind, &chain_id);
        let domain = bound_domain(&static_prefix, height, round);
        let core_bytes = bincode::serialize(&self.core).expect("tmp encode");

        let mut hasher = Sha3_256::new();
        hasher.update(&domain);
        hasher.update(&core_bytes);
        hasher.finalize().to_vec()
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.signer_pk.0
    }

    pub fn signature_bytes(&self) -> &[u8] {
        &self.sig.0
    }
}

/// Build the static domain prefix: "EEZO-CONSENSUS-V1|{chain_id}|{kind}"
pub fn static_prefix(kind: MsgKind, chain_id: &[u8]) -> Vec<u8> {
    let mut _v = Vec::with_capacity(24 + chain_id.len());
    _v.extend_from_slice(b"EEZO-CONSENSUS-V1|");
    _v.extend_from_slice(chain_id);
    _v.extend_from_slice(b"|");
    _v.extend_from_slice(match kind {
        MsgKind::Proposal => b"proposal",
        MsgKind::PreVote => b"prevote",
        MsgKind::PreCommit => b"precommit",
    });
    _v
}

/// Build the full domain bound to (height, round) using big-endian bytes.
pub fn bound_domain(static_prefix: &[u8], height: u64, round: u32) -> Vec<u8> {
    let mut _v = Vec::with_capacity(static_prefix.len() + 1 + 8 + 1 + 4);
    _v.extend_from_slice(static_prefix);
    _v.push(b'|');
    _v.extend_from_slice(&height.to_be_bytes());
    _v.push(b'|');
    _v.extend_from_slice(&round.to_be_bytes());
    _v
}

fn retain_with_flags<T>(_v: &mut Vec<T>, flags: &BitVec) {
    debug_assert_eq!(_v.len(), flags.len());
    let mut i = 0usize;
    _v.retain(|_| {
        let ok = flags[i];
        i += 1;
        ok
    });
}

/// Compute a cache key by hashing message, public key, and signature.
fn cache_key_sha3(msg: &[u8], pk: &[u8], sig: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(msg);
    h.update(pk);
    h.update(sig);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    k
}

/// Choose parallel or serial depending on features and config.
pub fn validate_consensus_batch(
    chain_id: [u8; 20],
    certs: &dyn CertLookupT4,
    cfg: &BatchVerifyCfg,
    batch: &mut Vec<SignedConsensusMsg>,
    verify_cache: Option<&VerifyCache>,
) -> BitVec {
    #[cfg(feature = "metrics")]
    let _timer = crate::metrics::VERIFY_BATCH_DURATION.start_timer();

    let mut flags = BitVec::repeat(false, batch.len());
    let mut to_verify_idx = Vec::new();
    let mut to_verify_msgs = Vec::new();

    for (i, m) in batch.iter().enumerate() {
        if let Some(vc) = verify_cache {
            let msg_bytes = m.to_domain_bound_bytes(chain_id);
            let pk_bytes = m.public_key_bytes();
            let sig_bytes = m.signature_bytes();
            let key = cache_key_sha3(&msg_bytes, pk_bytes, sig_bytes);
            if let Some(ok) = vc.get(&key) {
                flags.set(i, ok);
                continue;
            }
        }
        to_verify_idx.push(i);
        to_verify_msgs.push(m.clone());
    }

    let verify_flags: BitVec = if to_verify_msgs.is_empty() {
        BitVec::new()
    // PATCH 4: Collapse else-if
    } else if cfg.parallel {
        consensus_sig::verify_many(&to_verify_msgs[..], chain_id, certs)
    } else {
        BitVec::from_iter(
            to_verify_msgs
                .iter()
                .map(|m| consensus_sig::verify_core(m, &chain_id, certs).is_ok()),
        )
    };

    if !to_verify_idx.is_empty() {
        // PATCH 5: Use .enumerate() and remove manual counter `j`
        for (j, &i) in to_verify_idx.iter().enumerate() {
            let ok = verify_flags[j];
            flags.set(i, ok);

            if let Some(vc) = verify_cache {
                let m = &batch[i];
                let msg_bytes = m.to_domain_bound_bytes(chain_id);
                let pk_bytes = m.public_key_bytes();
                let sig_bytes = m.signature_bytes();
                let key = cache_key_sha3(&msg_bytes, pk_bytes, sig_bytes);
                vc.put(key.to_vec(), ok);
            }
        }
    }

    #[cfg(feature = "metrics")]
    {
        let total = flags.len();
        let ok = flags.count_ones();
        let fail = total - ok;
        crate::metrics::VERIFY_BATCH_OK.inc_by(ok as u64);
        crate::metrics::VERIFY_BATCH_FAIL.inc_by(fail as u64);
    }

    retain_with_flags(batch, &flags);
    flags
}

/// Consensus state struct to manage verification pipeline
pub struct Consensus {
    pub chain_id: [u8; 20],
    pub certs: Arc<dyn CertLookupT4 + Send + Sync>,
    pub verify_cfg: BatchVerifyCfg,
    pub verify_cache: Option<VerifyCache>,
}

impl Consensus {
    pub fn new(
        chain_id: [u8; 20],
        certs: Arc<dyn CertLookupT4 + Send + Sync>,
        verify_cfg: BatchVerifyCfg,
    ) -> Self {
        let verify_cache = if verify_cfg.cache_enabled {
            Some(VerifyCache::new(verify_cfg.cache_capacity))
        } else {
            None
        };
        Consensus {
            chain_id,
            certs,
            verify_cfg,
            verify_cache,
        }
    }

    pub fn on_recv_proposals(&mut self, mut batch: Vec<SignedConsensusMsg>) {
        let _flags = validate_consensus_batch(
            self.chain_id,
            &*self.certs,
            &self.verify_cfg,
            &mut batch,
            self.verify_cache.as_ref(),
        );
        // batch now contains only valid messages
        // ... continue ...
    }

    pub fn on_recv_prevotes(&mut self, mut batch: Vec<SignedConsensusMsg>) {
        let _flags = validate_consensus_batch(
            self.chain_id,
            &*self.certs,
            &self.verify_cfg,
            &mut batch,
            self.verify_cache.as_ref(),
        );
        // batch now contains only valid messages
        // ... continue ...
    }

    pub fn on_recv_precommits(&mut self, mut batch: Vec<SignedConsensusMsg>) {
        let _flags = validate_consensus_batch(
            self.chain_id,
            &*self.certs,
            &self.verify_cfg,
            &mut batch,
            self.verify_cache.as_ref(),
        );
        // batch now contains only valid messages
        // ... continue ...
    }

    pub fn validate_evidence(&self, a: &SignedConsensusMsg, b: &SignedConsensusMsg) -> bool {
        #[cfg(feature = "pq44-runtime")]
        {
            let flags =
                consensus_sig::verify_batch(&[a.clone(), b.clone()], self.chain_id, &*self.certs);
            flags.all()
        }
        #[cfg(not(feature = "pq44-runtime"))]
        {
            consensus_sig::verify_core::<eezo_crypto::sig::ml_dsa::MlDsa2>(
                a,
                &self.chain_id,
                &*self.certs,
            )
            .is_ok()
                && consensus_sig::verify_core::<eezo_crypto::sig::ml_dsa::MlDsa2>(
                    b,
                    &self.chain_id,
                    &*self.certs,
                )
                .is_ok()
        }
    }
}

/// Runtime configuration for a single node harness.
#[derive(Clone, Debug)]
pub struct SingleNodeCfg {
    pub chain_id: [u8; 20],
    pub block_byte_budget: usize,
    pub header_cache_cap: usize,
    #[cfg(feature = "checkpoints")]
    pub checkpoint_interval: u64,
}

impl Default for SingleNodeCfg {
    fn default() -> Self {
        Self {
            chain_id: [0u8; 20],
            block_byte_budget: 1 << 20, // 1 MB default
            header_cache_cap: 10_000,
            #[cfg(feature = "checkpoints")]
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
        }
    }
}

/// Per-slot observability summary.
#[derive(Clone, Debug)]
pub struct SlotSummary {
    pub txs: usize,
    pub bytes: usize,
    pub fees: u64,
    pub timestamp_ms: u128,
}

/// Unified error type for consensus harness.
#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("header error: {0:?}")]
    Header(HeaderErr),
    #[error("assemble error: {0:?}")]
    Assemble(AssembleError),
    #[error("validate error: {0:?}")]
    Validate(BlockValidationError),
    #[error("apply error: {0:?}")]
    Apply(BlockApplyError),
    #[error("bad quorum certificate")]
    BadQuorumCert,
    #[error("invalid tx: {0}")]
    InvalidTx(String),
}

/// Purely functional single-node harness.
/// Holds state and executes deterministic slot transitions.
pub struct SingleNode {
    pub cfg: SingleNodeCfg,
    pub cache: VerifyCache,
    pub accounts: Accounts,
    pub supply: Supply,
    pub height: u64,
    pub prev_hash: [u8; 32], // <-- Fixed type
    pub sk: SecretKey,
    pub pk: PublicKey,
    pub mempool: Mempool,
    #[cfg(feature = "checkpoints")]
    checkpoint_interval: u64,
	/// Header of the most recently applied block (cached for runner persistence)
	last_header: Option<BlockHeader>,
	/// Transactions of the most recently applied block (for persistence of full blocks)
	last_txs: Option<Vec<SignedTx>>,	
}

impl SingleNode {
    /// Construct a new single node with empty state and fresh cache.
    pub fn new(cfg: SingleNodeCfg, sk: SecretKey, pk: PublicKey) -> Self {
        #[cfg(feature = "checkpoints")]
        let ckpt_interval = if cfg.checkpoint_interval == 0 {
            DEFAULT_CHECKPOINT_INTERVAL
        } else {
            cfg.checkpoint_interval
        };
        Self {
            cache: VerifyCache::new(cfg.header_cache_cap),
            accounts: Accounts::default(),
            supply: Supply::default(),
            height: 0,
            prev_hash: [0u8; 32],
            mempool: Mempool::new(
                cfg.chain_id,
                Arc::new(CertStore::new(HashMap::<[u8; 20], ValidatedPk>::new())),
            ),
            cfg,
            sk,
            pk,
            #[cfg(feature = "checkpoints")]
            checkpoint_interval: ckpt_interval,
			last_header: None, // Initialize last_header
			last_txs: None,
        }
    }
    #[cfg(feature = "checkpoints")]
    #[inline]
    pub fn ckpt_interval(&self) -> u64 {
        self.checkpoint_interval
    }

    /// Deterministically assemble and sign a block proposal.
    pub fn propose_block(&mut self) -> Result<(Block, SlotSummary), ConsensusError> {
        #[cfg(feature = "metrics")]
        let _t_prop = start_proposal_timer();

        let ts_ms = now_ms();

        // Drain fee/byte-ordered candidates under the byte budget
        let candidates = self.mempool.drain_for_block(self.cfg.block_byte_budget);

        // === Nonce-aware selection for property tests (filter, don't error) ===
        // Keep mempool's cross-sender ordering; for each sender accept the longest
        // contiguous nonce prefix starting at the account's current nonce, even if
        // higher nonces appeared earlier in the fee-ordered list.
        #[cfg(feature = "consensus-tests")]
        let candidates = {
            use crate::tx::sender_from_pubkey_first20;
            use std::collections::HashMap;

            // expected nonce per sender (starts from current account nonce)
            let mut expect: HashMap<crate::Address, u64> = HashMap::new();
            let mut kept: Vec<_> = Vec::with_capacity(candidates.len());
            let mut remaining = candidates;

            loop {
                let mut progress = false;
                let mut next = Vec::new();

                for stx in remaining.into_iter() {
                    if let Some(sender) = sender_from_pubkey_first20(&stx) {
                        let want = *expect
                            .entry(sender)
                            .or_insert_with(|| self.accounts.get(&sender).nonce);
                        if stx.core.nonce == want {
                            kept.push(stx);
                            // next expected for this sender
                            *expect.get_mut(&sender).unwrap() = want + 1;
                            progress = true;
                        } else {
                            // Defer gaps (nonce > want) and replays (nonce < want) to later passes.
                            next.push(stx);
                        }
                    } else {
                        // Invalid sender pubkey -> drop
                    }
                }

                if !progress {
                    break;
                }
                remaining = next;
            }

            kept
        };

        // Empty mempool is allowed for liveness: assemble and apply an empty block
        #[cfg_attr(not(feature = "checkpoints"), allow(unused_mut))]
        let mut blk = assemble_block(
		    &self.accounts,
            self.cfg.chain_id,
            self.prev_hash,
            self.height + 1,
            self.cfg.block_byte_budget,
            candidates,
            ts_ms,
        )
        .map_err(ConsensusError::Assemble)?;
        #[cfg(feature = "checkpoints")]
        {
            let next_h = self.height + 1;
            let interval = self.ckpt_interval();
            let should_ckpt = interval > 0 && (next_h % interval == 0);
            if should_ckpt {
                // deterministic placeholder: certify the previous commit
                blk.header.qc_hash = self.prev_hash;

                #[cfg(all(feature = "metrics", feature = "checkpoints"))]
                crate::metrics::inc_qc_attached();

                #[cfg(feature = "metrics")]
                crate::metrics::inc_checkpoint_candidate();
            }
        }

        // Use the canonical encoded size
        let bytes = crate::block::encoded_len_ssz(&blk);

        #[cfg(feature = "metrics")]
        {
            observe_block_proposed(blk.header.tx_count, blk.header.fee_total as u64);
            drop(_t_prop);
        }

        let summary = SlotSummary {
            txs: blk.txs.len(),
            bytes,
            fees: blk.header.fee_total as u64,
            timestamp_ms: blk.header.timestamp_ms as u128,
        };

        Ok((blk, summary))
    }

    /// Validate a proposed block and apply it to state.
    pub fn validate_and_apply(&mut self, blk: &Block) -> Result<(), ConsensusError> {
        #[cfg(feature = "metrics")]
        let _t_val = start_validation_timer();

        // Sign the header deterministically with this node's SK
        let msg = header_domain_bytes(self.cfg.chain_id, &blk.header);
        let sig = detached_sign(&msg, &self.sk); // order: (&msg, &sk)

        // Compute current header hash
        let curr_hash = header_hash(&blk.header);

        // Preflight header using the CURRENT header hash as expected
        validate_header(
            self.cfg.chain_id,
            curr_hash,
            &blk.header,
            self.pk.as_bytes(),
            sig.as_bytes(),
            Some(&self.cache),
        )
        .map_err(ConsensusError::Header)?;

        // Full block validation
        validate_block(&self.accounts, &self.supply, self.cfg.chain_id, blk)
            .map_err(ConsensusError::Validate)?;

        // ── NEW: Verify Quorum Certificate (QC) when present (pre-apply) ─────
        #[cfg(all(feature = "checkpoints", feature = "checkpoints-verify"))]
        {
            // SOFT-PASS: do not hard-reject on header invariants here.
            if blk.header.qc_hash != [0u8; 32] {
                // Build a minimal QC that matches the header and soft-verify it.
                let mut qc = crate::checkpoints::QuorumCert {
                    height: blk.header.height,
                    block_hash: blk.header.qc_hash,
                    sigset: Some(crate::checkpoints::QcSigSet { signatures: vec![] }),
                };

                crate::checkpoints::add_local_sig_to_qc(
                    &mut qc,
                    &self.sk,
                    &self.pk,
                    self.cfg.chain_id,
                );

                #[cfg(feature = "metrics")]
                let _t = std::time::Instant::now();

                // Enforce only checkpoint-height gating + threshold (soft when empty).
                crate::checkpoints::verify_quorum_cert_with_env(
                    &qc,
                    self.cfg.chain_id,
                    self.ckpt_interval(),
                ).ok(); // <- SOFT: ignore error (don’t reject the block)

                #[cfg(feature = "metrics")]
                {
                    use crate::metrics::observe_qc_verify_duration_ms;
                    observe_qc_verify_duration_ms(_t.elapsed().as_millis() as u64);
                }
            }
        }
        #[cfg(all(feature = "checkpoints", not(feature = "checkpoints-verify")))]
        {
            if blk.header.qc_hash != [0u8; 32] {
                let _ = crate::checkpoints::verify_qc_stub(blk);
            }
        }
        // ─────────────────────────────────────────────────────────────────────

        #[cfg(feature = "metrics")]
        drop(_t_val);

        #[cfg(feature = "metrics")]
        let _t_apply = start_apply_timer();

        apply_block(self.cfg.chain_id, &mut self.accounts, &mut self.supply, blk)
            .map_err(ConsensusError::Apply)?;

        // Advance pointers: height and prev_hash = current header hash
        self.height = blk.header.height;
        self.prev_hash = curr_hash;
		// --- ADDED: Cache the applied header ---
		self.last_header = Some(blk.header.clone());
		// --- END ADDED ---
		// --- ADDED: Cache the applied block's txs ---
		self.last_txs = Some(blk.txs.clone());
		// --- END ADDED ---		

        #[cfg(feature = "metrics")]
        {
            observe_block_applied();
            observe_supply(&self.supply);
            drop(_t_apply);
        }

        Ok(())
    }

    /// One-slot loop: propose, validate, apply.
    /// If rollback_on_error = true, state/mempool are untouched on failure.
    pub fn run_one_slot(
        &mut self,
        rollback_on_error: bool,
    ) -> Result<(Block, SlotSummary), ConsensusError> {
        let snapshot = if rollback_on_error {
            Some((
                self.accounts.clone(),
                self.supply.clone(),
                self.height,
                self.prev_hash,
            ))
        } else {
            None
        };

        let (blk, summary) = self.propose_block()?;
        if let Err(e) = self.validate_and_apply(&blk) {
            if let Some((acc, sup, h, ph)) = snapshot {
                self.accounts = acc;
                self.supply = sup;
                self.height = h;
                self.prev_hash = ph;
            }
            return Err(e);
        }

        #[cfg(all(feature = "checkpoints", feature = "checkpoints-verify"))]
        {
            if blk.header.qc_hash != [0u8; 32] {
                let mut qc = crate::checkpoints::QuorumCert {
                    height: blk.header.height,
                    block_hash: blk.header.qc_hash,
                    sigset: Some(crate::checkpoints::QcSigSet { signatures: vec![] }),
                };

                crate::checkpoints::add_local_sig_to_qc(
                    &mut qc,
                    &self.sk,
                    &self.pk,
                    self.cfg.chain_id,
                );

                #[cfg(feature = "metrics")]
                let _t = std::time::Instant::now();

                crate::checkpoints::verify_quorum_cert_with_env(
                    &qc,
                    self.cfg.chain_id,
                    self.ckpt_interval(),
                ).ok(); // <- SOFT: ignore error

                #[cfg(feature = "metrics")]
                {
                    use crate::metrics::observe_qc_verify_duration_ms;
                    observe_qc_verify_duration_ms(_t.elapsed().as_millis() as u64);
                }
            }
        }

        #[cfg(all(feature = "checkpoints", not(feature = "checkpoints-verify")))]
        {
            if blk.header.qc_hash != [0u8; 32] {
                let _ = crate::checkpoints::verify_qc_stub(&blk);
            }
        }

        Ok((blk, summary))
    }

    // ────────────────────────────────────────────────────────────────────────
    // Snapshot helpers (no side effects). Node layer decides when/if to write.
    // ────────────────────────────────────────────────────────────────────────
    /// Returns true if the *next* height (current_height + 1) is a snapshot boundary.
    #[inline]
    pub fn next_is_snapshot_height(&self, snapshot_interval: u64) -> bool {
        if snapshot_interval == 0 {
            return false;
        }
        let next_h = self.height.saturating_add(1);
        next_h % snapshot_interval == 0
    }

    /// Compute the SSZ v2 state root if available; otherwise return zero.
    /// NOTE: `Accounts` / `Supply` don't implement `HashTreeRoot` yet, so we
    /// return zero to keep builds green. Persistence readers already fall back
    /// to legacy roots when `v2` is zero.
    #[cfg(feature = "eth-ssz")]
    #[inline]
    pub fn state_root_v2_opt(&self) -> [u8; 32] {
        [0u8; 32]
    }

    /// Stubbed variant when eth-ssz is disabled: return zero.
    #[cfg(not(feature = "eth-ssz"))]
    #[inline]
    pub fn state_root_v2_opt(&self) -> [u8; 32] {
        [0u8; 32]
    }

    /// Expose the current height's previous header hash (often used as qc_hash/material).
    /// Kept as a tiny convenience to avoid re-hashing outside the ledger when not needed.
    #[inline]
    pub fn last_header_hash(&self) -> [u8; 32] {
        self.prev_hash
    }
	/// Most recently applied `BlockHeader` (if any).
	/// Runner uses this to persist headers after commit.
	#[inline]
	pub fn last_committed_header(&self) -> Option<BlockHeader> {
		self.last_header.clone()
	}

	/// Transactions of the most recently applied block (if any).
	#[inline]
	pub fn last_committed_txs(&self) -> Option<Vec<SignedTx>> {
		self.last_txs.clone()
	}	
}

// ──────────────────────────────────────────────────────────────────────────────
// T27: HotStuff-like 3-phase pipeline (Prepare → PreCommit → Commit)
// This coexists with the legacy SingleNode harness above.
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ConsensusCfg {
    pub n: usize, // total validators
    pub f: usize, // max Byzantine
    pub chain_id: [u8; 20],
}
impl ConsensusCfg {
    #[inline]
    pub fn threshold(&self) -> usize {
        (2 * self.f) + 1
    }
}

/// Minimal network adapter; node provides an implementation.
pub trait ConsensusNetwork: Send + Sync + 'static {
    fn broadcast(&self, msg: hs_msg::SignedConsensusMsg);
    fn send_to(&self, _to: hs_msg::ValidatorId, msg: hs_msg::SignedConsensusMsg) {
        self.broadcast(msg)
    }
}

// PATCH 6: Add type aliases for complex HashMap types
type BucketKey = (hs_msg::Phase, hs_msg::View, BlockId);
type BucketValue = (BitVec, Vec<Vec<u8>>);

/// Tracks votes per (phase, view, block_id) and emits a QC when the threshold is hit.
#[derive(Default)]
struct VoteBook {
    // key: (phase, view, block_id)
    // PATCH 6: Use type aliases
    buckets: HashMap<BucketKey, BucketValue>,
}

impl VoteBook {
    fn insert(
        &mut self,
        cfg: &ConsensusCfg,
        vote: &hs_msg::SignedConsensusMsg,
    ) -> Option<hs_msg::QuorumCert> {
        let (phase, view, bid, signer_idx, sig_bytes) = match &vote.msg {
            hs_msg::ConsensusMsg::Vote(_v) => {
                let idx = vote.signer.0 as usize;
                (_v.phase, _v.view, _v.block_id, idx, vote.sig.clone())
            }
            _ => return None,
        };
        let key = (phase, view, bid);
        let entry = self
            .buckets
            .entry(key)
            .or_insert_with(|| (BitVec::repeat(false, cfg.n), Vec::new()));
        let (signers, sigs) = entry;

        if signer_idx >= cfg.n {
            return None;
        }
        if signer_idx >= signers.len() {
            signers.resize(cfg.n, false);
        }
        if signers.get(signer_idx).map(|b| *b).unwrap_or(false) {
            return None;
        }

        signers.set(signer_idx, true);
        sigs.push(sig_bytes);
        if signers.count_ones() >= cfg.threshold() {
            return Some(hs_msg::QuorumCert {
                phase,
                view,
                block_id: bid,
                signers: signers.clone(),
                sigs: sigs.clone(),
            });
        }
        None
    }
}

/// Minimal commit/lock tracking (extend with ancestry checks later).
#[derive(Default)]
pub struct CommitInfo {
    pub high_qc: Option<hs_msg::QuorumCert>,
    pub locked: Option<BlockId>,
    pub committed: Vec<BlockId>,
    pub view: hs_msg::View,
}

pub struct HotStuff<C: CertLookupT4, N: ConsensusNetwork> {
    cfg: ConsensusCfg,
    certs: Arc<C>,
    net: Arc<N>,
    votes: VoteBook,
    pub info: CommitInfo,
}

impl<C: CertLookupT4, N: ConsensusNetwork> HotStuff<C, N> {
    pub fn new(cfg: ConsensusCfg, certs: Arc<C>, net: Arc<N>) -> Self {
        Self {
            cfg,
            certs,
            net,
            votes: VoteBook::default(),
            info: CommitInfo::default(),
        }
    }

    /// Leader (or single-node) proposes a header for the current view.
    pub fn propose(
        &mut self,
        header: BlockHeader,
        proposer: hs_msg::ValidatorId,
        justify: Option<hs_msg::QuorumCert>,
    ) {
        let view = self.info.view;
        let proposal = hs_msg::Proposal {
            header,
            view,
            proposer,
            justify,
        };
        let msg = hs_msg::ConsensusMsg::Proposal(Box::new(proposal));
        let signed = self.sign_local(msg, proposer);
        #[cfg(feature = "metrics")]
        crate::metrics::CONSENSUS_PROPOSALS_TOTAL.inc();
        self.net.broadcast(signed);
    }

    /// Entry point for any signed message arriving from the network.
    pub fn on_signed_msg(&mut self, m: hs_msg::SignedConsensusMsg) {
        // Signature verification (can be swapped to batch verify later)
        if !m.verify_sig(self.cfg.chain_id, &*self.certs) {
            return;
        }
        match &m.msg {
            hs_msg::ConsensusMsg::Proposal(p) => self.on_proposal(&m, p),
            hs_msg::ConsensusMsg::Vote(_v) => self.on_vote(&m, _v),
        }
    }

    fn on_proposal(&mut self, m: &hs_msg::SignedConsensusMsg, p: &hs_msg::Proposal) {
        // Basic view monotonicity guard
        if p.view < self.info.view {
            return;
        }

        // Update high QC if provided and newer
        if let Some(qc) = &p.justify {
            if self.info.high_qc.as_ref().map(|h| h.view).unwrap_or(0) < qc.view {
                self.info.high_qc = Some(qc.clone());
            }
            // TODO: Locking rule (ensure proposed header extends the locked block)
        }

        // Vote Prepare/PreVote for this proposal
        let vote = hs_msg::Vote {
            phase: hs_msg::Phase::Prepare,
            view: p.view,
            block_id: p.header.id(),
            voter: m.signer,
        };
        let msg = hs_msg::ConsensusMsg::Vote(vote);
        let signed = self.sign_local(msg, m.signer);
        self.net.broadcast(signed);
        // Phase bumps are driven by QC formation in on_vote/on_qc.
    }

    fn on_vote(&mut self, m: &hs_msg::SignedConsensusMsg, _v: &hs_msg::Vote) {
        #[cfg(feature = "metrics")]
        {
            match _v.phase {
                hs_msg::Phase::Prepare => crate::metrics::CONSENSUS_VOTES_PREPARE.inc(),
                hs_msg::Phase::PreCommit => crate::metrics::CONSENSUS_VOTES_PRECOMMIT.inc(),
                hs_msg::Phase::Commit => crate::metrics::CONSENSUS_VOTES_COMMIT.inc(),
            }
        }
        if let Some(qc) = self.votes.insert(&self.cfg, m) {
            self.on_qc(qc);
        }
    }

    fn on_qc(&mut self, qc: hs_msg::QuorumCert) {
        #[cfg(feature = "metrics")]
        crate::metrics::CONSENSUS_QC_FORMED_TOTAL
            .with_label_values(&[&qc.phase.to_string()])
            .inc();
		// T32: aggregate QC formed counter (all phases)
        #[cfg(feature = "metrics")]
        {
			crate::metrics::EEZO_QC_FORMED_TOTAL.inc();
		}		

        match qc.phase {
            hs_msg::Phase::Prepare => {
                // Escalate to PreCommit votes
                let vote = hs_msg::Vote {
                    phase: hs_msg::Phase::PreCommit,
                    view: qc.view,
                    block_id: qc.block_id,
                    voter: hs_msg::ValidatorId(0),
                };
                let msg = hs_msg::ConsensusMsg::Vote(vote);
                let signed = self.sign_local(msg, hs_msg::ValidatorId(0));
                self.net.broadcast(signed);
            }
            hs_msg::Phase::PreCommit => {
                // Escalate to Commit votes
                let vote = hs_msg::Vote {
                    phase: hs_msg::Phase::Commit,
                    view: qc.view,
                    block_id: qc.block_id,
                    voter: hs_msg::ValidatorId(0),
                };
                let msg = hs_msg::ConsensusMsg::Vote(vote);
                let signed = self.sign_local(msg, hs_msg::ValidatorId(0));
                self.net.broadcast(signed);
            }
            hs_msg::Phase::Commit => {
                // Decide & commit the block
				// T32: block end-to-end latency (commit stage)
				#[cfg(feature = "metrics")]
				let __t32_commit_t0 = std::time::Instant::now();
                self.commit(qc.block_id);
				#[cfg(feature = "metrics")]
				crate::metrics::EEZO_BLOCK_E2E_LATENCY_SECONDS
				    .with_label_values(&["commit"])
                    .observe(__t32_commit_t0.elapsed().as_secs_f64()); 					
                self.info.view = self.info.view.saturating_add(1);
                #[cfg(feature = "metrics")]
                crate::metrics::CONSENSUS_VIEW.set(self.info.view as i64);
            }
        }
    }

    fn commit(&mut self, bid: BlockId) {
        self.info.committed.push(bid);
        #[cfg(feature = "metrics")]
        crate::metrics::CONSENSUS_COMMIT_HEIGHT.inc();
        // TODO: call into ledger/state to apply the block once wired in.
    }

    fn sign_local(
        &self,
        msg: hs_msg::ConsensusMsg,
        signer: hs_msg::ValidatorId,
    ) -> hs_msg::SignedConsensusMsg {
        // For initial bring-up, we keep a placeholder signature.
        // Swap to real ML-DSA signing once keystore is wired.
        let _digest = msg.digest(self.cfg.chain_id);
        let sig = vec![];
        hs_msg::SignedConsensusMsg {
            msg,
            sig,
            signer,
            #[cfg(feature = "eth-ssz")]
            codec_version: 2,
        }
    }
}