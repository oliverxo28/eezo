//! T4: Consensus message types, fixed-length keys/sigs, signer_id derivation.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use core::fmt;
use pqcrypto_traits::sign::PublicKey as PkTrait;
use crate::consensus_sig;
use crate::cert_store::CertLookup;
use crate::config::BatchVerifyCfg;
use crate::verify_cache::VerifyCache;
use bitvec::vec::BitVec;
use serde::de::{self, Visitor, SeqAccess};

#[cfg(feature = "pq44-runtime")]
use pqcrypto_mldsa::mldsa44;

// Phantom reference so the import is “used” and type-checked.
#[cfg(feature = "pq44-runtime")]
#[allow(dead_code)]
const _MLDSA44_USED: fn() = || {
    // Touch a stable API surface; anything simple works.
    let _ = mldsa44::public_key_bytes();
    let _ = mldsa44::signature_bytes();
};

pub const PK_LEN: usize  = 1312; // ML-DSA-44 public key bytes
pub const SIG_LEN: usize = 2420; // ML-DSA-44 detached signature bytes

/// 20-byte validator address derived from pk: first 20 bytes of SHA3-256(pk)
pub type SignerId = [u8; 20];

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

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{} bytes", PK_LEN) }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != PK_LEN { return Err(E::invalid_length(v.len(), &self)); }
                let mut a = [0u8; PK_LEN];
                a.copy_from_slice(v);
                Ok(PkBytes(a))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut a = [0u8; PK_LEN];
                for i in 0..PK_LEN {
                    a[i] = seq.next_element()?
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

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{} bytes", SIG_LEN) }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != SIG_LEN { return Err(E::invalid_length(v.len(), &self)); }
                let mut a = [0u8; SIG_LEN];
                a.copy_from_slice(v);
                Ok(SigBytes(a))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut a = [0u8; SIG_LEN];
                for i in 0..SIG_LEN {
                    a[i] = seq.next_element()?
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
pub enum MsgKind { Proposal = 0, PreVote = 1, PreCommit = 2 }

pub fn kind_of(core: &ConsensusMsgCore) -> MsgKind {
    match core {
        ConsensusMsgCore::Proposal(_)  => MsgKind::Proposal,
        ConsensusMsgCore::PreVote(_)   => MsgKind::PreVote,
        ConsensusMsgCore::PreCommit(_) => MsgKind::PreCommit,
    }
}

pub fn height_round_of(core: &ConsensusMsgCore) -> (u64, u32) {
    match core {
        ConsensusMsgCore::Proposal(p)  => (p.height, p.round),
        ConsensusMsgCore::PreVote(pv)  => (pv.height, pv.round),
        ConsensusMsgCore::PreCommit(pc)=> (pc.height, pc.round),
    }
}

/// signer_id = first 20 bytes of SHA3-256(pk)
pub fn signer_id_from_pk(pk: &PkBytes) -> SignerId {
    let h = Sha3_256::digest(&pk.0);
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
    let mut v = Vec::with_capacity(24 + chain_id.len());
    v.extend_from_slice(b"EEZO-CONSENSUS-V1|");
    v.extend_from_slice(chain_id);
    v.extend_from_slice(b"|");
    v.extend_from_slice(match kind {
        MsgKind::Proposal  => b"proposal",
        MsgKind::PreVote   => b"prevote",
        MsgKind::PreCommit => b"precommit",
    });
    v
}

/// Build the full domain bound to (height, round) using big-endian bytes.
pub fn bound_domain(static_prefix: &[u8], height: u64, round: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(static_prefix.len() + 1 + 8 + 1 + 4);
    v.extend_from_slice(static_prefix);
    v.push(b'|');
    v.extend_from_slice(&height.to_be_bytes());
    v.push(b'|');
    v.extend_from_slice(&round.to_be_bytes());
    v
}

fn retain_with_flags<T>(v: &mut Vec<T>, flags: &BitVec) {
    debug_assert_eq!(v.len(), flags.len());
    let mut i = 0usize;
    v.retain(|_| {
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
    certs: &(impl CertLookup + Sync + ?Sized),
    cfg: &BatchVerifyCfg,
    batch: &mut Vec<SignedConsensusMsg>,
    verify_cache: Option<&VerifyCache>,
) -> BitVec {
    // ---- Start timer BEFORE verify call (so duration covers verification) ----
    #[cfg(feature = "metrics")]
    let _timer = crate::metrics::VERIFY_BATCH_DUR_MS.start_timer();

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
        // miss → schedule for verification
        to_verify_idx.push(i);
        to_verify_msgs.push(m.clone());
    }

    // Verify only the misses (batch or serial depending on cfg)
    let verify_flags: BitVec = if to_verify_msgs.is_empty() {
        BitVec::new()
    } else {
        #[cfg(feature = "pq44-runtime")]
        {
            if cfg.parallel {
                consensus_sig::verify_many::<crate::pq44_runtime::Pq44>(&to_verify_msgs, chain_id, certs)
            } else {
                BitVec::from_iter(to_verify_msgs.iter().map(|m| {
                    consensus_sig::verify_core::<crate::pq44_runtime::Pq44>(m, &chain_id, certs).is_ok()
                }))
            }
        }
        #[cfg(not(feature = "pq44-runtime"))]
        {
            BitVec::from_iter(to_verify_msgs.iter().map(|m| {
                consensus_sig::verify_core::<eezo_crypto::sig::ml_dsa::MlDsa2>(m, &chain_id, certs).is_ok()
            }))
        }
    };

    // Merge results back to full flags + update cache
    if !to_verify_idx.is_empty() {
        let mut j = 0usize;
        for &i in &to_verify_idx {
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
            j += 1;
        }
    }

    // ---- Update counters AFTER verify call (then drop timer) ----
    #[cfg(feature = "metrics")]
    {
        let total = flags.len();
        let ok = flags.count_ones();
        let fail = total - ok;
        crate::metrics::VERIFY_BATCH_OK.inc_by(ok as u64);
        crate::metrics::VERIFY_BATCH_FAIL.inc_by(fail as u64);
        // dropping _timer records duration
    }

    retain_with_flags(batch, &flags);
    flags
}

/// Consensus state struct to manage verification pipeline
pub struct Consensus {
    pub chain_id: [u8; 20],
    pub certs: Box<dyn CertLookup + Sync + Send>,
    pub verify_cfg: BatchVerifyCfg,
    pub verify_cache: Option<VerifyCache>,
}

impl Consensus {
    pub fn new(chain_id: [u8; 20], certs: Box<dyn CertLookup + Sync + Send>, verify_cfg: BatchVerifyCfg) -> Self {
        let verify_cache = if verify_cfg.cache_enabled {
            Some(VerifyCache::new(verify_cfg.cache_capacity))
        } else {
            None
        };
        Consensus { chain_id, certs, verify_cfg, verify_cache }
    }

    pub fn on_recv_proposals(&mut self, mut batch: Vec<SignedConsensusMsg>) {
        let _flags = validate_consensus_batch(self.chain_id, &*self.certs, &self.verify_cfg, &mut batch, self.verify_cache.as_ref());
        // batch now contains only valid messages
        // ... continue ...
    }

    pub fn on_recv_prevotes(&mut self, mut batch: Vec<SignedConsensusMsg>) {
        let _flags = validate_consensus_batch(self.chain_id, &*self.certs, &self.verify_cfg, &mut batch, self.verify_cache.as_ref());
        // batch now contains only valid messages
        // ... continue ...
    }

    pub fn on_recv_precommits(&mut self, mut batch: Vec<SignedConsensusMsg>) {
        let _flags = validate_consensus_batch(self.chain_id, &*self.certs, &self.verify_cfg, &mut batch, self.verify_cache.as_ref());
        // batch now contains only valid messages
        // ... continue ...
    }

    pub fn validate_evidence(&self, a: &SignedConsensusMsg, b: &SignedConsensusMsg) -> bool {
        #[cfg(feature = "pq44-runtime")]
        {
            let flags = consensus_sig::verify_batch(&[a.clone(), b.clone()], self.chain_id, &*self.certs);
            flags.all()
        }
        #[cfg(not(feature = "pq44-runtime"))]
        {
            consensus_sig::verify_core::<eezo_crypto::sig::ml_dsa::MlDsa2>(a, &self.chain_id, &*self.certs).is_ok()
                && consensus_sig::verify_core::<eezo_crypto::sig::ml_dsa::MlDsa2>(b, &self.chain_id, &*self.certs).is_ok()
        }
    }
}