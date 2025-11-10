//! T27: HotStuff-like consensus messages and signed wrappers
//! Phases: Prepare → PreCommit → Commit. QCs attest to (phase, view, block_id).

use bitvec::vec::BitVec;
use core::fmt;
use serde::{Deserialize, Serialize};

use crate::block::{BlockHeader, BlockId};
use crate::cert_store::CertLookupT4;

// Provide a default for codec_version when decoding older messages that didn't carry it.
#[cfg(feature = "eth-ssz")]
#[inline]
fn default_codec_version() -> u8 {
    1
}

/// 20-byte chain id (already used across EEZO)
pub type ChainId = [u8; 20];

/// Monotonic logical time for proposals/votes
pub type View = u64;

/// Three-phase HS-like pipeline
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Phase {
    Prepare,
    PreCommit,
    Commit,
}

/// Validator identifier (index into the validator set).
/// NOTE: We use a compact index for now; later you can switch to a PK-derived id if desired.
/// Fix: If you want to use a 20-byte id, change this to pub struct ValidatorId(pub [u8; 20]);
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ValidatorId(pub u16);

/// Threshold attestation to (phase, view, block_id)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumCert {
    pub phase: Phase,
    pub view: View,
    pub block_id: BlockId,
    /// Bitmap of signers (index == validator index)
    pub signers: BitVec,
    /// Detached signatures ordered by set bits in `signers`
    pub sigs: Vec<Vec<u8>>,
}

/// Proposal for a new block/header. `justify` usually carries the highest QC.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proposal {
    pub header: BlockHeader,
    pub view: View,
    pub proposer: ValidatorId,
    pub justify: Option<QuorumCert>,
}

/// Vote carries a validator’s attestation for (phase, view, block_id)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vote {
    pub phase: Phase,
    pub view: View,
    pub block_id: BlockId,
    pub voter: ValidatorId,
}

/// Logical (unsigned) messages
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
}

/// Signed envelope (detached signature over canonical digest)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedConsensusMsg {
    pub msg: ConsensusMsg,
    pub sig: Vec<u8>, // ML-DSA detached signature bytes
    pub signer: ValidatorId,
    // Wire-level codec version (1 = SSZ-lite (legacy), 2 = ETH-SSZ)
    // Only compiled in when eth-ssz is enabled; defaults to 1 when deserializing older payloads.
    #[cfg(feature = "eth-ssz")]
    #[serde(default = "default_codec_version")]
    pub codec_version: u8,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Phase::Prepare => write!(f, "prepare"),
            Phase::PreCommit => write!(f, "precommit"),
            Phase::Commit => write!(f, "commit"),
        }
    }
}

impl ConsensusMsg {
    /// Canonical domain-separated digest (stable!). Uses SHA3-256 and the header’s canonical hash.
    pub fn digest(&self, chain_id: ChainId) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};

        const D_PROPOSAL: &[u8] = b"EEZO:consensus:proposal:v1";
        const D_VOTE: &[u8] = b"EEZO:consensus:vote:v1";

        let mut h = Sha3_256::new();
        h.update(&chain_id);

        match self {
            ConsensusMsg::Proposal(p) => {
                h.update(D_PROPOSAL);
                // Header must already be canonical-hashed inside ledger
                h.update(&p.header.hash());
                h.update(&p.view.to_le_bytes());
                h.update(&p.proposer.0.to_le_bytes());
                if let Some(qc) = &p.justify {
                    h.update(&qc.view.to_le_bytes());
                    h.update(&qc.block_id.0);
                    h.update(&[qc.phase as u8]);
                } else {
                    h.update(&[0u8]);
                }
            }
            ConsensusMsg::Vote(v) => {
                h.update(D_VOTE);
                h.update(&v.view.to_le_bytes());
                h.update(&[v.phase as u8]);
                h.update(&v.block_id.0);
                h.update(&v.voter.0.to_le_bytes());
            }
        }

        h.finalize().into()
    }
}

impl SignedConsensusMsg {
    pub fn new(msg: ConsensusMsg, signer: ValidatorId, sig: Vec<u8>) -> Self {
        Self {
            msg,
            sig,
            signer,
            #[cfg(feature = "eth-ssz")]
            codec_version: 2,
        }
    }

    /// Verify the detached signature using the provided certificate store.
    /// NOTE: T27 bring-up keeps this as a stub returning true; we’ll swap to real ML-DSA verify
    /// (or batch verify) in the next subtask using `certs.public_key(self.signer)`.
    pub fn verify_sig(&self, chain_id: ChainId, certs: &impl CertLookupT4) -> bool {
        // In real code, verify the sig using the public key from certs.
        // For bring-up, stub as always true.
        let _ = (chain_id, certs);
        true
    }
}