//! T27: Wire envelope for legacy consensus (Proposal/Vote) — historical, see T81.
//! Phase (Prepare/PreCommit/Commit) is carried *inside* Vote and is committed via the signature digest.
//!
//! Note: This is pre-DAG consensus wire format. EEZO production uses pure DAG
//! consensus as of T81. The code is retained for backward compatibility.
#![cfg(feature = "pq44-runtime")]
use eezo_ledger::{ConsensusMsgCore, SignedConsensusMsg};
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireKind {
    Proposal = 0,
    Vote = 1,
}

#[inline]
fn kind_of_msg(m: &ConsensusMsgCore) -> WireKind {
    match m {
        ConsensusMsgCore::Proposal(_) => WireKind::Proposal,
        ConsensusMsgCore::PreVote(_) | ConsensusMsgCore::PreCommit(_) => WireKind::Vote,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GossipEnvelope {
    pub kind: u8,
    pub payload: Vec<u8>,
}

pub fn encode_envelope(msg: &SignedConsensusMsg) -> GossipEnvelope {
    let kind = kind_of_msg(&msg.core);
    let payload = bincode::serialize(msg).expect("encode signed consensus msg");
    GossipEnvelope {
        kind: kind as u8,
        payload,
    }
}

pub fn decode_envelope(env: &GossipEnvelope) -> Result<SignedConsensusMsg, String> {
    let msg: SignedConsensusMsg =
        bincode::deserialize(&env.payload).map_err(|_| "payload decode failed".to_string())?;
    let expected = kind_of_msg(&msg.core);
    if env.kind != expected as u8 {
        return Err("envelope kind mismatch".into());
    }
    Ok(msg)
}