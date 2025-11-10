//! T27: Wire envelope for HotStuff-like consensus (Proposal/Vote).
//! Phase (Prepare/PreCommit/Commit) is carried *inside* Vote and is committed via the signature digest.
#![cfg(feature = "pq44-runtime")]
use eezo_ledger::consensus_msg::{ConsensusMsg, SignedConsensusMsg};
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireKind {
    Proposal = 0,
    Vote = 1,
}

#[inline]
fn kind_of_msg(m: &ConsensusMsg) -> WireKind {
    match m {
        ConsensusMsg::Proposal(_) => WireKind::Proposal,
        ConsensusMsg::Vote(_) => WireKind::Vote,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GossipEnvelope {
    pub kind: u8,
    pub payload: Vec<u8>,
}

pub fn encode_envelope(msg: &SignedConsensusMsg) -> GossipEnvelope {
    let kind = kind_of_msg(&msg.msg);
    let payload = bincode::serialize(msg).expect("encode signed consensus msg");
    GossipEnvelope {
        kind: kind as u8,
        payload,
    }
}

pub fn decode_envelope(env: &GossipEnvelope) -> Result<SignedConsensusMsg, String> {
    let msg: SignedConsensusMsg =
        bincode::deserialize(&env.payload).map_err(|_| "payload decode failed".to_string())?;
    let expected = kind_of_msg(&msg.msg);
    if env.kind != expected as u8 {
        return Err("envelope kind mismatch".into());
    }
    Ok(msg)
}
