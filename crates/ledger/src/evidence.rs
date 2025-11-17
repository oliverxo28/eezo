//! T4: Double-sign evidence container with reporter signature (spam resistance).

use crate::consensus::SigBytes;
use crate::SignedConsensusMsg;
use serde::{Deserialize, Serialize};

/// step: 0=Proposal, 1=PreVote, 2=PreCommit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    pub height: u64,
    pub round: u32,
    pub step: u8,
    pub a: SignedConsensusMsg,
    pub b: SignedConsensusMsg,
    /// Signature made by the reporter node over a canonical hash of (a,b).
    pub reporter_sig: SigBytes,
}
