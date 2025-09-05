// crates/ledger/src/tx.rs
use serde::{Deserialize, Serialize};

use crate::consensus::SigBytes;

/// Minimal transaction witness container.
/// Flesh out later when we wire real tx verification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxWitness {
    /// 32-byte hash (tx hash or merkle root)
    pub payload_hash: [u8; 32],
    /// ML-DSA detached signatures over a bound domain (placeholder here)
    pub sigs: Vec<SigBytes>,
}

impl TxWitness {
    pub fn new(payload_hash: [u8; 32]) -> Self {
        Self { payload_hash, sigs: Vec::new() }
    }
    pub fn add_sig(&mut self, sig: SigBytes) {
        self.sigs.push(sig);
    }
    pub fn len(&self) -> usize { self.sigs.len() }
    pub fn is_empty(&self) -> bool { self.sigs.is_empty() }
}
