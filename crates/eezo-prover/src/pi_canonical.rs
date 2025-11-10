#![cfg(feature = "stark-air")]

use blake3::hash;

/// canonical, rotation-safe public inputs for LC + SNARK wrappers
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPi {
    pub chain_id20: [u8; 20],
    pub suite_id: u8,          // e.g. 1=mock, 2=stark-v2
    pub circuit_version: u8,   // e.g. 2
    pub ssz_version: u8,       // e.g. 2
    pub header_hash: [u8; 32], // block header hash (ledger canonical)
    pub txs_root_v2: [u8; 32],
    pub state_root_v2: [u8; 32],
    pub sig_batch_digest: [u8; 32],
    pub height: u64,
}

impl CanonicalPi {
    /// Stable byte layout (LE for ints), version-tagged up front.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 20 + 3 + 32 * 4 + 8);
        out.push(1u8); // version of CanonicalPi layout
        out.extend_from_slice(&self.chain_id20);
        out.push(self.suite_id);
        out.push(self.circuit_version);
        out.push(self.ssz_version);
        out.extend_from_slice(&self.header_hash);
        out.extend_from_slice(&self.txs_root_v2);
        out.extend_from_slice(&self.state_root_v2);
        out.extend_from_slice(&self.sig_batch_digest);
        out.extend_from_slice(&self.height.to_le_bytes());
        out
    }

    /// BLAKE3 digest over canonical bytes — the LC/relay “certified PI” root.
    pub fn digest(&self) -> [u8; 32] {
        let h = hash(&self.to_bytes());
        *h.as_bytes()
    }
}

// --- Optional convenience constructors (fill from your existing types) ---
// Add exact From/try_from impls later once you upload the source types:
// - AirPiV2 / AirSpec
// - ledger::Header
// - rotation/suite metadata
