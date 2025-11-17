// crates/ledger/src/state_sync.rs
#![cfg(all(feature = "eth-ssz", feature = "state-sync"))]

use crate::{
    accounts::Accounts,
    light::{light_verify, LightHeader, TxProofBundle},
    persistence::{PersistError, Persistence, Result as PersistResult, StateSnapshot},
    supply::Supply,
};
use eezo_serde::eth::{Decode, Encode, SerdeError};

#[cfg(feature = "metrics")]
use std::time::Instant;

/// Minimal v2 snapshot manifest (ETH-SSZ).
#[derive(Clone, Debug)]
pub struct SnapshotManifestV2 {
    pub height: u64,
    pub codec_version: u8,     // always 2 for v2 snapshots
    pub state_root_v2: [u8; 32],
}

impl Encode for SnapshotManifestV2 {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        // height: u64 little-endian
        self.height.ssz_write(out);

        // codec_version: exactly one byte
        out.push(self.codec_version);

        // state_root_v2: exactly 32 bytes
        assert_eq!(
            self.state_root_v2.len(),
            32,
            "invalid state_root_v2 length"
        );
        out.extend_from_slice(&self.state_root_v2);
    }
}

impl Decode for SnapshotManifestV2 {
    fn ssz_read(inp: &[u8]) -> Result<(Self, usize), SerdeError> {
        let mut off = 0;

        // height: u64
        let (h, n1) = u64::ssz_read(&inp[off..])?;
        off += n1;

        // codec_version: u8
        if inp.len() < off + 1 {
            return Err(SerdeError::InvalidLength);
        }
        let codec_version = inp[off];
        off += 1;

        // state_root_v2: 32 bytes
        if inp.len() < off + 32 {
            return Err(SerdeError::InvalidLength);
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&inp[off..off + 32]);
        off += 32;

        Ok((SnapshotManifestV2 { height: h, codec_version, state_root_v2: root }, off))
    }
}

/// A compact delta manifest (placeholder shape). In a production implementation
/// this would carry a compact multiproof for changed keys between two heights.
#[derive(Clone, Debug)]
pub struct DeltaManifestV2 {
    pub base_height: u64,
    pub new_height: u64,
    pub proof_keys: Vec<Vec<u8>>,
    pub proof_values: Vec<Vec<u8>>,
    pub new_state_root_v2: [u8; 32],
}

impl Encode for DeltaManifestV2 {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        self.base_height.ssz_write(out);
        self.new_height.ssz_write(out);

        // keys (list<bytes>)
        (self.proof_keys.len() as u64).ssz_write(out);
        for k in &self.proof_keys {
            (k.len() as u64).ssz_write(out);
            out.extend_from_slice(k);
        }

        // values (list<bytes>)
        (self.proof_values.len() as u64).ssz_write(out);
        for v in &self.proof_values {
            (v.len() as u64).ssz_write(out);
            out.extend_from_slice(v);
        }

        out.extend_from_slice(&self.new_state_root_v2);
    }
}

/// Build a v2 snapshot manifest from persistence for (<= height).
pub fn build_snapshot_manifest_v2(p: &Persistence, height: u64) -> PersistResult<SnapshotManifestV2> {
    let snap: StateSnapshot = p
        .get_latest_snapshot_at_or_below(height)?
        .ok_or(PersistError::NotFound)?;

    // Under eth-ssz we always set codec_version=2 and use the v2 root.
    let manifest = SnapshotManifestV2 {
        height: snap.height,
        codec_version: 2,
        state_root_v2: snap.state_root_v2,
    };
    Ok(manifest)
}

/// Naive delta builder (placeholder). Replace with real state multiproof generation.
pub fn build_delta_manifest_v2(
    _p: &Persistence,
    base_height: u64,
    new_height: u64,
) -> PersistResult<DeltaManifestV2> {
    // Wire in your trie/trie-diff multiproof here.
    Ok(DeltaManifestV2 {
        base_height,
        new_height,
        proof_keys: Vec::new(),
        proof_values: Vec::new(),
        new_state_root_v2: [0u8; 32],
    })
}

/// End-to-end light verification glue (parent/child linkage + tx proof).
#[inline]
pub fn verify_block_and_tx(
    parent: &LightHeader,
    child: &LightHeader,
    txp: &TxProofBundle,
) -> Result<(), crate::light::LightError> {
    light_verify(child, parent, txp)
}

/// Verify the snapshot manifest matches the snapshot payload and return decoded state.
/// Currently accepts bincode `StateSnapshot` payloads. We strictly check:
///   - codec_version == 2
///   - snapshot.height == manifest.height
///   - snapshot.state_root_v2 == manifest.state_root_v2
// PATCH 1: Indent doc comment
///     Once full ETH-SSZ snapshot encoding lands, also recompute the root from
// PATCH 2: Indent doc comment
///     (accounts, supply) and compare.
pub fn verify_snapshot_and_apply(
    manifest: &SnapshotManifestV2,
    snapshot_bytes: &[u8],
) -> Result<(Accounts, Supply), &'static str> {
    // Decode the snapshot payload (current project uses bincode for Accounts/Supply in tests).
    let snap: StateSnapshot = bincode::deserialize(snapshot_bytes).map_err(|_| "snapshot decode failed")?;

    // Quick structural checks against manifest
    if manifest.codec_version != 2 {
        return Err("unexpected codec version (expected 2)");
    }
    if snap.height != manifest.height {
        return Err("height mismatch");
    }

    // Strict root check against the value persisted in the snapshot.
    // (snap.state_root_v2 is produced by ledger when the snapshot was taken.)
    if snap.state_root_v2 != manifest.state_root_v2 {
        return Err("state_root_v2 mismatch");
    }

    Ok((snap.accounts, snap.supply))
}

// ─────────────────────────────────────────────────────────────────────────────
// T32 helpers (state-sync observability). These are called from the actual
// bootstrap/page-apply loops (in the node). No-ops when metrics are off.
// ─────────────────────────────────────────────────────────────────────────────

/// Start a per-page apply timer. Call `t32_page_apply_finish` with the token.
#[inline]
pub fn t32_page_apply_start() -> Option<Instant> {
    #[cfg(feature = "metrics")]
    {
        // PATCH 3: Remove unneeded return
        Some(Instant::now())
    }
    #[cfg(not(feature = "metrics"))]
    {
        None
    }
}

/// Finish a per-page apply timing and increment the pages-applied counter.
#[inline]
pub fn t32_page_apply_finish(t0: Option<Instant>) {
    #[cfg(feature = "metrics")]
    if let Some(t0) = t0 {
        crate::metrics::EEZO_STATE_SYNC_PAGE_APPLY_SECONDS.observe(t0.elapsed().as_secs_f64());
        crate::metrics::EEZO_STATE_SYNC_PAGES_APPLIED_TOTAL.inc();
    }
}

/// Start a bootstrap timer. Call `t32_bootstrap_finish` at the end of bootstrap.
#[inline]
pub fn t32_bootstrap_start() -> Option<Instant> {
    #[cfg(feature = "metrics")]
    {
        // PATCH 4: Remove unneeded return
        Some(Instant::now())
    }
    #[cfg(not(feature = "metrics"))]
    {
        None
    }
}

/// Finish bootstrap timing and record total seconds.
#[inline]
pub fn t32_bootstrap_finish(t0: Option<Instant>) {
    #[cfg(feature = "metrics")]
    if let Some(t0) = t0 {
        crate::metrics::EEZO_STATE_BOOTSTRAP_SECONDS.observe(t0.elapsed().as_secs_f64());
    }
}