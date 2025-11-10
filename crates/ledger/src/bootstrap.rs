// crates/ledger/src/bootstrap.rs
#![cfg(all(feature = "eth-ssz", feature = "state-sync"))]

use crate::{
    light::{light_verify, LightHeader, TxProofBundle},
    persistence::{Persistence, StateSnapshot},
    state_sync::{verify_snapshot_and_apply, SnapshotManifestV2},
};
use eezo_serde::eth::Decode;
#[allow(unused_imports)]
use eezo_serde::eth::HashTreeRoot; // may be handy if you anchor parent/child later

// NEW: persist light anchor (v2) and record genesis state root (v2)
use crate::persistence::{save_genesis_state_root_v2, LightAnchor};

/// Bytes fetched from the node’s HTTP endpoint(s).
pub struct RemoteSnapshot {
    pub manifest_ssz: Vec<u8>,
    pub snapshot_blob: Vec<u8>,
}

#[derive(Debug)]
pub enum BootstrapError {
    Light,
    SnapshotDecode,
    Persist(crate::persistence::PersistError),
}
impl From<crate::persistence::PersistError> for BootstrapError {
    fn from(e: crate::persistence::PersistError) -> Self {
        BootstrapError::Persist(e)
    }
}

/// Verify child vs parent (light client) then apply snapshot locally.
pub fn bootstrap_from_light_and_snapshot(
    p: &Persistence,
    parent: &LightHeader,
    child: &LightHeader,
    txp: &TxProofBundle,
    remote: RemoteSnapshot,
) -> Result<(), BootstrapError> {
    // 1) Light verification
    light_verify(child, parent, txp).map_err(|_| BootstrapError::Light)?;

    // 2) Decode & sanity-check manifest (ETH-SSZ)
    let (manifest, _n): (SnapshotManifestV2, usize) =
        SnapshotManifestV2::ssz_read(&remote.manifest_ssz).map_err(|_| BootstrapError::SnapshotDecode)?;

    // 3) Verify & decode snapshot payload
    //    This checks codec_version/height and compares state_root_v2 with the manifest.
    let (accounts, supply) =
        verify_snapshot_and_apply(&manifest, &remote.snapshot_blob).map_err(|_| BootstrapError::SnapshotDecode)?;

    // If this is the genesis snapshot, store the v2 genesis root for HTTP/export consumers.
    if manifest.height == 0 {
        // Best-effort: don't fail bootstrap if this already exists or write races; ignore error.
        let _ = save_genesis_state_root_v2(p, manifest.state_root_v2);
    }

    // 4) Persist the snapshot locally
    //    NOTE: StateSnapshot requires legacy fields too; set v1 root to zeros for v2-only snapshots.
    p.put_state_snapshot(&StateSnapshot {
        codec_version: 2,
        height: manifest.height,
        state_root: [0u8; 32],            // legacy v1 (unused for v2-only nodes)
		bridge: Some(crate::bridge::BridgeState::default()),
        state_root_v2: manifest.state_root_v2,
        accounts,
        supply,
    })?;

    // 5) Advance local tip to the child height (the block we verified)
    p.set_tip(child.height)?;

    // 6) Persist the ETH-SSZ light anchor corresponding to the verified child.
    //    This lets readers fetch the latest light anchor via persistence.
    p.put_light_anchor(&LightAnchor {
        header: child.clone(),
        codec_version: 2,
    })?;

    Ok(())
}