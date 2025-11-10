#![cfg(all(test, feature="eth-ssz", feature="state-sync", feature="testing"))]

use eezo_ledger::{
    accounts::Accounts,
    supply::Supply,
    light::{LightHeader, TxProofBundle},
    state_sync::SnapshotManifestV2,
    bootstrap::{bootstrap_from_light_and_snapshot, RemoteSnapshot, BootstrapError},
    persistence::{Persistence, StateSnapshot},
};
use eezo_serde::eth::{Encode, HashTreeRoot};

#[test]
fn bootstrap_happy_path_mocked() {
    // Parent/child that link (HTR(parent) == child.parent_root)
    let parent = LightHeader {
        height: 10,
        parent_root: [0; 32],
        tx_root_v2: [1; 32],
        #[cfg(feature="checkpoints")]
        qc_root: [2; 32],
        timestamp_ms: 1_000,
    };
    let parent_htr: [u8; 32] = parent.hash_tree_root();

    // Choose a tx_root and reuse it both in the header and the proof leaf (empty branch).
    let child_tx_root: [u8; 32] = [7; 32];

    let child = LightHeader {
        height: 11,
        parent_root: parent_htr,
        tx_root_v2: child_tx_root,
        #[cfg(feature="checkpoints")]
        qc_root: [4; 32],
        timestamp_ms: 1_200,
    };

    // Minimal tx-proof shape: empty branch => leaf must equal the header's tx_root_v2
    let proof = TxProofBundle {
        tx_index: 0,
        leaf: child_tx_root.to_vec(),
        branch: vec![],
    };

    // Mocked v2 snapshot manifest and blob (use real (Accounts, Supply) to satisfy apply)
    let manifest_ssz = SnapshotManifestV2 {
        height: 0,
        codec_version: 2,
        state_root_v2: [0; 32],
    }.ssz_bytes();

    // Encode a full StateSnapshot so verify_snapshot_and_apply can check height/root.
    let snapshot_blob = bincode::serialize(&StateSnapshot {
        codec_version: 2,
        height: 0,
        state_root: [0u8; 32],
        state_root_v2: [0u8; 32],
        accounts: Accounts::default(),
        supply: Supply::default(),
    }).unwrap();

    let tmp = tempfile::TempDir::new().unwrap();
    let p = Persistence::open_default(tmp.path()).unwrap();

    let remote = RemoteSnapshot { manifest_ssz, snapshot_blob };
    bootstrap_from_light_and_snapshot(&p, &parent, &child, &proof, remote).unwrap();
}

#[test]
fn bootstrap_rejects_root_mismatch() {
    // Valid parent/child linkage
    let parent = LightHeader {
        height: 10,
        parent_root: [0; 32],
        tx_root_v2: [1; 32],
        #[cfg(feature="checkpoints")]
        qc_root: [2; 32],
        timestamp_ms: 1_000,
    };
    let parent_htr = parent.hash_tree_root();
    let child_tx_root: [u8; 32] = [5; 32];
    let child = LightHeader {
        height: 11,
        parent_root: parent_htr,
        tx_root_v2: child_tx_root,
        #[cfg(feature="checkpoints")]
        qc_root: [4; 32],
        timestamp_ms: 1_200,
    };
    // Light proof must pass, so leaf == child's tx_root_v2 and branch empty.
    let proof = TxProofBundle { tx_index: 0, leaf: child_tx_root.to_vec(), branch: vec![] };

    // Manifest claims state_root_v2 = [9;32]...
    let manifest_ssz = SnapshotManifestV2 {
        height: 0,
        codec_version: 2,
        state_root_v2: [9; 32],
    }.ssz_bytes();

    // ...but the snapshot encodes state_root_v2 = [8;32] (mismatch).
    let snapshot_blob = bincode::serialize(&StateSnapshot {
        codec_version: 2,
        height: 0,
        state_root: [0u8; 32],
        state_root_v2: [8u8; 32],
        accounts: Accounts::default(),
        supply: Supply::default(),
    }).unwrap();

    let tmp = tempfile::TempDir::new().unwrap();
    let p = Persistence::open_default(tmp.path()).unwrap();
    let remote = RemoteSnapshot { manifest_ssz, snapshot_blob };

    let err = bootstrap_from_light_and_snapshot(&p, &parent, &child, &proof, remote)
        .expect_err("mismatched roots must be rejected");
    // It should fail in the snapshot verification path
    match err {
        BootstrapError::SnapshotDecode => {}
        other => panic!("expected SnapshotDecode error, got {:?}", other),
    }
}