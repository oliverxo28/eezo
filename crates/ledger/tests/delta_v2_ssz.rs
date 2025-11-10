// Run with: cargo test -p eezo-ledger --features eth-ssz
#![cfg(all(feature = "eth-ssz", feature = "persistence"))]
use eezo_ledger::bridge::BridgeState;
use eezo_ledger::persistence::{export_delta_manifest_v2_ssz, Persistence, StateSnapshot};
use eezo_ledger::{Accounts, Supply};
use tempfile::TempDir;

#[test]
fn delta_v2_empty_roundtrip() {
    // --- arrange: temp DB + minimal snapshot at height 0
    let tmp = TempDir::new().unwrap();
    let db = Persistence::open_default(tmp.path()).unwrap();

    // deterministic root for the assertion
    let mut root = [0u8; 32];
    root[0..4].copy_from_slice(b"root");

    // Build a minimal snapshot explicitly (no Default impl on StateSnapshot)
    let snap = StateSnapshot {
        height: 0,
        accounts: Accounts::default(),
        supply: Supply {
            native_mint_total: 0,
            bridge_mint_total: 0,
            burn_total: 0,
        },
        state_root: root,
        bridge: Some(BridgeState::default()),
        #[cfg(feature = "eth-ssz")]
        codec_version: 2,
        #[cfg(feature = "eth-ssz")]
        state_root_v2: root,
    };

    db.put_state_snapshot(&snap).expect("write snap0");

    // --- act
    let bytes = export_delta_manifest_v2_ssz(&db, 0, 0).expect("export ok");

    // --- assert: SSZ2D frame with empty proof
    assert!(bytes.starts_with(b"SSZ2D"), "missing SSZ2D magic");

    let from = u64::from_le_bytes(bytes[5..13].try_into().unwrap());
    let to = u64::from_le_bytes(bytes[13..21].try_into().unwrap());
    assert_eq!((from, to), (0, 0), "bad from/to");

    let new_root = &bytes[21..53];
    assert_eq!(new_root, &root, "root mismatch");

    let kcnt = u32::from_le_bytes(bytes[53..57].try_into().unwrap());
    let plen = u32::from_le_bytes(bytes[57..61].try_into().unwrap());
    assert_eq!((kcnt, plen), (0, 0), "expected empty proof");

    // exact size for empty-proof frame
    assert_eq!(bytes.len(), 61);
}
