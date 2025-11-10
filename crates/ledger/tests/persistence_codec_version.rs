#![cfg(all(feature = "persistence", feature = "testing"))]

use eezo_ledger::persistence::StateSnapshot;
use eezo_ledger::{Accounts, Supply};
use serde_json;

// We added codec_version to StateSnapshot (not a separate manifest type).
// This smoke test simply roundtrips a snapshot; with eth-ssz the field exists,
// without eth-ssz the field is not compiled-in and this test still builds (gated).
#[test]
fn snapshot_roundtrip_smoke() {
    let snap = StateSnapshot {
        height: 0,
        accounts: Accounts::default(),
        supply: Supply::default(),
        state_root: [0u8; 32],
        #[cfg(feature = "eth-ssz")]
        codec_version: 2,
        #[cfg(feature = "eth-ssz")]
        state_root_v2: [0u8; 32],
    };
    let json = serde_json::to_vec(&snap).unwrap();
    let s2: StateSnapshot = serde_json::from_slice(&json).unwrap();
    #[cfg(feature = "eth-ssz")]
    assert_eq!(s2.codec_version, 2);
}

// Optional: if you want to assert JSON-defaulting for missing codec_version,
// you can craft a JSON object without that field and ensure it decodes to 1.
// This only works with JSON (not bincode). Uncomment if desired:
/*
#[cfg(feature = "eth-ssz")]
#[test]
fn missing_codec_version_defaults_to_1_in_json() {
    // Build a JSON without codec_version.
    let json = serde_json::json!({
        "height": 3,
        "accounts": Accounts::default(),
        "supply": Supply::default(),
        "state_root": [0u8; 32],
    });
    let s: StateSnapshot = serde_json::from_value(json).unwrap();
    assert_eq!(s.codec_version, 1);
}
*/