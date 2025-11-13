#![cfg(feature = "persistence")]

use eezo_ledger::accounts::Accounts;
use eezo_ledger::config::PersistenceCfg;
use eezo_ledger::persistence::{open_db, Persistence};
use eezo_ledger::supply::Supply;
use eezo_ledger::StateSnapshot;
use tempfile::tempdir;

#[test]
fn snapshot_and_recover_roundtrip() {
    // temp RocksDB path
    let dir = tempdir().unwrap();
    let mut cfg = PersistenceCfg::default();
    cfg.db_path = dir.path().join("db");

    // open store
    let store: Persistence = open_db(&cfg).expect("open");

    // prepare a tiny state (defaults are fine for smoke)
    let accs = Accounts::default();
    let supply = Supply::default();

    // write a snapshot at height 5
    let snap = StateSnapshot {
        height: 5,
        accounts: accs.clone(),
        supply: supply.clone(),
        state_root: [0u8; 32],
        #[cfg(feature = "eth-ssz")]
        codec_version: 2, // v2 marker for ETH-SSZ snapshots
        #[cfg(feature = "eth-ssz")]
        state_root_v2: [0u8; 32], // dummy root for test
		// new bridge field added in StateSnapshot; use its Default for test
		bridge: Default::default(),
    };
    store.put_state_snapshot(&snap).expect("put snapshot");

    // drop & reopen to prove it persists
    drop(store);
    let store2: Persistence = open_db(&cfg).expect("reopen");

    // recover and compare
    let (accs2, supply2) = store2.recover_state(5).expect("recover");
    assert_eq!(accs2, accs, "accounts must round-trip identically");
    assert_eq!(supply2, supply, "supply must round-trip identically");
}