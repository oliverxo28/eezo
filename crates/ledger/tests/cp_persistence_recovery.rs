#![cfg(feature = "persistence")]

use eezo_ledger::block::{Block, BlockHeader};
use eezo_ledger::persistence::{open_db, Persistence};
use eezo_ledger::config::PersistenceCfg;
use tempfile::tempdir;

#[test]
fn tip_and_headers_survive_reopen_consistently() {
    let dir = tempdir().unwrap();
    let cfg = PersistenceCfg {
        db_path: dir.path().join("db"),
        ..Default::default()
    };

    let db: Persistence = open_db(&cfg).expect("open");
    db.set_genesis(0).unwrap();

    // Write two consecutive headers/blocks and advance tip.
    for h in 1..=2u64 {
        let header = BlockHeader {
            height: h,
            prev_hash: [0u8; 32],
            tx_root: [0u8; 32],
            #[cfg(feature = "eth-ssz")]
            tx_root_v2: [0u8; 32],
            fee_total: 0,
            tx_count: 0,
            timestamp_ms: 0,
            #[cfg(feature = "checkpoints")]
            qc_hash: [0u8; 32],
        };
        let blk = Block { header, txs: vec![] };
        db.put_block(h, &blk).unwrap();
        db.set_tip(h).unwrap();
        let hdr = db.get_header(h).unwrap();
        assert_eq!(hdr.height, h);
    }
    assert_eq!(db.get_tip().unwrap(), 2);

    drop(db);
    // Reopen and confirm tip/header are identical.
    let db2: Persistence = open_db(&cfg).expect("reopen");
    assert_eq!(db2.get_tip().unwrap(), 2);
    assert_eq!(db2.get_header(2).unwrap().height, 2);
}