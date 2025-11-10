#![cfg(all(feature = "pq44-runtime", feature = "checkpoints", not(feature = "checkpoints-verify")))]

use eezo_ledger::{SingleNode, SingleNodeCfg};
use pqcrypto_mldsa::mldsa44::keypair;

#[test]
fn checkpoints_cfg_compiles_and_node_runs() {
    // Defaulted interval (0 -> uses DEFAULT_CHECKPOINT_INTERVAL internally)
    let cfg0 = SingleNodeCfg {
        chain_id: [7u8; 20],
        block_byte_budget: 4096,
        header_cache_cap: 1024,
        checkpoint_interval: 0u64,
    };
    let (pk0, sk0) = keypair();
    let mut n0 = SingleNode::new(cfg0, sk0, pk0);
    let _ = n0.run_one_slot(true); // just ensure it runs/compiles

    // Explicit interval set (we don’t peek inside; just ensure it doesn’t break)
    let cfg1 = SingleNodeCfg {
        chain_id: [7u8; 20],
        block_byte_budget: 4096,
        header_cache_cap: 1024,
        checkpoint_interval: 7u64,
    };
    let (pk1, sk1) = keypair();
    let mut n1 = SingleNode::new(cfg1, sk1, pk1);
    let _ = n1.run_one_slot(true);
}

#[test]
fn interval_one_attaches_every_block() {
    let (pk, sk) = keypair();
    let chain_id = [0xA1u8; 20];
    let cfg = SingleNodeCfg {
        chain_id,
        block_byte_budget: 2048,
        header_cache_cap: 64,
        checkpoint_interval: 1u64,
    };
    let mut n = SingleNode::new(cfg, sk, pk);

    // Height 1: no previous header to certify → qc_hash == 0.
    let (b1, _s1) = n.run_one_slot(false).expect("slot1");
    assert_eq!(b1.header.height, 1);
    assert_eq!(b1.header.qc_hash, [0u8; 32], "first block should not have a QC");

    // From height 2 onward, QC attaches every block when interval=1.
    let (b2, _s2) = n.run_one_slot(false).expect("slot2");
    assert_eq!(b2.header.height, 2);
    assert_ne!(b2.header.qc_hash, [0u8; 32], "QC must attach from height 2 with interval=1");

    let (b3, _s3) = n.run_one_slot(false).expect("slot3");
    assert_eq!(b3.header.height, 3);
    assert_ne!(b3.header.qc_hash, [0u8; 32], "QC must attach every block thereafter with interval=1");
}

#[test]
fn interval_k_attaches_only_on_multiples() {
    let (pk, sk) = keypair();
    let chain_id = [0xA2u8; 20];
    let k = 3u64;
    let cfg = SingleNodeCfg {
        chain_id,
        block_byte_budget: 2048,
        header_cache_cap: 64,
        checkpoint_interval: k,
    };
    let mut n = SingleNode::new(cfg, sk, pk);

    // Heights 1..6; only 3 and 6 should carry a non-zero qc_hash.
    for h in 1..=6u64 {
        let (b, _s) = n.run_one_slot(false).expect("slot");
        assert_eq!(b.header.height, h);
        let expects_qc = h % k == 0;
        if expects_qc {
            assert_ne!(b.header.qc_hash, [0u8; 32], "expected QC at height {}", h);
        } else {
            assert_eq!(b.header.qc_hash, [0u8; 32], "unexpected QC at height {}", h);
        }
    }
}