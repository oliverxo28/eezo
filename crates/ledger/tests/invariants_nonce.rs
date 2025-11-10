#![cfg(feature = "pq44-runtime")]

// (Removed the compile_error! guard so the test can run under pq44-runtime)

use eezo_ledger::{SingleNode, SingleNodeCfg};
use pqcrypto_mldsa::mldsa44::keypair;
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence};
mod support;

#[cfg(feature = "persistence")]
use support::temp_persistence;
use support::tx_build as tb;

fn node() -> SingleNode {
    #[cfg(feature = "persistence")]
    let (_persistence, _tmp) = temp_persistence();

    let cfg = SingleNodeCfg {
        chain_id: [0xE0; 20],
        block_byte_budget: 64 * 1024,
        header_cache_cap: 1024,
        ..Default::default()
    };
    let (pk, sk) = keypair();
    SingleNode::new(cfg, sk, pk)
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            ".proptest-regressions-invariants_nonce"
        ))),
        .. ProptestConfig::default()
    })]
    #[test]
    fn nonces_monotonic_across_applies(runs in 1usize..5) {
        let mut n = node();
        let builders = tb::new_many([0xE0; 20], 1);
        let sender = builders[0].sender();
        let to = tb::addr(0xAB);

        // pre-fund sender so txs can succeed
        n.supply.mint_native(&mut n.accounts, sender, 1_000_000).unwrap();

        // enqueue txs with sequential nonces 0..runs
        for nonce in 0..runs {
            let tx = builders[0].build(to, 1, 10, nonce as u64);
            n.mempool.enqueue_tx(tx);
        }

        // run one slot to include as many as fit
        let (blk, _sum) = n.run_one_slot(false).unwrap();

        // expected: account nonce advanced exactly by number of included txs
        let acct = n.accounts.get(&sender);
        prop_assert_eq!(acct.nonce, blk.txs.len() as u64);
    }
}

#[test]
fn rejects_replay_and_gaps() {
    let mut n = node();
    let builders = tb::new_many([0xE0; 20], 1);
    let sender = builders[0].sender();
    let to = tb::addr(0xCD);

    n.supply.mint_native(&mut n.accounts, sender, 1_000_000).unwrap();

    // valid tx nonce=0
    let tx0 = builders[0].build(to, 1, 10, 0);
    n.mempool.enqueue_tx(tx0);
    let _ = n.run_one_slot(false).unwrap();

    // replay nonce=0 should be filtered out during candidate selection
    let replay = builders[0].build(to, 1, 10, 0);
    n.mempool.enqueue_tx(replay);
    let (blk, _) = n.propose_block().unwrap();
    // The block should be empty because replay was filtered out
    assert!(blk.txs.is_empty(), "replay should be filtered out");
    
    // validate_and_apply should succeed with empty block
    let res = n.validate_and_apply(&blk);
    assert!(res.is_ok(), "empty block should validate successfully");

    // gap nonce=5 should be filtered out during candidate selection  
    let gap = builders[0].build(to, 1, 10, 5);
    n.mempool.enqueue_tx(gap);
    let (blk2, _) = n.propose_block().unwrap();
    // The block should be empty because gap was filtered out
    assert!(blk2.txs.is_empty(), "skipped nonce should be filtered out");
    
    // validate_and_apply should succeed with empty block
    let res = n.validate_and_apply(&blk2);
    assert!(res.is_ok(), "empty block should validate successfully");
}
