#![cfg(feature = "pq44-runtime")]

// (Removed the compile_error! guard so the test can run under pq44-runtime)

use eezo_ledger::{SingleNode, SingleNodeCfg};
use pqcrypto_mldsa::mldsa44::keypair;
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence};
mod support;
use support::tx_build as tb;

#[cfg(feature = "persistence")]
use support::temp_persistence;

prop_compose! {
    fn block_budget()(k in 4_096usize..131_072usize) -> usize { k }
}

#[allow(dead_code)]
fn fresh_node(budget: usize) -> SingleNode {
    let cfg = SingleNodeCfg {
        chain_id: [0xE0; 20],
        block_byte_budget: budget,
        header_cache_cap: 1024,
        ..Default::default() // fills checkpoint_interval when feature="checkpoints"
    };
    let (pk, sk) = keypair();
    SingleNode::new(cfg, sk, pk)
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            ".proptest-regressions-invariants_txroot"
        ))),
        .. ProptestConfig::default()
    })]
    #[test]
    fn tx_root_deterministic(budget in block_budget()) {
        #[cfg(feature = "persistence")]
        let (p1, _t1) = temp_persistence();
        #[cfg(feature = "persistence")]
        let (p2, _t2) = temp_persistence();

        let cfg = SingleNodeCfg {
            chain_id: [0xE0; 20],
            block_byte_budget: budget,
            header_cache_cap: 1024,
            ..Default::default()          // fills checkpoint_interval when feature="checkpoints"
        };

        let (pk1, sk1) = keypair();
        let mut n1 = SingleNode::new(cfg.clone(), sk1, pk1);

        let (pk2, sk2) = keypair();
        let mut n2 = SingleNode::new(cfg, sk2, pk2);

        // Build 4 deterministic txs from same sender
        let builders = tb::new_many([0xE0; 20], 1);
        let sender = builders[0].sender();
        let to = tb::addr(0xAB);
        n1.supply.mint_native(&mut n1.accounts, sender, 1_000_000).unwrap();
        n2.supply.mint_native(&mut n2.accounts, sender, 1_000_000).unwrap();

        let mut txs: Vec<_> = (0..4)
            .map(|nonce| builders[0].build(to, 1, 5, nonce))
            .collect();
        // enqueue in order for n1
        for tx in txs.clone() {
            n1.mempool.enqueue_tx(tx);
        }
        // enqueue in reverse order for n2
        txs.reverse();
        for tx in txs {
            n2.mempool.enqueue_tx(tx);
        }

        let out1 = n1.run_one_slot(false).expect("slot runs");
        let (blk1, _sum1) = out1;                    // out1: (Block, SlotSummary)
        let _h1 = blk1.header.height;
        #[cfg(feature = "persistence")]
        p1.put_block(_h1, &blk1).expect("persist block for n1");

        // FIX: Properly gate the block loading based on persistence feature
        #[cfg(feature = "persistence")]
        let b1 = p1.get_block(_h1).expect("load committed block for n1");
        #[cfg(not(feature = "persistence"))]
        let b1 = blk1.clone();

        let out2 = n2.run_one_slot(false).expect("slot runs");
        let (blk2, _sum2) = out2;                    // out2: (Block, SlotSummary)
        let _h2 = blk2.header.height;
        #[cfg(feature = "persistence")]
        p2.put_block(_h2, &blk2).expect("persist block for n2");

        // FIX: Properly gate the block loading based on persistence feature
        #[cfg(feature = "persistence")]
        let b2 = p2.get_block(_h2).expect("load committed block for n2");
        #[cfg(not(feature = "persistence"))]
        let b2 = blk2.clone();

        // Roots must be identical regardless of mempool insertion order
        prop_assert_eq!(b1.header.tx_root, b2.header.tx_root);
    }
}