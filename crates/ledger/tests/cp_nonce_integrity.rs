#![cfg(feature = "pq44-runtime")]

use eezo_ledger::{SingleNode, SingleNodeCfg};

use pqcrypto_mldsa::mldsa44::keypair;

mod support;

use support::tx_build as tb;

fn node() -> SingleNode {
    let cfg = SingleNodeCfg {
        chain_id: [0xE0; 20],
        block_byte_budget: 64 * 1024,
        header_cache_cap: 1024,
        ..Default::default()
    };

    let (pk, sk) = keypair();
    SingleNode::new(cfg, sk, pk)
}

#[test]
fn no_gap_and_no_replay_for_one_sender() {
    let mut n = node();
    let builders = tb::new_many([0xE0; 20], 1);
    let b = &builders[0];
    let sender = b.sender();
    let to = tb::addr(0xBB);

    n.supply.mint_native(&mut n.accounts, sender, 1_000_000).unwrap();

    // Enqueue nonce=1 WITHOUT nonce=0 → should produce empty block (filtered by mempool)
    n.mempool.enqueue_tx(b.build(to, 10, 1, 1));

    // The slot should succeed but produce an empty block due to invalid nonce being filtered
    let (blk, _sum) = n.run_one_slot(false).expect("slot should succeed with empty block");
    assert!(blk.txs.is_empty(), "block should be empty due to nonce gap");

    // Now enqueue nonce=0, then 1 → both included, in order.
    n.mempool.enqueue_tx(b.build(to, 10, 1, 0));
    n.mempool.enqueue_tx(b.build(to, 20, 2, 1));

    let (blk1, _sum) = n.run_one_slot(false).expect("slot ok");
    assert_eq!(blk1.txs.len(), 2);
    assert!(blk1.txs[0].core.nonce < blk1.txs[1].core.nonce);

    // Replay nonce=1 again must be filtered/rejected.
    n.mempool.enqueue_tx(b.build(to, 5, 1, 1)); // replay

    let (blk2, _sum) = n.run_one_slot(false).expect("slot ok");
    assert!(blk2.txs.is_empty(), "replay should be filtered out");
}
