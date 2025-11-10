#![cfg(feature = "pq44-runtime")]

// Supply is conserved except for burned fees; apply two txs over two slots to avoid fee-priority reordering.
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
fn supply_conserved_minus_fees_over_block() {
    let mut n = node();
    let builders = tb::new_many([0xE0; 20], 1);
    let b = &builders[0];
    let sender = b.sender();
    let to = tb::addr(0xFA);

    // Prefund sender; we’ll burn fees later.
    n.supply.mint_native(&mut n.accounts, sender, 1_000_000).unwrap();

    // Two txs with nonces 0 and 1, applied over TWO slots to respect nonce ordering regardless of fee priority.
    let a1 = 200u128; let f1 = 5u128;
    let a2 = 300u128; let f2 = 7u128;

    let before_total_bal = n.accounts.balance_of(sender) + n.accounts.balance_of(to);
    let before_supply = n.supply.circulating();

    // Slot 1: include nonce=0
    n.mempool.enqueue_tx(b.build(to, a1, f1, 0));
    let (blk1, _sum1) = n.run_one_slot(false).expect("slot 1 ok");
    assert_eq!(blk1.txs.len(), 1);
    assert_eq!(blk1.header.tx_count, 1);

    // Slot 2: include nonce=1
    n.mempool.enqueue_tx(b.build(to, a2, f2, 1));
    let (blk2, _sum2) = n.run_one_slot(false).expect("slot 2 ok");
    assert_eq!(blk2.txs.len(), 1);
    assert_eq!(blk2.header.tx_count, 1);

    // Check cumulative effects after both slots.
    let after_total_bal = n.accounts.balance_of(sender) + n.accounts.balance_of(to);
    let after_supply = n.supply.circulating();

    // Only fees are destroyed from balances; transfer itself is internal.
    assert_eq!(before_total_bal - after_total_bal, f1 + f2, "balances drop by fees only");
    // Supply is reduced exactly by burned fees across both blocks.
    assert_eq!(before_supply - after_supply, f1 + f2, "supply burned equals fee total");
}