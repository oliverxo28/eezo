#![cfg(feature = "pq44-runtime")]

use eezo_ledger::{SingleNode, SingleNodeCfg};
use pqcrypto_mldsa::mldsa44::keypair;
mod support;

#[cfg(feature = "persistence")]
use support::temp_persistence;
use support::tx_build as tb;

fn fresh_node() -> SingleNode {
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

#[test]
fn single_transfer_happy_path() {
    let mut n = fresh_node();

    // Builder uses real ML-DSA-44 signatures under pq44-runtime
    let builders = tb::new_many([0xE0; 20], 1);
    let b = &builders[0];
    let sender = b.sender();
    let to = tb::addr(0xCC);

    // Prefund sender so tx can pass stateful checks
    n.supply.mint_native(&mut n.accounts, sender, 1_000_000).unwrap();

    // Send amount=1_000 with fee=10, nonce=0
    let amount = 1_000u128;
    let fee = 10u128;
    let stx = b.build(to, amount, fee, 0);
    n.mempool.enqueue_tx(stx);

    let (blk, _sum) = n.run_one_slot(false).expect("slot ok");

    // Block should include exactly one tx; header fields reflect it
    assert_eq!(blk.txs.len(), 1);
    assert_eq!(blk.header.tx_count, 1);
    assert_eq!(blk.header.fee_total, fee);

    // Account state updated: sender nonce advanced; balances moved
    let s_acct = n.accounts.get(&sender);
    let r_acct = n.accounts.get(&to);

    assert_eq!(s_acct.nonce, 1, "sender nonce should advance");
    // Sender paid amount + fee
    assert_eq!(
        s_acct.balance,
        1_000_000 - amount - fee,
        "sender balance after amount+fee"
    );
    // Receiver got amount
    assert_eq!(r_acct.balance, amount, "receiver balance should increase by amount");
}

#[test]
fn two_consecutive_txs_two_slots() {
    let mut n = fresh_node();

    let builders = tb::new_many([0xE0; 20], 1);
    let b = &builders[0];
    let sender = b.sender();
    let to = tb::addr(0xDD);

    n.supply.mint_native(&mut n.accounts, sender, 2_000_000).unwrap();

    // Two txs with nonces 0 and 1
    let a1 = 200u128;
    let f1 = 5u128;
    let a2 = 300u128;
    let f2 = 7u128;

    let t1 = b.build(to, a1, f1, 0);
    let t2 = b.build(to, a2, f2, 1);

    // --- Slot 1: include nonce=0 ---
    n.mempool.enqueue_tx(t1);
    let (blk1, _sum1) = n.run_one_slot(false).expect("slot1 ok");
    assert_eq!(blk1.txs.len(), 1);
    assert_eq!(blk1.header.tx_count, 1);
    assert_eq!(blk1.txs[0].core.nonce, 0);

    // --- Slot 2: include nonce=1 (now account nonce has advanced to 1) ---
    n.mempool.enqueue_tx(t2);
    let (blk2, _sum2) = n.run_one_slot(false).expect("slot2 ok");
    assert_eq!(blk2.txs.len(), 1);
    assert_eq!(blk2.header.tx_count, 1);
    assert_eq!(blk2.txs[0].core.nonce, 1);

    // Final account state after both slots
    let s_acct = n.accounts.get(&sender);
    let r_acct = n.accounts.get(&to);

    assert_eq!(s_acct.nonce, 2);
    assert_eq!(
        s_acct.balance,
        2_000_000 - (a1 + f1) - (a2 + f2),
        "sender pays both amount+fee across two slots"
    );
    assert_eq!(r_acct.balance, a1 + a2, "receiver gets both amounts");
}

