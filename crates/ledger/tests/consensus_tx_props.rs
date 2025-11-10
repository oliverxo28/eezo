#![cfg(feature = "pq44-runtime")]

use eezo_ledger::{
    block::{tx_size_bytes, HEADER_BUDGET_BYTES},
    SingleNode, SingleNodeCfg,
};
use pqcrypto_mldsa::mldsa44::keypair;
mod support;
#[cfg(feature = "persistence")]
use support::temp_persistence;
use support::tx_build as tb;

fn fresh_node_with_budget(budget: usize) -> SingleNode {
    #[cfg(feature = "persistence")]
    let (_persistence, _tmp) = temp_persistence();

    let mut cfg = SingleNodeCfg::default();
    cfg.chain_id = [0xE0; 20];
    cfg.block_byte_budget = budget;
    cfg.header_cache_cap = 1024;

    let (pk, sk) = keypair();
    SingleNode::new(cfg, sk, pk)
}

// Helper to fund sender using the real API
fn fund_sender(node: &mut SingleNode, who: eezo_ledger::Address, amount: u128) {
    node.supply
        .mint_native(&mut node.accounts, who, amount)
        .expect("mint");
}

#[test]
fn fee_ordering_is_deterministic() {
    // Provide a large, fixed budget to ensure all txs can be processed.
    let mut node = fresh_node_with_budget(1_000_000);
    let builders = tb::new_many([0xE0; 20], 4);
    let to = tb::addr(0xAB);

    // Pre-fund each independent sender
    for b in &builders {
        fund_sender(&mut node, b.sender(), 1_000_000_000_000);
    }

    // Use nonce 0 for the first transaction from each account
    let txs = vec![
        builders[0].build(to, 1, 90, 0),
        builders[1].build(to, 1, 50, 0),
        builders[2].build(to, 1, 50, 0),
        builders[3].build(to, 1, 10, 0),
    ];

    for tx in txs {
        node.mempool.enqueue_tx(tx);
    }

    let out = node.run_one_slot(false).expect("slot runs");
    let (blk, _sum) = out;
    let fees: Vec<u128> = blk.txs.iter().map(|t| t.core.fee).collect();
    assert_eq!(
        fees,
        vec![90, 50, 50, 10],
        "fee-desc, stable tie-break preserved"
    );
}

#[test]
fn byte_budget_enforced() {
    let temp_builders = tb::new_many([0xE0; 20], 1);
    let temp_builder = &temp_builders[0];
    let small = temp_builder.build(tb::addr(0xCD), 100, 1, 0);

    // Calculate budget based on the accurate SSZ size.
    let small_sz = tx_size_bytes(&small);
    let budget = HEADER_BUDGET_BYTES + 2 * small_sz; // Budget for exactly 2 txs

    let mut node = fresh_node_with_budget(budget);
    let builders = tb::new_many([0xE0; 20], 4);
    let to = tb::addr(0xCD);

    // Pre-fund each independent sender
    for b in &builders {
        fund_sender(&mut node, b.sender(), 1_000_000_000_000);
    }

    // Use nonce 0 for the first transaction from each account
    let txs = vec![
        builders[0].build(to, 1, 100, 0),
        builders[1].build(to, 1, 90, 0),
        builders[2].build(to, 1, 80, 0),
        builders[3].build(to, 1, 70, 0),
    ];

    for tx in txs {
        node.mempool.enqueue_tx(tx);
    }

    let out = node.run_one_slot(false).expect("slot runs");
    let (blk, _sum) = out;
    assert_eq!(
        blk.header.tx_count, 2,
        "only two txs fit under the byte budget"
    );
}

#[test]
fn supply_invariant_preserved() {
    let mut node = fresh_node_with_budget(1_000_000);
    let builders = tb::new_many([0xE0; 20], 2);
    let to = tb::addr(0xEF);

    // Pre-fund sender
    fund_sender(&mut node, builders[0].sender(), 1_000_000_000);

    // Build tx: send 100 with fee 10
    let tx = builders[0].build(to, 100, 10, 0);
    node.mempool.enqueue_tx(tx);

    let (_blk, _sum) = node.run_one_slot(false).expect("slot runs");

    // Invariant: all minted minus burned == sum of all account balances.
    // Fees are already reflected in the sender's reduced balance.
    let supply_total = node.supply.native_mint_total
        + node.supply.bridge_mint_total
        - node.supply.burn_total;
    let balances_sum: u128 = node
        .accounts
        .iter()
        .map(|(_addr, acct)| acct.balance)
        .sum();
    assert_eq!(
        supply_total,
        balances_sum,
        "supply invariant must hold"
    );
}

#[test]
fn double_apply_is_rejected() {
    let mut node = fresh_node_with_budget(1_000_000);
    let builders = tb::new_many([0xE0; 20], 1);
    let to = tb::addr(0xF1);
    fund_sender(&mut node, builders[0].sender(), 1_000);

    let tx = builders[0].build(to, 10, 1, 0);
    node.mempool.enqueue_tx(tx);
    let (blk, _sum) = node.run_one_slot(false).expect("slot runs");

    // Block returned by run_one_slot is already applied.
    // Any attempt to re-apply must fail (replay).
    assert!(
        node.validate_and_apply(&blk).is_err(),
        "block is already applied internally; re-apply must be rejected"
    );
}

#[test]
fn invalid_tx_is_rejected() {
    let mut node = fresh_node_with_budget(1_000_000);
    let builders = tb::new_many([0xE0; 20], 1);
    let to = tb::addr(0xF2);
    fund_sender(&mut node, builders[0].sender(), 1_000);

    // Nonce = 5, but expected = 0 → invalid
    let bad_tx = builders[0].build(to, 10, 1, 5);
    node.mempool.enqueue_tx(bad_tx);

    match node.run_one_slot(false) {
        // strict mode: surface the bad nonce as an error
        Err(e) => {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("BadNonce") || msg.contains("invalid tx"),
                "expected BadNonce/InvalidTx, got {msg}"
            );
        }
        // filtering mode: slot succeeds but the invalid tx must not be included
        Ok((blk, _sum)) => {
            assert!(
                blk.txs.is_empty(),
                "bad-nonce tx must not land in a block"
            );
        }
    }
}
