#![cfg(feature = "pq44-runtime")]

// (Removed the compile_error! guard so the test can run under pq44-runtime)

use eezo_ledger::{SingleNode, SingleNodeCfg};
use pqcrypto_mldsa::mldsa44::keypair;
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence};
mod support;
use support::tx_build as tb;

fn node() -> SingleNode {
    let (pk, sk) = keypair();
    let cfg = SingleNodeCfg {
        chain_id: [0xE0; 20],
        block_byte_budget: 64 * 1024,
        header_cache_cap: 1024,
        ..Default::default() // fills checkpoint_interval (and future fields) safely
    };
    SingleNode::new(cfg, sk, pk)
}

fn supply_total(n: &SingleNode) -> u128 {
    n.supply.native_mint_total + n.supply.bridge_mint_total - n.supply.burn_total
}

fn sum_balances(n: &SingleNode) -> u128 {
    n.accounts.iter().map(|(_addr, acct)| acct.balance).sum()
}

fn fund(n: &mut SingleNode, who: eezo_ledger::Address, amount: u128) {
    n.supply.mint_native(&mut n.accounts, who, amount).expect("mint");
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            ".proptest-regressions-invariants_supply"
        ))),
        .. ProptestConfig::default()
    })]
    #[test]
    fn supply_conservation_holds(n_txs in 1usize..5usize) {
        let mut n = node();

        // Arrange: two funded senders and a sink address
        let builders = tb::new_many([0xE0; 20], 2);
        let a = builders[0].sender();
        let b = builders[1].sender();
        let to = tb::addr(0xAA);
        fund(&mut n, a, 1_000_000);
        fund(&mut n, b, 1_000_000);

        // Baseline invariant before any transfers
        let supply_before = supply_total(&n);
        let balances_before = sum_balances(&n);
        prop_assert_eq!(supply_before, balances_before, "pre: supply must equal total balances");

        // Enqueue n_txs transfers with fees from alternating senders,
        // maintaining a per-sender nonce counter to avoid gaps.
        let mut n_a: u64 = 0;
        let mut n_b: u64 = 0;
        for i in 0..n_txs {
            let tx = if i % 2 == 0 {
                let tx = builders[0].build(to, 10, 3, n_a); // amount=10, fee=3
                n_a += 1;
                tx
            } else {
                let tx = builders[1].build(to, 7, 2, n_b);  // amount=7,  fee=2
                n_b += 1;
                tx
            };
            n.mempool.enqueue_tx(tx);
        }
        let (blk, _sum) = n.run_one_slot(false).expect("slot runs");
        let fees_committed: u128 = blk.txs.iter().map(|t| t.core.fee as u128).sum();

        // Assert: total supply unchanged by pure transfers; no fee leak
        let supply_after = supply_total(&n);
        let balances_after = sum_balances(&n);
        // supply equals balances at all times
        prop_assert_eq!(supply_after, balances_after, "post: supply must equal total balances");
        // fees are burned in this model → supply decreases exactly by fees committed
        prop_assert_eq!(supply_after, supply_before - fees_committed, "supply must decrease by fees");
    }
}