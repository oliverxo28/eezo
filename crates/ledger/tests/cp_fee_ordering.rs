#![cfg(all(feature = "pq44-runtime", feature = "testing"))]

use eezo_ledger::{
    Address, SignedTx,
    block::assemble_block,
    tx_types::TxCore,
    consensus::{SingleNode, SingleNodeCfg},
    sender_from_pubkey_first20,
};

use pqcrypto_mldsa::mldsa44::keypair;

mod helpers; // mk_signed_tx()
use helpers::mk_signed_tx;

fn cfg() -> SingleNodeCfg {
    SingleNodeCfg {
        chain_id: [0xF0; 20],
        block_byte_budget: 64 * 1024,
        header_cache_cap: 1024,
        #[cfg(feature = "checkpoints")]
        checkpoint_interval: eezo_ledger::consensus::DEFAULT_CHECKPOINT_INTERVAL,
    ..Default::default()
}
}

#[test]
fn fee_grouping_and_nonce_ordering_are_respected() {
    let (pk, sk) = keypair();
    let node = SingleNode::new(cfg(), sk, pk);

    // Same recipient, single sender; fees vary, nonces must be contiguous
    let to = Address([0x33; 20]);
    let c0 = TxCore { to, amount: 5,  fee: 3,  nonce: 0 };
    let c1 = TxCore { to, amount: 5,  fee: 10, nonce: 1 };
    let c2 = TxCore { to, amount: 5,  fee: 1,  nonce: 2 };

    // Sign all with the same sender (pk/sk)
    let t0: SignedTx = mk_signed_tx(c0, &pk, &sk, node.cfg.chain_id);
    let t1: SignedTx = mk_signed_tx(c1, &pk, &sk, node.cfg.chain_id);
    let t2: SignedTx = mk_signed_tx(c2, &pk, &sk, node.cfg.chain_id);

    // FUND the sender so stateful validation passes inside assemble_block
    let sender = sender_from_pubkey_first20(&t0).expect("sender");
    let mut node = node; // take mutable after we have sender
    node.accounts.credit_unchecked_for_testing(sender, 1_000_000);
    node.accounts.set_nonce_unchecked_for_testing(sender, 0);

    // One shared timestamp so headers would be identical if compared
    let ts = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    };

    // Assemble with all three candidates
    let blk = assemble_block(
        &node.accounts,
        node.cfg.chain_id,
        node.prev_hash,
        node.height + 1,
        node.cfg.block_byte_budget,
        vec![t0, t1, t2],
        ts,
    ).expect("assembled");

    // All should be included
    assert_eq!(blk.header.tx_count, 3, "all three must be included");

    // Because they share a sender, assembler must output them in **nonce order**
    let nonces: Vec<u64> = blk.txs.iter().map(|tx| tx.core.nonce).collect();
    assert_eq!(nonces, vec![0, 1, 2], "same-sender txs must be in nonce order");
}
