#![cfg(feature = "pq44-runtime")]

use eezo_ledger::{
    Address, SignedTx,
    block::{assemble_block, header_hash},
    tx_types::TxCore,
    consensus::{SingleNode, SingleNodeCfg},
};
use pqcrypto_mldsa::mldsa44::keypair;

mod helpers; // mk_signed_tx lives here
use helpers::mk_signed_tx;

fn cfg() -> SingleNodeCfg {
    SingleNodeCfg {
        chain_id: [0xDD; 20],
        block_byte_budget: 64 * 1024,
        header_cache_cap: 1024,
        #[cfg(feature = "checkpoints")]
        checkpoint_interval: eezo_ledger::consensus::DEFAULT_CHECKPOINT_INTERVAL,
    ..Default::default()
}
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn two_nodes_assemble_identical_blocks() {
    // Two clean nodes with identical configs (different node keys is fine)
    let (pk1, sk1) = keypair();
    let (pk2, sk2) = keypair();
    let a = SingleNode::new(cfg(), sk1, pk1);
    let b = SingleNode::new(cfg(), sk2, pk2);

    // Same candidate set (all signed by pk1/sk1; both nodes will verify identically)
    let to = Address([0x11; 20]);
    let c0 = TxCore { to, amount: 50, fee: 3,  nonce: 0 };
    let c1 = TxCore { to, amount: 50, fee: 10, nonce: 1 };
    let c2 = TxCore { to, amount: 50, fee: 1,  nonce: 2 };

    let t0: SignedTx = mk_signed_tx(c0, &pk1, &a.sk, a.cfg.chain_id);
    let t1: SignedTx = mk_signed_tx(c1, &pk1, &a.sk, a.cfg.chain_id);
    let t2: SignedTx = mk_signed_tx(c2, &pk1, &a.sk, a.cfg.chain_id);

    // Reuse one timestamp so headers can be bit-identical
    let ts = now_ms();

    // Assemble on both nodes with identical inputs
    let ba = assemble_block(
        &a.accounts, a.cfg.chain_id, a.prev_hash, a.height + 1, a.cfg.block_byte_budget,
        vec![t0.clone(), t1.clone(), t2.clone()], ts
    ).expect("A assembled");

    let bb = assemble_block(
        &b.accounts, b.cfg.chain_id, b.prev_hash, b.height + 1, b.cfg.block_byte_budget,
        vec![t0, t1, t2], ts
    ).expect("B assembled");

    // Must be identical
    assert_eq!(ba.header.tx_root, bb.header.tx_root, "tx roots must match");
    assert_eq!(ba.header.tx_count, bb.header.tx_count, "tx counts must match");
    assert_eq!(header_hash(&ba.header), header_hash(&bb.header), "headers must match");
}
