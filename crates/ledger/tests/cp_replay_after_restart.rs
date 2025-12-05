#![cfg(all(feature = "pq44-runtime", feature = "persistence"))]

use eezo_ledger::{
    Address, SignedTx,
    block::assemble_block,
    tx_types::TxCore,
    consensus::{SingleNode, SingleNodeCfg},
};

mod helpers; // pulls in mk_signed_tx()
use helpers::mk_signed_tx;

fn cfg() -> SingleNodeCfg {
    SingleNodeCfg {
        chain_id: [0xEE; 20],
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
fn replay_is_rejected_after_restart() {
    use pqcrypto_mldsa::mldsa44::keypair;

    let (pk, sk) = keypair();
    let mut n = SingleNode::new(cfg(), sk, pk);

    let to = Address([0xAB; 20]);

    // First tx (nonce 0), properly signed
    let core0 = TxCore { to, amount: 10, fee: 1, nonce: 0 };
    let tx0: SignedTx = mk_signed_tx(core0, &pk, &sk, n.cfg.chain_id);

    // Assemble/apply a block containing tx0
    let blk1 = assemble_block(
        &n.accounts, n.cfg.chain_id, n.prev_hash, n.height + 1, n.cfg.block_byte_budget,
        vec![tx0.clone()], now_ms()
    ).expect("assembled");
    n.validate_and_apply(&blk1).expect("apply b1");

    // “Restart”: new node with same cfg/keys; persistence feature should restore state
    drop(n);
    let mut n2 = SingleNode::new(cfg(), sk, pk);

    // Try to assemble the same tx again (nonce 0 → replay)
    let blk2 = assemble_block(
        &n2.accounts, n2.cfg.chain_id, n2.prev_hash, n2.height + 1, n2.cfg.block_byte_budget,
        vec![tx0], now_ms()
    ).expect("assembled2");

    // Either the assembler filtered it out (count==0) or validation rejects it.
    match n2.validate_and_apply(&blk2) {
        Ok(()) => assert_eq!(blk2.header.tx_count, 0, "replay must not be included again"),
        Err(_) => { /* also acceptable: stateful replay caught */ }
    }
}