#![cfg(all(feature = "pq44-runtime", not(feature = "skip-sig-verify"), not(feature = "testing")))]

use eezo_ledger::{verify_signed_tx, SingleNode, SingleNodeCfg};
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
fn bad_signature_never_applies() {
    let mut n = node();
    let chain_id = [0xE0; 20];

    let builders = tb::new_many(chain_id, 1);
    let b = &builders[0];
    let sender = b.sender();
    let to = tb::addr(0xCD);

    n.supply.mint_native(&mut n.accounts, sender, 1_000_000).unwrap();

    // Build a valid tx then corrupt the signature.
    let mut stx = b.build(to, 123, 5, 0);
    assert!(verify_signed_tx(chain_id, &stx));
    stx.sig[0] ^= 1;
    assert!(!verify_signed_tx(chain_id, &stx));

    n.mempool.enqueue_tx(stx);
    let (blk, _sum) = n.run_one_slot(false).expect("slot ok");
    assert!(blk.txs.is_empty(), "bad signature must never make it into a block");
}
