#![cfg(feature = "eth-ssz")]

use eezo_ledger::{eth_ssz::txs_root_v2, Address, SignedTx, TxCore};

fn mk_tx(
    to: [u8; 20],
    amount: u128,
    fee: u128,
    nonce: u64,
    pubkey_len: usize,
    sig_len: usize,
) -> SignedTx {
    SignedTx {
        core: TxCore {
            to: Address::from_bytes(to),
            amount,
            fee,
            nonce,
        },
        pubkey: vec![7u8; pubkey_len],
        sig: vec![9u8; sig_len],
    }
}

#[test]
fn v2_root_is_order_independent() {
    // 4 simple txs with distinct nonces
    let to = [0x11u8; 20];
    let txs = vec![
        mk_tx(to, 10, 1, 0, 32, 64),
        mk_tx(to, 20, 1, 1, 32, 64),
        mk_tx(to, 30, 2, 2, 32, 64),
        mk_tx(to, 40, 3, 3, 32, 64),
    ];

    let r0 = txs_root_v2(&txs);

    // a few different permutations
    let mut p1 = txs.clone();
    p1.swap(0, 3);
    let mut p2 = txs.clone();
    p2.swap(1, 2);
    let p3 = vec![txs[3].clone(), txs[1].clone(), txs[0].clone(), txs[2].clone()];

    assert_eq!(r0, txs_root_v2(&p1));
    assert_eq!(r0, txs_root_v2(&p2));
    assert_eq!(r0, txs_root_v2(&p3));
}