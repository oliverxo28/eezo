#![cfg(feature = "eth-ssz")]

use eezo_ledger::{Address, SignedTx, TxCore, block::BlockHeader};
use eezo_serde::eth::{Encode, Decode, HashTreeRoot};

fn mk_tx(nonce: u64) -> SignedTx {
    let to = Address::from_bytes([0xAB; 20]);
    SignedTx {
        core: TxCore { to, amount: 42, fee: 3, nonce },
        pubkey: vec![1u8; 32],
        sig: vec![2u8; 64],
    }
}

#[test]
fn signed_tx_roundtrip_and_root() {
    let tx = mk_tx(7);
    let bytes = tx.ssz_bytes();
    let (tx2, used) = SignedTx::ssz_read(&bytes).expect("decode ok");
    assert_eq!(used, bytes.len());
    assert_eq!(tx.hash_tree_root(), tx2.hash_tree_root());
}

#[test]
fn header_roundtrip_and_root() {
    let hdr = BlockHeader {
        height: 10,
        prev_hash: [9u8;32],
        tx_root: [8u8;32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [7u8;32],
        fee_total: 123,
        tx_count: 2,
        timestamp_ms: 999,
        #[cfg(feature = "checkpoints")]
        qc_hash: [6u8;32],
    };
    let bytes = hdr.ssz_bytes();
    let (hdr2, used) = BlockHeader::ssz_read(&bytes).expect("decode ok");
    assert_eq!(used, bytes.len());
    assert_eq!(hdr.hash_tree_root(), hdr2.hash_tree_root());
}
