#![cfg(all(feature = "checkpoints", feature = "persistence"))]

use eezo_ledger::{Block, BlockHeader};
use pqcrypto_mldsa::mldsa44::keypair;

mod support;
use support::temp_persistence;

#[test]
fn qc_hash_survives_persistence_roundtrip() {
    let (_pk, _sk) = keypair();
    let (p, _tmp) = temp_persistence();

    let h = BlockHeader {
        height: 42,
        prev_hash: [1u8; 32],
        tx_root: [2u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 0,
        tx_count: 0,
        timestamp_ms: 123456,
        #[cfg(feature = "checkpoints")]
        qc_hash: [9u8; 32],
    };
    let b = Block {
        header: h,
        txs: Vec::new(),
    };

    p.put_header_and_block(b.header.height, &b.header, &b)
        .expect("put header+block");

    let hdr2 = p.get_header(b.header.height).expect("get header");
    let blk2 = p.get_block(b.header.height).expect("get block");

    assert_eq!(hdr2.qc_hash, [9u8; 32], "qc_hash must round-trip in header");
    assert_eq!(
        blk2.header.qc_hash, [9u8; 32],
        "qc_hash must round-trip in block"
    );
}

/// Write multiple heights with a mix of zero/non-zero qc_hash and ensure all round-trip intact.
#[test]
fn qc_hash_multi_height_roundtrip() {
    let (_pk, _sk) = keypair();
    let (p, _tmp) = temp_persistence();

    // Heights 1..6: only even heights carry a QC in this synthetic data.
    for h in 1u64..=6 {
        let qc = if h % 2 == 0 { [h as u8; 32] } else { [0u8; 32] };
        let hdr = BlockHeader {
            height: h,
            prev_hash: [0xAA; 32],
            tx_root: [0xBB; 32],
            #[cfg(feature = "eth-ssz")]
            tx_root_v2: [0u8; 32],
            fee_total: 0,
            tx_count: 0,
            timestamp_ms: 1000 + h,
            #[cfg(feature = "checkpoints")]
            qc_hash: qc,
        };
        let blk = Block { header: hdr, txs: vec![] };
        p.put_header_and_block(h, &blk.header, &blk)
            .expect("put header+block");
    }

    for h in 1u64..=6 {
        let hdr = p.get_header(h).expect("get header");
        let blk = p.get_block(h).expect("get block");
        let want_qc = if h % 2 == 0 { [h as u8; 32] } else { [0u8; 32] };
        assert_eq!(hdr.qc_hash, want_qc, "header qc mismatch at height {}", h);
        assert_eq!(
            blk.header.qc_hash, want_qc,
            "block qc mismatch at height {}",
            h
        );
    }
}

/// Rewriting the same height with identical data should be idempotent (no corruption, same readback).
#[test]
fn qc_hash_idempotent_overwrite_same_height() {
    let (_pk, _sk) = keypair();
    let (p, _tmp) = temp_persistence();

    let h = 5u64;
    let hdr = BlockHeader {
        height: h,
        prev_hash: [3u8; 32],
        tx_root: [4u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 0,
        tx_count: 0,
        timestamp_ms: 777,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0x5Au8; 32],
    };
    let blk = Block { header: hdr, txs: vec![] };

    // First write
    p.put_header_and_block(h, &blk.header, &blk)
        .expect("put #1");
    // Second write (identical)
    p.put_header_and_block(h, &blk.header, &blk)
        .expect("put #2");

    let hdr2 = p.get_header(h).expect("get header");
    let blk2 = p.get_block(h).expect("get block");

    assert_eq!(hdr2.qc_hash, [0x5Au8; 32]);
    assert_eq!(blk2.header.qc_hash, [0x5Au8; 32]);
    assert_eq!(hdr2.height, h);
    assert_eq!(blk2.header.height, h);
}

/// Ensure our DB helpers can read back tx_root_v2 and timestamp (secs) for a stored block.
#[cfg(feature = "eth-ssz")]
#[test]
fn tx_root_v2_and_timestamp_getters_roundtrip() {
    let (_pk, _sk) = keypair();
    let (p, _tmp) = temp_persistence();

    let h = 7u64;
    let hdr = BlockHeader {
        height: h,
        prev_hash: [0x11u8; 32],
        tx_root: [0x22u8; 32],
        tx_root_v2: [0xCDu8; 32], // <- v2 root we expect to read back
        fee_total: 0,
        tx_count: 0,
        timestamp_ms: 4_242_000, // 4242 seconds
        qc_hash: [0x33u8; 32],
    };
    let blk = Block {
        header: hdr,
        txs: vec![],
    };

    // Write header + block
    p.put_header_and_block(h, &blk.header, &blk)
        .expect("put header+block");

    // Read back via helpers
    let got_tx_v2 = p.get_tx_root_v2(h).expect("get tx_root_v2");
    let got_ts = p.get_block_timestamp_secs(h).expect("get ts secs");

    assert_eq!(
        got_tx_v2,
        [0xCDu8; 32],
        "tx_root_v2 must round-trip"
    );
    assert_eq!(
        got_ts, 4242,
        "timestamp (secs) must be header.timestamp_ms/1000"
    );
}
