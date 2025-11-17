// tests/checkpoints_stub.rs
#![cfg(feature = "checkpoints")]

use eezo_ledger::block::{Block, BlockHeader};
use eezo_ledger::checkpoints::verify_qc_stub;

#[test]
fn verify_qc_stub_accepts_zero_and_nonzero_hash() {
    // zero qc_hash -> trivially accepted
    let h0 = BlockHeader {
        height: 1,
        prev_hash: [0u8; 32],
        tx_root: [0u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 0,
        tx_count: 0,
        timestamp_ms: 0,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    };
    let b0 = Block {
        header: h0,
        txs: vec![],
    };
    assert!(verify_qc_stub(&b0));

    // non-zero qc_hash -> stub verify still true
    let mut h1 = b0.header.clone();
    #[cfg(feature = "checkpoints")]
    {
        h1.qc_hash = [1u8; 32];
    }
    let b1 = Block {
        header: h1,
        txs: vec![],
    };
    assert!(verify_qc_stub(&b1));
}

// NEW: Add this test for the QC message format and threshold helpers
#[test]
fn qc_message_stable_shape() {
    use eezo_ledger::checkpoints::{qc_message_bytes, quorum_threshold, QC_DOMAIN};
    use eezo_ledger::QcHash;

    let chain = [0xE0u8; 20];
    let h: u64 = 42;
    let bh: QcHash = [7u8; 32];

    let msg = qc_message_bytes(chain, h, &bh);
    // domain prefix
    assert!(msg.starts_with(QC_DOMAIN));
    // size = domain + 20 + 8 + 32
    assert_eq!(msg.len(), QC_DOMAIN.len() + 20 + 8 + 32);

    // quick threshold checks
    assert_eq!(quorum_threshold(1), 1);
    assert_eq!(quorum_threshold(2), 2);
    assert_eq!(quorum_threshold(3), 3);
    assert_eq!(quorum_threshold(4), 3);
    assert_eq!(quorum_threshold(5), 4);
}

// NEW: Determinism + input sensitivity (without assuming endianness)
#[test]
fn qc_message_determinism_and_input_sensitivity() {
    use eezo_ledger::checkpoints::{qc_message_bytes, QC_DOMAIN};
    use eezo_ledger::QcHash;

    let chain = [0xABu8; 20];
    let h1: u64 = 1;
    let h2: u64 = 256; // differs in a different byte position than 1
    let bh = [0xCDu8; 32] as QcHash;

    let m1a = qc_message_bytes(chain, h1, &bh);
    let m1b = qc_message_bytes(chain, h1, &bh);
    assert_eq!(m1a, m1b, "same inputs must produce identical bytes");
    assert!(m1a.starts_with(QC_DOMAIN));

    // Offsets inside the message
    let dom = QC_DOMAIN.len();
    let off_chain = dom;
    let off_height = dom + 20;
    let off_bh = dom + 20 + 8;

    // Change *only* height → only height slice should differ
    let m2 = qc_message_bytes(chain, h2, &bh);
    assert_eq!(&m1a[0..off_chain], &m2[0..off_chain], "prefix (domain) must match");
    assert_eq!(&m1a[off_chain..off_height], &m2[off_chain..off_height], "chain id region must match");
    assert_ne!(&m1a[off_height..off_bh], &m2[off_height..off_bh], "height region must differ");
    assert_eq!(&m1a[off_bh..], &m2[off_bh..], "qc hash region must match");

    // Change *only* chain → only chain slice should differ
    let mut chain2 = chain;
    chain2[0] ^= 0xFF;
    let m3 = qc_message_bytes(chain2, h1, &bh);
    assert_ne!(&m1a[off_chain..off_height], &m3[off_chain..off_height], "chain id region must differ");
    assert_eq!(&m1a[off_height..off_bh], &m3[off_height..off_bh], "height region must match");
    assert_eq!(&m1a[off_bh..], &m3[off_bh..], "qc hash region must match");

    // Change *only* qc hash → only hash slice should differ
    let mut bh2 = bh;
    bh2[0] ^= 0x55;
    let m4 = qc_message_bytes(chain, h1, &bh2);
    assert_eq!(&m1a[off_chain..off_height], &m4[off_chain..off_height], "chain id region must match");
    assert_eq!(&m1a[off_height..off_bh], &m4[off_height..off_bh], "height region must match");
    assert_ne!(&m1a[off_bh..], &m4[off_bh..], "qc hash region must differ");
}

// NEW: Quorum threshold general properties (monotonic + range)
#[test]
fn quorum_threshold_properties() {
    use eezo_ledger::checkpoints::quorum_threshold;

    let mut last = 0usize;
    for n in 1usize..=64 {
        let q = quorum_threshold(n);
        assert!(q >= 1, "q(n) must be at least 1 for n>=1");
        assert!(q <= n, "q(n) must not exceed n");
        assert!(q >= last, "q(n) must be non-decreasing");
        last = q;
    }

    // Large n should be safe to call (no panic / overflow)
    let _ = quorum_threshold(100_000usize);
}

// NEW: Stub ignores unrelated header fields and accepts >1 heights
#[test]
fn stub_verifier_irrelevant_fields_and_heights() {
    for h in 1u64..=5 {
        let mut prev = [0u8; 32];
        prev[0] = h as u8;
        let hdr = BlockHeader {
            height: h,
            prev_hash: prev,
            tx_root: [h as u8; 32],
            #[cfg(feature = "eth-ssz")]
            tx_root_v2: [0u8; 32],
            fee_total: (h as u128) * 10u128,
            tx_count: h as u32,
            timestamp_ms: 123456 + h,
            #[cfg(feature = "checkpoints")]
            qc_hash: if h % 2 == 0 { [0u8; 32] } else { [1u8; 32] },
        };
        let blk = Block { header: hdr, txs: vec![] };
        assert!(verify_qc_stub(&blk));
    }
}