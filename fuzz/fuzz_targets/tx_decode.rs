#![no_main]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "eth-ssz")]
use eezo_ledger::{block::BlockHeader, SignedTx};
#[cfg(feature = "eth-ssz")]
use eezo_serde::eth::{Decode, Encode, HashTreeRoot};

fuzz_target!(|data: &[u8]| {
    // Only run this when ETH-SSZ is compiled in.
    #[cfg(feature = "eth-ssz")]
    {
        // SignedTx: decode → re-encode → decode → compare roots (stable semantics)
        if let Ok((tx, _used)) = SignedTx::ssz_read(data) {
            let enc = tx.ssz_bytes();
            if let Ok((tx2, _used2)) = SignedTx::ssz_read(&enc) {
                assert_eq!(tx.hash_tree_root(), tx2.hash_tree_root(), "SignedTx HTR mismatch");
            }
        }

        // BlockHeader: same roundtrip check
        if let Ok((h, _used)) = BlockHeader::ssz_read(data) {
            let enc = h.ssz_bytes();
            if let Ok((h2, _used2)) = BlockHeader::ssz_read(&enc) {
                assert_eq!(h.hash_tree_root(), h2.hash_tree_root(), "Header HTR mismatch");
            }
        }
    }
});

