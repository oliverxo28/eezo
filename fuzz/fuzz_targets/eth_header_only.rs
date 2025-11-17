#![no_main]
use libfuzzer_sys::fuzz_target;

use eezo_ledger::block::BlockHeader;
use eezo_serde::eth::{Decode, Encode};

fuzz_target!(|data: &[u8]| {
    if let Ok((h, used)) = BlockHeader::ssz_read(data) {
        // roundtrip
        let enc = h.ssz_bytes();
        if let Ok((h2, used2)) = BlockHeader::ssz_read(&enc) {
            assert!(used > 0, "consume check");
            assert_eq!(used2, enc.len(), "full decode");
            assert_eq!(h, h2, "header roundtrip mismatch");
        }
    }
});
