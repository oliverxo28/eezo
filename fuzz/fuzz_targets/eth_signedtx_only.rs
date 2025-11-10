#![no_main]
use libfuzzer_sys::fuzz_target;

use eezo_ledger::SignedTx;
use eezo_serde::eth::{Decode, Encode, HashTreeRoot};

fuzz_target!(|data: &[u8]| {
    if let Ok((tx, used)) = SignedTx::ssz_read(data) {
        // roundtrip preserves root
        let root1 = tx.hash_tree_root();
        let enc = tx.ssz_bytes();
        if let Ok((tx2, used2)) = SignedTx::ssz_read(&enc) {
            assert_eq!(used2, enc.len(), "full decode");
            assert_eq!(root1, tx2.hash_tree_root(), "HTR must be stable");
            assert_eq!(tx, tx2, "SignedTx roundtrip mismatch");
        }
        // also accept partial input consumption info
        let _ = used;
    }
});
