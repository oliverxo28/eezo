use eezo_ledger::mempool::{MempoolError, VerifyCache, validate_witness};
use eezo_ledger::tx::TxWitness;
use eezo_ledger::consensus::{SigBytes, SIG_LEN};
use proptest::prelude::*;

#[derive(Default)]
struct NoopCache;

impl VerifyCache for NoopCache {
    fn verify_witness(&mut self, _payload_hash: &[u8], _witness: &TxWitness) -> bool {
        true // No-op: always return true for test purposes
    }
}

fn sigs_from_bytes(raw: &[u8]) -> Vec<SigBytes> {
    if raw.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    // make at least 2 signatures to ensure we exceed MAX_WITNESS_BYTES (4096)
    // even if proptest gives a small-ish raw (but your range is already 5k..6k)
    let mut i = 0;
    while i < raw.len() {
        let mut arr = [0u8; SIG_LEN];
        let end = (i + SIG_LEN).min(raw.len());
        let chunk = &raw[i..end];
        arr[..chunk.len()].copy_from_slice(chunk);
        out.push(SigBytes(arr));
        i += SIG_LEN;
    }
    // ensure >=2 signatures so serialized size > 4096
    if out.len() < 2 {
        out.push(SigBytes([0u8; SIG_LEN]));
    }
    out
}

proptest! {
    #[test]
    fn oversized_witness_is_rejected(raw in prop::collection::vec(any::<u8>(), 5000..6000)) {
        let sigs = sigs_from_bytes(&raw);
        let w = TxWitness { payload_hash: [0u8;32], sigs };

        let mut cache = NoopCache::default();
        let res = validate_witness(&[0u8;32], &w, &mut cache);
        prop_assert!(matches!(res, Err(MempoolError::WitnessTooLarge(_))));
    }
}