use eezo_ledger::consensus::{SigBytes, SIG_LEN};
use eezo_ledger::mempool::{validate_witness, MempoolError, VerifyCache};
use eezo_ledger::tx::TxWitness;
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence};
use std::convert::TryInto;

// bring in signed-tx builders that use real ML-DSA-44
mod support;
use support::tx_build as tb;

#[derive(Default)]
struct NoopCache;

impl VerifyCache for NoopCache {
    fn verify_witness(&mut self, _payload_hash: &[u8], _witness: &TxWitness) -> bool {
        true // No-op: always return true for test purposes
    }
}

fn sigs_from_bytes(raw: &[u8]) -> Vec<SigBytes> {
    let mut out = Vec::new();
    for chunk in raw.chunks_exact(SIG_LEN) {
        // chunks_exact guarantees chunk.len() == SIG_LEN
        let arr: [u8; SIG_LEN] = chunk.try_into().unwrap();
        out.push(SigBytes(arr));
    }
    if out.len() < 2 {
        out.push(SigBytes([0u8; SIG_LEN]));
    }
    out
}

prop_compose! {
    fn arb_signed_tx()
        (
            to_byte in any::<u8>(),
            amount  in 1u128..1_000_000u128,
            fee     in 1u128..10_000u128,
            nonce   in 0u64..8u64,
        ) -> eezo_ledger::SignedTx
    {
        let chain = [0xE0u8; 20];
        let builders = tb::new_many(chain, 1);
        let b = &builders[0];

        let to = tb::addr(to_byte);
        // build() signs with ML-DSA-44 under pq44-runtime
        b.build(to, amount, fee, nonce)
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            ".proptest-regressions-mempool_prop"
        ))),
        .. ProptestConfig::default()
    })]

    #[test]
    fn oversized_witness_is_rejected(raw in prop::collection::vec(any::<u8>(), 5000..6000)) {
        let sigs = sigs_from_bytes(&raw);
        let w = TxWitness { payload_hash: [0u8; 32], sigs };

        let mut cache = NoopCache;
        let res = validate_witness(&[0u8; 32], &w, &mut cache);
        prop_assert!(matches!(res, Err(MempoolError::WitnessTooLarge(_))));
    }

    #[test]
    fn built_signed_tx_is_well_formed(stx in arb_signed_tx()) {
        // Stateless shape must pass
        eezo_ledger::tx_types::validate_tx_shape(&stx.core).unwrap();

        // Sender must be derivable from the pubkey (first 20 bytes)
        let sender = eezo_ledger::tx::sender_from_pubkey_first20(&stx)
            .expect("sender derivation must succeed");
        prop_assert_ne!(sender.0, [0u8; 20]);

        // Size must be positive and reasonably bounded
        let sz = eezo_ledger::block::tx_size_bytes(&stx);
        prop_assert!(sz > 0 && sz < 128 * 1024);
    }
}