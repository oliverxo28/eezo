#![cfg(all(feature = "pq44-runtime", not(feature = "testing")))]
// These tests require REAL signature verification.
#[cfg(feature = "skip-sig-verify")]
compile_error!("sign_verify.rs requires real signature verification; build WITHOUT 'skip-sig-verify'.");

use eezo_ledger::SignedTx;
use eezo_ledger::tx_sig::verify_signed_tx;

mod support;
use support::tx_build as tb;

use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence};

#[test]
fn good_signature_verifies() {
    let chain_id = [0xE0; 20];
    let to = tb::addr(0xA1);
    let b = tb::new_many(chain_id, 1).remove(0);

    let stx: SignedTx = b.build(to, 10, 1, 0);
    assert!(verify_signed_tx(chain_id, &stx), "freshly built tx must verify");
}

#[test]
fn tamper_sig_fails() {
    let chain_id = [0xE0; 20];
    let to = tb::addr(0xA2);
    let b = tb::new_many(chain_id, 1).remove(0);

    let mut stx: SignedTx = b.build(to, 10, 1, 0);
    // flip one bit in the signature
    assert!(!stx.sig.is_empty());
    stx.sig[0] ^= 0x01;

    assert!(
        !verify_signed_tx(chain_id, &stx),
        "bit-flipped signature must fail verification"
    );
}

#[test]
fn tamper_core_fails() {
    let chain_id = [0xE0; 20];
    let to = tb::addr(0xA3);
    let b = tb::new_many(chain_id, 1).remove(0);

    let mut stx: SignedTx = b.build(to, 10, 1, 0);
    // change the signed message (amount) after signing
    stx.core.amount += 1;

    assert!(
        !verify_signed_tx(chain_id, &stx),
        "mutating core after signing must invalidate the signature"
    );
}

#[test]
fn chain_id_mismatch_fails() {
    let chain_id = [0xE0; 20];
    let wrong_chain = [0xE1; 20];
    let to = tb::addr(0xA4);
    let b = tb::new_many(chain_id, 1).remove(0);

    let stx: SignedTx = b.build(to, 10, 1, 0);

    assert!(verify_signed_tx(chain_id, &stx), "sanity: verifies on correct chain_id");
    assert!(
        !verify_signed_tx(wrong_chain, &stx),
        "domain separation: verification must fail on different chain_id"
    );
}

#[test]
fn wrong_pubkey_fails() {
    let chain_id = [0xE0; 20];
    let to = tb::addr(0xA5);
    let b = tb::new_many(chain_id, 1).remove(0);

    let mut stx: SignedTx = b.build(to, 10, 1, 0);
    // Corrupt the public key bytes (keep same length) — signature no longer matches this pubkey.
    assert!(!stx.pubkey.is_empty());
    stx.pubkey[0] ^= 0x01;

    assert!(
        !verify_signed_tx(chain_id, &stx),
        "using a modified pubkey must fail verification"
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            ".proptest-regressions-sign_verify"
        ))),
        .. ProptestConfig::default()
    })]
    #[test]
    fn any_single_bit_flip_in_sig_is_rejected(bit in 0usize..512) {
        let chain_id = [0xE0; 20];
        let to = tb::addr(0xB0);
        let b = tb::new_many(chain_id, 1).remove(0);
        let base: SignedTx = b.build(to, 1, 1, 0);

        // If signature is shorter than 512, wrap the position.
        let mut stx = base.clone();
        let len = stx.sig.len();
        prop_assume!(len > 0);
        let i = bit % len;
        stx.sig[i] ^= 0x01;

        prop_assert!(!verify_signed_tx(chain_id, &stx));
    }
}
