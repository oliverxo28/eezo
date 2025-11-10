//! EEZO Crypto — SLH-DSA (SPHINCS+) Smoke Tests

#![cfg(feature = "slh-dsa")]

use eezo_crypto::sig::{SigBytes, SignatureScheme};
use eezo_crypto::sig::slh_dsa::SlhDsa128f;

#[test]
fn slhdsa_sign_verify_roundtrip() {
    let (pk, sk) = SlhDsa128f::keypair();
    let msg = b"element zero slh-dsa smoke test";
    let sig = SlhDsa128f::sign(&sk, msg);
    assert!(SlhDsa128f::verify(&pk, msg, &sig));
}

#[test]
fn slhdsa_repeated_signatures_differ() {
    let (pk, sk) = SlhDsa128f::keypair();
    let msg = b"entropy test message";
    let sig1 = SlhDsa128f::sign(&sk, msg);
    let sig2 = SlhDsa128f::sign(&sk, msg);
    assert_ne!(sig1.0, sig2.0, "SPHINCS+ signatures should be randomized");
    assert!(SlhDsa128f::verify(&pk, msg, &sig1));
    assert!(SlhDsa128f::verify(&pk, msg, &sig2));
}

#[test]
fn slhdsa_tampered_signature_fails() {
    let (pk, sk) = SlhDsa128f::keypair();
    let msg = b"tamper test case";
    let sig = SlhDsa128f::sign(&sk, msg);
    
    // Create a tampered signature
    let mut tampered_sig = sig.0.clone();
    if !tampered_sig.is_empty() {
        tampered_sig[0] ^= 0x01;
    }
    let tampered = SigBytes(tampered_sig);
    
    assert!(!SlhDsa128f::verify(&pk, msg, &tampered));
}

#[test]
fn slhdsa_wrong_message_fails() {
    let (pk, sk) = SlhDsa128f::keypair();
    let msg = b"original message";
    let sig = SlhDsa128f::sign(&sk, msg);
    assert!(!SlhDsa128f::verify(&pk, b"different message", &sig));
}