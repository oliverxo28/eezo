//! Check unified verifiers dispatch correctly under pq44-runtime (ML-DSA).

use eezo_crypto::sig::{verify_sig, SignatureScheme};
use eezo_crypto::sig::ml_dsa::MlDsa44;
use eezo_crypto::sig::registry::{verify, verify_anchor_mldsa_44};

#[test]
fn registry_and_unified_verifiers_accept_valid_sig() {
    let (pk, sk) = MlDsa44::keypair();
    let msg = b"dispatch::mldsa44::ok";
    let sig = MlDsa44::sign(&sk, msg);

    // bytes views for the unified paths
    let pkb = MlDsa44::pk_as_bytes(&pk);
    let sigb = &sig.0;

    assert!(verify(pkb, msg, sigb), "registry::verify should accept valid ML-DSA-44");
    assert!(verify_sig(pkb, msg, sigb), "sig::verify_sig should accept valid ML-DSA-44");
}

#[test]
fn verify_anchor_mldsa_44_enforces_strict_lengths() {
    let (pk, sk) = MlDsa44::keypair();
    let msg = b"anchor::mldsa44::ok";
    let sig = MlDsa44::sign(&sk, msg);

    let pk_ok = MlDsa44::pk_as_bytes(&pk).to_vec();
    let sig_ok = sig.0.clone();

    // OK lengths → true
    assert!(verify_anchor_mldsa_44(&pk_ok, msg, &sig_ok));

    // Wrong pk length → false
    let mut pk_bad = pk_ok.clone();
    let _ = pk_bad.pop();
    assert!(!verify_anchor_mldsa_44(&pk_bad, msg, &sig_ok));

    // Wrong sig length → false
    let mut sig_bad = sig_ok.clone();
    let _ = sig_bad.pop();
    assert!(!verify_anchor_mldsa_44(&pk_ok, msg, &sig_bad));
}
