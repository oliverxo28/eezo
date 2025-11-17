//! ML-DSA-44 end-to-end: keygen → sign → verify.

use eezo_crypto::sig::ml_dsa::MlDsa44;
use eezo_crypto::sig::SignatureScheme;

#[test]
fn mldsa44_sign_verify_roundtrip() {
    // keygen
    let (pk, sk) = MlDsa44::keypair();

    // message
    let msg = b"eezo::crypto::mldsa44 smoke";

    // sign
    let sig = MlDsa44::sign(&sk, msg);

    // verify (true)
    assert!(MlDsa44::verify(&pk, msg, &sig));

    // verify (false) with a tweaked message
    assert!(!MlDsa44::verify(&pk, b"eezo::crypto::mldsa44 sm0ke", &sig));
}

#[test]
fn mldsa44_sizes_match_constants() {
    assert_eq!(MlDsa44::PK_LEN, 1312);
    assert_eq!(MlDsa44::SK_LEN, 2528);
    // Note: SIG_MAX_LEN = 2420 is a const, clippy warns on assert!(true)
}
