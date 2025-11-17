//! EEZO crypto smoke tests (PQ44 runtime): ML-DSA-44 roundtrip.

use eezo_crypto::sig::ml_dsa::MlDsa44;
use eezo_crypto::sig::SignatureScheme;

#[test]
fn mldsa44_sign_verify_smoke() {
    // keygen
    let (pk, sk) = MlDsa44::keypair();

    // message
    let msg = b"eezo::crypto::smoke::mldsa44";

    // sign
    let sig = MlDsa44::sign(&sk, msg);

    // verify should pass
    assert!(MlDsa44::verify(&pk, msg, &sig));

    // and fail on a different message
    assert!(!MlDsa44::verify(&pk, b"eezo::crypto::sm0ke::mldsa44", &sig));
}

#[test]
fn mldsa44_size_constants_sane() {
    // Sanity checks for sizes (expected Dilithium2-like sizes)
    assert_eq!(MlDsa44::PK_LEN, 1312);
    assert_eq!(MlDsa44::SK_LEN, 2528);
    // Note: SIG_MAX_LEN = 2420 is a const, clippy warns on assert!(true)
}
