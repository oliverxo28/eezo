use eezo_wallet::keystore::{encrypt_secret, decrypt_secret};
use eezo_crypto::sig::ml_dsa::{MlDsa44, pk_from_bytes, sk_from_bytes};
use eezo_crypto::sig::SignatureScheme;

#[test]
fn wallet_keystore_sign_verify_mldsa44() {
    // 1) Keygen via eezo-crypto
    let (pk, sk) = MlDsa44::keypair();
    let pkb = MlDsa44::pk_as_bytes(&pk).to_vec();
    let skb = MlDsa44::sk_as_bytes(&sk).to_vec();

    // 2) Store secret key in keystore (encrypted)
    let ks = encrypt_secret("pw", 0x0144, &skb); // 0x0144 = ML-DSA-44 in your scheme set

    // 3) Restore secret key bytes
    let plain = decrypt_secret("pw", &ks).expect("decrypt ok");
    assert_eq!(&plain.0[..], &skb[..], "restored secret matches");

    // 4) Reconstruct key types
    let sk2 = sk_from_bytes(&plain.0).expect("sk_from_bytes");
    let pk2 = pk_from_bytes(&pkb).expect("pk_from_bytes");

    // 5) Sign + verify
    let msg = b"wallet::keystore::ml_dsa44";
    let sig = MlDsa44::sign(&sk2, msg);
    assert!(MlDsa44::verify(&pk2, msg, &sig), "sign/verify should succeed");

    // Negative: wrong message must fail
    assert!(!MlDsa44::verify(&pk2, b"wallet::keystore::m1_dsa44", &sig));
}
