use eezo_wallet::keystore::{encrypt_secret, decrypt_secret};

#[test]
fn keystore_encrypt_decrypt_roundtrip() {
    let password = "correct horse battery staple";
    let secret = b"super-secret-bytes";
    let ks = encrypt_secret(password, 0x0144, secret); // algo_id placeholder for ML-DSA-44
    let pt = decrypt_secret(password, &ks).expect("decrypt ok");
    assert_eq!(&pt.0, secret);
}
