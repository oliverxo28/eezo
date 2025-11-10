use eezo_wallet::keystore::{encrypt_secret, Keystore};

#[test]
fn keystore_json_roundtrip() {
    let ks = encrypt_secret("pw", 0x0144, b"abc123");
    let j = serde_json::to_string(&ks).expect("serialize");
    let ks2: Keystore = serde_json::from_str(&j).expect("deserialize");

    assert_eq!(ks2.algo_id(), ks.algo_id());
    assert_eq!(ks2.kdf_salt().len(), ks.kdf_salt().len());
    assert_eq!(ks2.nonce(), ks.nonce());
}