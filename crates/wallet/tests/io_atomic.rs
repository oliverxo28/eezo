use std::path::PathBuf;
use eezo_wallet::{keystore::{encrypt_secret, decrypt_secret}, write_keystore_atomic};

#[test]
fn keystore_atomic_write_and_load() {
    let tmp = tempfile::tempdir().unwrap();
    let path = PathBuf::from(tmp.path()).join("ks").join("keystore.json");

    let ks = encrypt_secret("pw", 0x0144, b"payload");
    write_keystore_atomic(&path, &ks).expect("atomic write ok");

    let bytes = std::fs::read(&path).expect("read back");
    let ks2: eezo_wallet::keystore::Keystore = serde_json::from_slice(&bytes).unwrap();

    let pt = decrypt_secret("pw", &ks2).expect("decrypt");
    assert_eq!(&pt.0[..], b"payload");
}
