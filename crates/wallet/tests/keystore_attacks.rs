use eezo_wallet::keystore::{encrypt_secret, decrypt_secret, Keystore};
use serde_json::{self, Value};

#[test]
fn decrypt_fails_with_wrong_password() {
    let ks = encrypt_secret("correct horse", 0x0144, b"secret");
    assert!(decrypt_secret("battery staple", &ks).is_err());
}

#[test]
fn decrypt_fails_if_ciphertext_tampered() {
    // Create a valid keystore
    let ks = encrypt_secret("pw", 0x0144, b"secret");

    // Serialize to JSON Value so we can mutate private fields without helper methods
    let mut v: Value = serde_json::to_value(&ks).expect("serialize keystore");
    // Flip a bit in the first byte of ciphertext
    if let Some(arr) = v.get_mut("ciphertext").and_then(|x| x.as_array_mut()) {
        if let Some(first) = arr.get_mut(0) {
            let n = first.as_u64().expect("ciphertext[0] as u64") ^ 0x80;
            *first = Value::from(n);
        }
    }

    // Re-hydrate a Keystore with tampered ciphertext
    let ks_tampered: Keystore = serde_json::from_value(v).expect("deserialize tampered keystore");
    assert!(decrypt_secret("pw", &ks_tampered).is_err(), "tamper should break auth");
}

#[test]
fn decrypt_fails_if_metadata_tampered() {
    let ks = encrypt_secret("pw", 0x0144, b"secret");

    let mut v: Value = serde_json::to_value(&ks).expect("serialize keystore");
    // Flip a bit in the first byte of the nonce (metadata tamper)
    if let Some(arr) = v.get_mut("nonce").and_then(|x| x.as_array_mut()) {
        if let Some(first) = arr.get_mut(0) {
            let n = first.as_u64().expect("nonce[0] as u64") ^ 0x01;
            *first = Value::from(n);
        }
    }

    let ks_tampered: Keystore = serde_json::from_value(v).expect("deserialize tampered keystore");
    assert!(decrypt_secret("pw", &ks_tampered).is_err(), "AAD should bind nonce");
}

#[test]
fn keystore_validate_rejects_bad_params() {
    let ks = encrypt_secret("pw", 0x0144, b"s");

    let mut v: Value = serde_json::to_value(&ks).expect("serialize keystore");
    // Make kdf_salt too short to pass validate()
    v["kdf_salt"] = Value::from(vec![1u64, 2, 3, 4]);

    let ks_bad: Keystore = serde_json::from_value(v).expect("deserialize malformed keystore");
    assert!(ks_bad.validate().is_err(), "validate() should reject short kdf_salt");
}
