use eezo_crypto::sig::ml_dsa::MlDsa44;
use eezo_crypto::sig::SignatureScheme;
use std::fmt::Write;

fn to_hex(bytes: &[u8]) -> String {
    // simple hex encoder, no external crate
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{:02x}", b).expect("write! to String cannot fail");
    }
    s
}

fn main() {
    // Generate ML-DSA-44 keypair using your existing crypto crate
    let (pk, sk) = MlDsa44::keypair();

    // pk.0 and sk.0 are the raw bytes (1312 and 2528 bytes respectively)
    let pk_hex = to_hex(&pk.0);
    let sk_hex = to_hex(&sk.0);

    // Print as shell exports so you can eval them
    println!("export EEZO_TX_PK_HEX=0x{}", pk_hex);
    println!("export EEZO_TX_SK_HEX=0x{}", sk_hex);
}
