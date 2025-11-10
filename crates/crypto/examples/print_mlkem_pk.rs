use eezo_crypto::kem::ml_kem::keygen; // Use the keygen alias from ml_kem.rs
use pqcrypto_traits::kem::PublicKey; // Import the PublicKey trait for as_bytes()

fn main() {
    // generate a temporary server keypair for the probe
    let (pk, _sk) = keygen(); // Call the key generation function
    print!("0x");
    for b in pk.as_bytes() { // Use the as_bytes() method
        print!("{:02x}", b);
    }
    println!();
}
