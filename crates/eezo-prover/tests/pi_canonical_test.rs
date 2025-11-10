#![cfg(feature = "stark-air")]

use eezo_prover::pi_canonical::CanonicalPi;

#[test]
fn canonical_pi_digest_stable_and_tamper_detects() {
    let pi = CanonicalPi{
        chain_id20: [0x7A;20], // dev: anvil 31337 sample
        suite_id: 2,
        circuit_version: 2,
        ssz_version: 2,
        header_hash: [0x11;32],
        txs_root_v2: [0x22;32],
        state_root_v2: [0x33;32],
        sig_batch_digest: [0x44;32],
        height: 12345,
    };
    let d1 = pi.digest();
    let d2 = CanonicalPi{ height: 12345, ..pi.clone() }.digest();
    assert_eq!(d1, d2, "same fields -> same digest");

    // tamper one byte → digest MUST change
    let mut pi_bad = pi.clone();
    pi_bad.header_hash[0] ^= 0xFF;
    assert_ne!(pi.digest(), pi_bad.digest(), "tamper must change digest");
}
