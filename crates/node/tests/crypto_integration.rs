#[cfg(feature = "pq44-runtime")]
#[test]
fn node_header_sign_and_verify_roundtrip_mldsa() {
    use eezo_ledger::block::{BlockHeader, header_domain_bytes};
    use pqcrypto_mldsa::mldsa44::{keypair, detached_sign, verify_detached_signature, DetachedSignature};
    use pqcrypto_traits::sign::DetachedSignature as _; // <- trait for as_bytes/from_bytes

    let chain_id = [7u8; 20];

    // Construct a minimal header explicitly (no checkpoints field here)
    let h = BlockHeader {
        height: 1,
        prev_hash: [0u8; 32],
        tx_root: [0u8; 32],
        fee_total: 0,
        tx_count: 0,
        timestamp_ms: 0,
		#[cfg(feature = "checkpoints")]
		qc_hash: [0u8; 32],
    };

    let msg = header_domain_bytes(chain_id, &h);

    let (pk, sk) = keypair();
    let sig = detached_sign(&msg, &sk);
    assert!(verify_detached_signature(&sig, &msg, &pk).is_ok());

    // Negative: flip a bit
    let mut bad = sig.as_bytes().to_vec();
    bad[0] ^= 1;
    let bad = DetachedSignature::from_bytes(&bad).unwrap();
    assert!(verify_detached_signature(&bad, &msg, &pk).is_err());
}
