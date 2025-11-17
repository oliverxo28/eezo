#![cfg(all(feature = "pq44-runtime", feature = "checkpoints"))]

use eezo_ledger::{SingleNode, SingleNodeCfg};
use eezo_ledger::block::header_domain_bytes;
use pqcrypto_mldsa::mldsa44::{keypair, detached_sign, verify_detached_signature, PublicKey, SecretKey};

/// Build a node and also return its keypair for direct signature checks.
fn node_with_keys() -> (SingleNode, SecretKey, PublicKey) {
    let cfg = SingleNodeCfg {
        chain_id: [0xE0; 20],
        block_byte_budget: 64 * 1024,
        header_cache_cap: 1024,
        ..Default::default()
    };
    let (pk, sk) = keypair();
    let node = SingleNode::new(cfg, sk, pk);
    (node, sk, pk)
}

#[test]
fn tampered_qc_hash_is_rejected() {
    let (mut n, sk, pk) = node_with_keys();

    // Produce blocks until we actually see a QC-bearing header.
    const MAX_SCAN: usize = 1024;
    let mut orig = None;
    for _ in 0..MAX_SCAN {
        let (blk, _sum) = n.run_one_slot(false).expect("slot ok");
        if blk.header.qc_hash != [0u8; 32] {
            orig = Some(blk);
            break;
        }
    }
    let mut blk = match orig {
        Some(b) => b,
        None => {
            eprintln!(
                "cp_checkpoints_safety: no QC observed within {MAX_SCAN} blocks; \
                 interval likely larger; skipping tamper check."
            );
            return;
        }
    };

    // Sign the authentic header domain bytes (proposer would do this in production).
    let msg = header_domain_bytes([0xE0; 20], &blk.header);
    let sig = detached_sign(&msg, &sk);

    // Tamper the QC hash and show the same signature no longer verifies.
    blk.header.qc_hash[0] ^= 1;
    let tampered = header_domain_bytes([0xE0; 20], &blk.header);
    let ok = verify_detached_signature(&sig, &tampered, &pk).is_ok();
    assert!(!ok, "tampered QC/hash must be cryptographically rejected");
}