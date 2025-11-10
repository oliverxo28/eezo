#![cfg(all(feature = "pq44-runtime", feature = "checkpoints", not(feature = "checkpoints-verify")))]

use eezo_ledger::{SingleNode, SingleNodeCfg};
use eezo_ledger::block::{header_domain_bytes, header_hash, validate_header, HeaderErr};
use eezo_ledger::verify_cache::VerifyCache;
use pqcrypto_mldsa::mldsa44::{detached_sign, keypair};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

// Keep your original compile check (now under the same gate)
#[test]
fn checkpoints_feature_compiles() {
    use eezo_ledger::checkpoints::{verify_quorum_cert, QuorumCert};
    let qc = QuorumCert::new(1, [0u8; 32]);
    verify_quorum_cert(&qc).expect("qc verify (stub/real) ok");
}

#[test]
fn boot_and_first_qc() {
    let (pk, sk) = keypair();
    let chain = [0xC2u8; 20];
    let cfg = SingleNodeCfg {
        chain_id: chain,
        block_byte_budget: 4096,
        header_cache_cap: 64,
        checkpoint_interval: 2,
    };
    let mut n = SingleNode::new(cfg, sk, pk);

    let (b1, _s1) = n.run_one_slot(false).expect("slot1");
    assert_eq!(b1.header.height, 1);
    assert_eq!(b1.header.qc_hash, [0u8; 32], "first block has no QC");

    let (b2, _s2) = n.run_one_slot(false).expect("slot2");
    assert_eq!(b2.header.height, 2);
    assert_ne!(b2.header.qc_hash, [0u8; 32], "QC appears at interval=2");

    // header hash is stable across recompute
    let h1a = header_hash(&b2.header);
    let h1b = header_hash(&b2.header);
    assert_eq!(h1a, h1b);
}

#[test]
fn monotonicity_and_non_reuse() {
    let (pk, sk) = keypair();
    let chain = [0xD2u8; 20];
    let cfg = SingleNodeCfg {
        chain_id: chain,
        block_byte_budget: 4096,
        header_cache_cap: 64,
        checkpoint_interval: 2,
    };
    let mut n = SingleNode::new(cfg, sk, pk);

    let mut qc_heights = Vec::new();
    for h in 1u64..=8 {
        let (b, _s) = n.run_one_slot(false).expect("slot");
        assert_eq!(b.header.height, h);
        if b.header.qc_hash != [0u8; 32] {
            qc_heights.push(h);
        }
    }
    assert_eq!(qc_heights, vec![2, 4, 6, 8], "QCs should appear on multiples of interval");
}

#[test]
fn validate_headers_end_to_end_and_tamper_qc() {
    let (pk, sk) = keypair();
    let chain = [0xE2u8; 20];
    let cfg = SingleNodeCfg {
        chain_id: chain,
        block_byte_budget: 4096,
        header_cache_cap: 64,
        checkpoint_interval: 2,
    };
    let mut n = SingleNode::new(cfg, sk.clone(), pk.clone());

    // Produce a few blocks and validate each header with PQC
    for _ in 0..4 {
        let (b, _s) = n.run_one_slot(false).expect("slot");
        let expected = header_hash(&b.header);
        let sig = detached_sign(&header_domain_bytes(chain, &b.header), &sk);
        validate_header(chain, expected, &b.header, pk.as_bytes(), sig.as_bytes(), None)
            .expect("header should validate");

        // If QC is present, tamper and expect HashMismatch
        if b.header.qc_hash != [0u8; 32] {
            let mut tampered = b.header.clone();
            tampered.qc_hash[0] ^= 1;
            let err = validate_header(chain, expected, &tampered, pk.as_bytes(), sig.as_bytes(), None)
                .unwrap_err();
            assert!(matches!(err, HeaderErr::HashMismatch));
        }
    }
}

#[test]
fn chain_id_isolation() {
    let (pk, sk) = keypair();
    let chain_a = [0xA1u8; 20];
    let chain_b = [0xB1u8; 20];
    let cfg = SingleNodeCfg {
        chain_id: chain_a,
        block_byte_budget: 4096,
        header_cache_cap: 64,
        checkpoint_interval: 2,
    };
    let mut n = SingleNode::new(cfg, sk.clone(), pk.clone());

    // Build a header + valid sig for chain A
    let (b, _s) = n.run_one_slot(false).expect("slot");
    let expected = header_hash(&b.header);
    let sig = detached_sign(&header_domain_bytes(chain_a, &b.header), &sk);
    validate_header(chain_a, expected, &b.header, pk.as_bytes(), sig.as_bytes(), None).unwrap();

    // Verify on a different chain must fail (domain bytes include chain_id)
    let err = validate_header(chain_b, expected, &b.header, pk.as_bytes(), sig.as_bytes(), None)
        .unwrap_err();
    assert!(matches!(err, HeaderErr::BadSig));
}

#[test]
fn budget_independence_of_qc_policy() {
    let (pk, sk) = keypair();
    let chain = [0xC3u8; 20];

    // Large budget
    let cfg_big = SingleNodeCfg {
        chain_id: chain,
        block_byte_budget: 4096,
        header_cache_cap: 64,
        checkpoint_interval: 2,
    };
    let mut n_big = SingleNode::new(cfg_big, sk.clone(), pk.clone());
    let mut qc_big = Vec::new();
    for h in 1u64..=6 {
        let (b, _s) = n_big.run_one_slot(false).expect("slot");
        qc_big.push((h, b.header.qc_hash != [0u8; 32]));
    }

    // Small budget
    let cfg_small = SingleNodeCfg {
        chain_id: chain,
        block_byte_budget: 256, // much smaller
        header_cache_cap: 64,
        checkpoint_interval: 2,
    };
    let mut n_small = SingleNode::new(cfg_small, sk, pk);
    let mut qc_small = Vec::new();
    for h in 1u64..=6 {
        let (b, _s) = n_small.run_one_slot(false).expect("slot");
        qc_small.push((h, b.header.qc_hash != [0u8; 32]));
    }

    // QC attachment policy (heights with QC) should be identical
    assert_eq!(qc_big, qc_small);
}

#[test]
fn replay_guard_with_verify_cache() {
    let (pk, sk) = keypair();
    let chain = [0xD3u8; 20];
    let cfg = SingleNodeCfg {
        chain_id: chain,
        block_byte_budget: 4096,
        header_cache_cap: 64,
        checkpoint_interval: 2,
    };
    let mut n = SingleNode::new(cfg, sk.clone(), pk.clone());

    let (b, _s) = n.run_one_slot(false).expect("slot");
    let expected = header_hash(&b.header);
    let sig = detached_sign(&header_domain_bytes(chain, &b.header), &sk);

    let cache = VerifyCache::default();
    validate_header(chain, expected, &b.header, pk.as_bytes(), sig.as_bytes(), Some(&cache))
        .expect("first validation ok");
    let err = validate_header(chain, expected, &b.header, pk.as_bytes(), sig.as_bytes(), Some(&cache))
        .unwrap_err();
    assert!(matches!(err, HeaderErr::Replay));
}

#[test]
fn header_serde_roundtrip_preserves_qc() {
    use bincode::{deserialize, serialize};

    let (pk, sk) = keypair();
    let chain = [0xE3u8; 20];
    let cfg = SingleNodeCfg {
        chain_id: chain,
        block_byte_budget: 4096,
        header_cache_cap: 64,
        checkpoint_interval: 2,
    };
    let mut n = SingleNode::new(cfg, sk.clone(), pk.clone());

    // Get a header with a QC (height 2)
    let (_b1, _s1) = n.run_one_slot(false).expect("slot1");
    let (b2, _s2) = n.run_one_slot(false).expect("slot2");
    assert_ne!(b2.header.qc_hash, [0u8; 32], "expect QC at height 2");

    let ser = serialize(&b2.header).expect("serialize");
    let round: eezo_ledger::BlockHeader = deserialize(&ser).expect("deserialize");

    assert_eq!(round, b2.header, "header must round-trip exactly");

    // It should still validate after roundtrip
    let expected = header_hash(&round);
    let sig = detached_sign(&header_domain_bytes(chain, &round), &sk);
    validate_header(chain, expected, &round, pk.as_bytes(), sig.as_bytes(), None).unwrap();
}