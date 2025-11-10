#![cfg(all(feature = "checkpoints", not(feature = "checkpoints-verify")))]

use eezo_ledger::{SingleNode, SingleNodeCfg};
use pqcrypto_mldsa::mldsa44::keypair;

#[test]
fn qc_hash_attaches_only_on_interval() {
    let (pk, sk) = keypair();
    let chain_id = [7u8; 20];

    // interval = 2 -> expect height 1: zero, height 2: non-zero
    let cfg = SingleNodeCfg {
        chain_id,
        block_byte_budget: 1024,
        header_cache_cap: 32,
        #[cfg(feature = "checkpoints")]
        checkpoint_interval: 2,
    };

    let mut n = SingleNode::new(cfg, sk, pk);

    // slot 1
    let (b1, _s1) = n.run_one_slot(false).expect("slot1");
    assert_eq!(b1.header.height, 1);
    assert_eq!(
        b1.header.qc_hash, [0u8; 32],
        "height 1 should NOT attach QC"
    );

    // slot 2
    let (b2, _s2) = n.run_one_slot(false).expect("slot2");
    assert_eq!(b2.header.height, 2);
    assert_ne!(b2.header.qc_hash, [0u8; 32], "height 2 should attach QC");
}

#[test]
fn qc_hash_zero_when_not_on_interval() {
    let (pk, sk) = keypair();
    let chain_id = [9u8; 20];

    // interval = 3 -> first two heights should be zero
    let cfg = SingleNodeCfg {
        chain_id,
        block_byte_budget: 1024,
        header_cache_cap: 32,
        #[cfg(feature = "checkpoints")]
        checkpoint_interval: 3,
    };

    let mut n = SingleNode::new(cfg, sk, pk);

    let (b1, _s1) = n.run_one_slot(false).expect("slot1");
    assert_eq!(b1.header.height, 1);
    assert_eq!(b1.header.qc_hash, [0u8; 32]);

    let (b2, _s2) = n.run_one_slot(false).expect("slot2");
    assert_eq!(b2.header.height, 2);
    assert_eq!(b2.header.qc_hash, [0u8; 32]);
}

// --- New robustness tests below ---

use eezo_ledger::block::{header_domain_bytes, header_hash, validate_header, HeaderErr};
use pqcrypto_mldsa::mldsa44::detached_sign;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

/// Tampering qc_hash must invalidate the signed header (hash/domain includes qc_hash).
#[test]
fn qc_hash_is_part_of_signed_header() {
    let (pk, sk) = keypair();
    let chain = [0xABu8; 20];

    let cfg = SingleNodeCfg {
        chain_id: chain,
        block_byte_budget: 1024,
        header_cache_cap: 32,
        #[cfg(feature = "checkpoints")]
        checkpoint_interval: 2, // ensure height 2 has qc
    };
    let mut n = SingleNode::new(cfg, sk.clone(), pk.clone());

    // height 1 (no qc), then height 2 (has qc + proposer signature)
    let (_b1, _s1) = n.run_one_slot(false).expect("slot1");
    let (mut b2, _s2) = n.run_one_slot(false).expect("slot2");
    assert_ne!(b2.header.qc_hash, [0u8; 32], "expected QC on interval");

    // expected hash for the original header
    let expected = header_hash(&b2.header);

    // Compute a valid detached signature for the *untampered* header
    let sig2 = detached_sign(&header_domain_bytes(chain, &b2.header), &sk);

    // Tamper qc_hash → header content changes → should fail hash check first
    b2.header.qc_hash[0] ^= 0x01;
    let res = validate_header(chain, expected, &b2.header, pk.as_bytes(), sig2.as_bytes(), None);
    assert!(matches!(res, Err(HeaderErr::HashMismatch)));
}

/// The header signature must be chain-bound; verifying on a different chain_id fails.
#[test]
fn qc_hash_chain_bound() {
    let (pk, sk) = keypair();
    let chain_a = [0x11u8; 20];
    let chain_b = [0x22u8; 20];

    let cfg = SingleNodeCfg {
        chain_id: chain_a,
        block_byte_budget: 1024,
        header_cache_cap: 32,
        #[cfg(feature = "checkpoints")]
        checkpoint_interval: 2,
    };
    let mut n = SingleNode::new(cfg, sk.clone(), pk.clone());

    let (_b1, _s1) = n.run_one_slot(false).expect("slot1");
    let (b2, _s2) = n.run_one_slot(false).expect("slot2");
    let expected = header_hash(&b2.header);

    // Sign header for chain_a (the chain used by the node)
    let sig = detached_sign(&header_domain_bytes(chain_a, &b2.header), &sk);
    // Verify on the SAME chain succeeds
    validate_header(chain_a, expected, &b2.header, pk.as_bytes(), sig.as_bytes(), None).unwrap();

    // Verify on a DIFFERENT chain must fail signature (domain bytes include chain_id)
    let err = validate_header(chain_b, expected, &b2.header, pk.as_bytes(), sig.as_bytes(), None)
        .unwrap_err();
    assert!(matches!(err, HeaderErr::BadSig));
}

/// Replay protection: the same header hash should not be accepted twice when a cache is used.
#[cfg(feature = "pq44-runtime")]
#[test]
fn qc_hash_replay_protection() {
    use eezo_ledger::verify_cache::VerifyCache;

    let (pk, sk) = keypair();
    let chain = [0x33u8; 20];

    let cfg = SingleNodeCfg {
        chain_id: chain,
        block_byte_budget: 1024,
        header_cache_cap: 32,
        #[cfg(feature = "checkpoints")]
        checkpoint_interval: 2,
    };
    let mut n = SingleNode::new(cfg, sk.clone(), pk.clone());

    let (_b1, _s1) = n.run_one_slot(false).expect("slot1");
    let (b2, _s2) = n.run_one_slot(false).expect("slot2");
    let expected = header_hash(&b2.header);

    // Sign header for the node's chain
    let sig = detached_sign(&header_domain_bytes(chain, &b2.header), &sk);

    // First validation inserts into cache
    let cache = VerifyCache::default();
    validate_header(chain, expected, &b2.header, pk.as_bytes(), sig.as_bytes(), Some(&cache))
        .expect("first verify ok");

    // Second validation should hit replay
    let err = validate_header(chain, expected, &b2.header, pk.as_bytes(), sig.as_bytes(), Some(&cache))
        .unwrap_err();
    assert!(matches!(err, HeaderErr::Replay));
}