//! Verified-path header binding tests (no SingleNode / quorum sim needed).
//! Requires real PQC verify and checkpoint-verify code paths.
//!
//! These tests exercise:
//!  - qc_hash participates in the signed header domain (tamper → HashMismatch)
//!  - signatures are chain-bound (wrong chain → BadSig)
//!  - replay protection via VerifyCache (second verify → Replay)

#![cfg(all(feature = "checkpoints", feature = "checkpoints-verify", feature = "pq44-runtime"))]

use eezo_ledger::block::{header_domain_bytes, header_hash, validate_header, HeaderErr};
use eezo_ledger::verify_cache::VerifyCache;
use eezo_ledger::block::BlockHeader;

use pqcrypto_mldsa::mldsa44::{keypair, detached_sign};
use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};

#[inline]
fn header_with_qc(height: u64, qc_hash: [u8; 32]) -> BlockHeader {
    BlockHeader {
        height,
        prev_hash: [0xAA; 32],
        tx_root:   [0xBB; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 0,
        tx_count:  0,
        timestamp_ms: 123_456,
        #[cfg(feature = "checkpoints")]
        qc_hash,
    }
}

/// qc_hash must be part of the signed header domain; tampering invalidates hash/signature.
#[test]
fn verified_qc_hash_is_part_of_signed_header() {
    let chain = [0xC1u8; 20];
    let (pk, sk) = keypair();

    // height=2 to represent a checkpoint interval header (non-zero qc expected in real flow)
    let mut hdr = header_with_qc(2, [0x11; 32]);
    let expected = header_hash(&hdr);

    // sign valid domain bytes for this header/chain
    let sig = detached_sign(&header_domain_bytes(chain, &hdr), &sk);

    // mutate qc_hash → content changes → HashMismatch before signature is even checked
    hdr.qc_hash[0] ^= 0x01;

    let err = validate_header(chain, expected, &hdr, pk.as_bytes(), sig.as_bytes(), None)
        .unwrap_err();
    assert!(matches!(err, HeaderErr::HashMismatch));
}

/// header signatures are chain-bound; verifying on the wrong chain must fail.
#[test]
fn verified_qc_header_chain_bound() {
    let chain_a = [0xA1u8; 20];
    let chain_b = [0xB2u8; 20];

    let (pk, sk) = keypair();
    let hdr = header_with_qc(2, [0x22; 32]);
    let expected = header_hash(&hdr);

    // Sign for chain_a
    let sig = detached_sign(&header_domain_bytes(chain_a, &hdr), &sk);

    // Correct chain → OK
    validate_header(chain_a, expected, &hdr, pk.as_bytes(), sig.as_bytes(), None).unwrap();

    // Wrong chain → BadSig (domain includes chain id)
    let err = validate_header(chain_b, expected, &hdr, pk.as_bytes(), sig.as_bytes(), None)
        .unwrap_err();
    assert!(matches!(err, HeaderErr::BadSig));
}

/// replay protection: the same (header_hash, header) pair must not be accepted twice.
#[test]
fn verified_qc_header_replay_protection() {
    let chain = [0xD3u8; 20];
    let (pk, sk) = keypair();

    let hdr = header_with_qc(2, [0x33; 32]);
    let expected = header_hash(&hdr);
    let sig = detached_sign(&header_domain_bytes(chain, &hdr), &sk);

    let cache = VerifyCache::default();

    // first verify inserts into cache
    validate_header(chain, expected, &hdr, pk.as_bytes(), sig.as_bytes(), Some(&cache)).unwrap();

    // second verify must be rejected as replay
    let err = validate_header(chain, expected, &hdr, pk.as_bytes(), sig.as_bytes(), Some(&cache))
        .unwrap_err();
    assert!(matches!(err, HeaderErr::Replay));
}