//! Certificate window & revocation tests (self-contained).
//! These tests validate edge cases for not_before/not_after, revocation, domain separation,
//! and ML-DSA-44 signature integrity.
//! They are ignored unless `--features consensus-tests` is enabled.

#![cfg_attr(not(feature = "consensus-tests"), allow(unused))]

use serde::{Deserialize, Serialize};

#[cfg(feature = "pq44-runtime")]
use pqcrypto_mldsa::mldsa44::{detached_sign, verify_detached_signature, DetachedSignature, PublicKey, SecretKey, keypair};
#[cfg(feature = "pq44-runtime")]
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TestCert {
    serial: u64,
    not_before_ms: u64,
    not_after_ms: u64,
    // For this test format we embed the ML-DSA-44 public key bytes
    pubkey: Vec<u8>,
    sig: Vec<u8>, // detached signature over domain bytes
}

#[inline]
fn cert_domain_bytes(chain_id: [u8; 20], serial: u64, not_before_ms: u64, not_after_ms: u64) -> Vec<u8> {
    // Domain: b"EEZO-CERT\0" || chain_id(20) || serial(u64 LE) || not_before(u64 LE) || not_after(u64 LE)
    let mut out = Vec::with_capacity(8 + 20 + 8 + 8 + 8);
    out.extend_from_slice(b"EEZO-CERT\0");
    out.extend_from_slice(&chain_id);
    out.extend_from_slice(&serial.to_le_bytes());
    out.extend_from_slice(&not_before_ms.to_le_bytes());
    out.extend_from_slice(&not_after_ms.to_le_bytes());
    out
}

#[cfg(feature = "pq44-runtime")]
fn make_cert(chain_id: [u8; 20], serial: u64, not_before_ms: u64, not_after_ms: u64) -> (TestCert, PublicKey, SecretKey) {
    let (pk, sk) = keypair();
    let msg = cert_domain_bytes(chain_id, serial, not_before_ms, not_after_ms);
    let sig = detached_sign(&msg, &sk);
    let cert = TestCert {
        serial,
        not_before_ms,
        not_after_ms,
        pubkey: pk.as_bytes().to_vec(),
        sig: sig.as_bytes().to_vec(),
    };
    (cert, pk, sk)
}

#[cfg(feature = "pq44-runtime")]
fn verify_cert(cert: &TestCert, now_ms: u64, chain_id: [u8; 20], revoked: &std::collections::BTreeSet<u64>) -> Result<(), &'static str> {
    // 1) Window check (inclusive lower bound, exclusive upper bound)
    if now_ms < cert.not_before_ms {
        return Err("not_yet_valid");
    }
    if now_ms >= cert.not_after_ms {
        return Err("expired");
    }
    // 2) Revocation
    if revoked.contains(&cert.serial) {
        return Err("revoked");
    }
    // 3) Signature / domain separation (chain-bound)
    let pk = PublicKey::from_bytes(&cert.pubkey).map_err(|_| "bad_pubkey")?;
    let ds = DetachedSignature::from_bytes(&cert.sig).map_err(|_| "bad_sig_format")?;
    let msg = cert_domain_bytes(chain_id, cert.serial, cert.not_before_ms, cert.not_after_ms);
    verify_detached_signature(&ds, &msg, &pk).map_err(|_| "bad_signature")?;
    Ok(())
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[cfg(feature = "pq44-runtime")]
#[test]
fn cert_not_yet_valid_is_rejected() {
    let chain = [0x11u8; 20];
    let now = 10_000;
    let (cert, _pk, _sk) = make_cert(chain, 42, 11_000, 20_000);
    let revoked = std::collections::BTreeSet::new();
    assert_eq!(verify_cert(&cert, now, chain, &revoked), Err("not_yet_valid"));
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[cfg(feature = "pq44-runtime")]
#[test]
fn cert_starts_exactly_at_not_before_is_accepted() {
    let chain = [0x22u8; 20];
    let nb = 50_000;
    let (cert, _pk, _sk) = make_cert(chain, 7, nb, nb + 5_000);
    let revoked = std::collections::BTreeSet::new();
    assert!(verify_cert(&cert, nb, chain, &revoked).is_ok());
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[cfg(feature = "pq44-runtime")]
#[test]
fn cert_expires_exactly_at_not_after_is_rejected() {
    let chain = [0x33u8; 20];
    let nb = 1_000;
    let na = 2_000;
    let (cert, _pk, _sk) = make_cert(chain, 99, nb, na);
    let revoked = std::collections::BTreeSet::new();
    // Upper bound is exclusive
    assert_eq!(verify_cert(&cert, na, chain, &revoked), Err("expired"));
    // Just before not_after is OK
    assert!(verify_cert(&cert, na - 1, chain, &revoked).is_ok());
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[cfg(feature = "pq44-runtime")]
#[test]
fn cert_revoked_is_rejected() {
    let chain = [0x44u8; 20];
    let (cert, _pk, _sk) = make_cert(chain, 555, 100, 200);
    let mut revoked = std::collections::BTreeSet::new();
    revoked.insert(555u64);
    assert_eq!(verify_cert(&cert, 150, chain, &revoked), Err("revoked"));
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[cfg(feature = "pq44-runtime")]
#[test]
fn cert_bad_signature_is_rejected() {
    let chain = [0x55u8; 20];
    let (mut cert, _pk, _sk) = make_cert(chain, 1, 0, 10_000);
    if let Some(b) = cert.sig.get_mut(0) { *b ^= 0x01; }
    let revoked = std::collections::BTreeSet::new();
    assert_eq!(verify_cert(&cert, 5_000, chain, &revoked), Err("bad_signature"));
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[cfg(feature = "pq44-runtime")]
#[test]
fn cert_wrong_chain_is_rejected() {
    let chain_a = [0xAAu8; 20];
    let chain_b = [0xBBu8; 20];
    let (cert, _pk, _sk) = make_cert(chain_a, 10, 0, 100);
    let revoked = std::collections::BTreeSet::new();
    // Signature checks out only for the chain it was signed for
    assert!(verify_cert(&cert, 50, chain_a, &revoked).is_ok());
    assert_eq!(verify_cert(&cert, 50, chain_b, &revoked), Err("bad_signature"));
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[cfg(feature = "pq44-runtime")]
#[test]
fn cert_serde_roundtrip_preserves_semantics() {
    let chain = [0x66u8; 20];
    let (cert, _pk, _sk) = make_cert(chain, 1234, 1_000, 9_000);
    let revoked = std::collections::BTreeSet::new();
    // bincode roundtrip
    let enc = bincode::serialize(&cert).unwrap();
    let dec: TestCert = bincode::deserialize(&enc).unwrap();
    assert!(verify_cert(&dec, 2_000, chain, &revoked).is_ok());
}