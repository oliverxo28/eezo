//! Thin, feature-gated facade over pqcrypto_mldsa for consensus QC signatures.
//! T34.0: make verification suite-aware (default remains ML-DSA-44 until rotation lands).
// --- Imports ---
use crate::cert_store::CertLookupT4;
use crate::consensus::SignedConsensusMsg as LegacyMsg;
use bitvec::prelude::*;
use pqcrypto_mldsa::mldsa44 as pq44;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _}; // brings in from_bytes(), as_bytes()

use sha3::{Digest, Sha3_256};
use crate::qc_sidecar::{QcSidecarV2, ReanchorReason};
use thiserror::Error;

// Metrics (unchanged)
#[cfg(feature = "metrics")]
#[cfg(feature = "pq44-runtime")]
use crate::metrics::{
    VERIFY_BATCH_DURATION, VERIFY_BATCH_FAIL, VERIFY_BATCH_OK, VERIFY_BATCH_TOTAL,
};

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("unknown validator")]
    UnknownValidator,
    #[error("expired or not-yet-valid cert")]
    BadCertWindow,
    #[error("revoked validator cert")]
    Revoked,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("envelope mismatch")]
    EnvelopeMismatch,
    #[error("missing public key")]
    MissingPublicKey,
    #[error("bad signature format")]
    BadSignatureFormat,
    #[error("bad signature")]
    BadSignature,
}

/// Minimal suite id for rotation framework (local shim for T34.0).
/// In T34.1+, replace with `crate::crypto::suite::CryptoSuite`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CryptoSuite {
    MlDsa44   = 1,
    SphincsPlus = 2,
}

impl core::convert::TryFrom<u8> for CryptoSuite {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            1 => Ok(CryptoSuite::MlDsa44),
            2 => Ok(CryptoSuite::SphincsPlus),
            _ => Err(()),
        }
    }
}

// Helper: compute the legacy preimage exactly as used for signing
fn legacy_msg_digest(msg: &LegacyMsg, chain_id: [u8; 20]) -> Vec<u8> {
    // This should match SignedConsensusMsg::to_domain_bound_bytes
    let kind = crate::consensus::kind_of(&msg.core);
    let (height, round) = crate::consensus::height_round_of(&msg.core);
    let static_prefix = crate::consensus::static_prefix(kind, &chain_id);
    let domain = crate::consensus::bound_domain(&static_prefix, height, round);
    let core_bytes = bincode::serialize(&msg.core).expect("tmp encode");

    let mut hasher = Sha3_256::new();
    hasher.update(&domain);
    hasher.update(&core_bytes);
    hasher.finalize().to_vec()
}

// Batch wrapper for pq44-runtime (legacy)
// NOTE: Only accepts a batch of 2 as per your update
#[cfg(feature = "pq44-runtime")]
pub fn verify_batch(msgs: &[LegacyMsg; 2], chain_id: [u8; 20], certs: &dyn CertLookupT4) -> BitVec {
    #[cfg(feature = "metrics")]
    {
        VERIFY_BATCH_TOTAL.inc();
        let timer = std::time::Instant::now();
        let result_bits = verify_many(&msgs[..], chain_id, certs);
        VERIFY_BATCH_DURATION.observe(timer.elapsed().as_secs_f64());
        if result_bits.all() {
            VERIFY_BATCH_OK.inc();
        } else {
            VERIFY_BATCH_FAIL.inc();
        }
        result_bits
    }
    #[cfg(not(feature = "metrics"))]
    {
        verify_many(&msgs[..], chain_id, certs)
    }
}

// Serial fallback when pq44-runtime is off (legacy)
#[cfg(not(feature = "pq44-runtime"))]
pub fn verify_batch(msgs: &[LegacyMsg; 2], chain_id: [u8; 20], certs: &dyn CertLookupT4) -> BitVec {
    BitVec::from_iter(
        msgs.iter()
            .map(|m| verify_core(m, &chain_id, certs).is_ok()),
    )
}

// --- Non-generic, concrete pqcrypto types ---
#[cfg(feature = "pq44-runtime")]
pub fn verify_core(
    msg: &LegacyMsg,
    chain_id: &[u8; 20],
    certs: &dyn CertLookupT4,
) -> Result<(), VerifyError> {
    // default to ML-DSA-44 to preserve current behavior
    verify_core_with_suite(msg, chain_id, certs, CryptoSuite::MlDsa44)
}

/// Suite-aware core verifier (T34.0). ML-DSA-44 implemented; SPHINCS+ stubbed.
#[cfg(feature = "pq44-runtime")]
pub fn verify_core_with_suite(
    msg: &LegacyMsg,
    chain_id: &[u8; 20],
    certs: &dyn CertLookupT4,
    suite: CryptoSuite,
) -> Result<(), VerifyError> {
    // 1) Compute the legacy digest (preimage) exactly as used during signing
    let digest: Vec<u8> = legacy_msg_digest(msg, *chain_id);

    match suite {
        CryptoSuite::MlDsa44 => {
            // 2) Fetch pk by address, not ValidatorId (legacy messages carry 20-byte signer id)
            let pk: pq44::PublicKey = match certs.get_pk(&msg.signer_id, u64::MAX).map(|v| v.pk) {
                Some(pk) => pk,
                None => return Err(VerifyError::MissingPublicKey),
            };

            // 3) Parse signature from msg into pqcrypto DetachedSignature
            let sig_obj = pq44::DetachedSignature::from_bytes(&msg.sig.0)
                .map_err(|_| VerifyError::BadSignatureFormat)?;

            // 4) Verify using correct pq44 function (order: &DetachedSignature, msg: &[u8], &PublicKey)
            if pq44::verify_detached_signature(&sig_obj, &digest, &pk).is_ok() {
                Ok(())
            } else {
                Err(VerifyError::BadSignature)
            }
        }
        CryptoSuite::SphincsPlus => {
            // T34.2 will introduce real SPHINCS+ checking (and pk lookup).
            // For T34.0 framework, keep this as a stub to avoid accidental acceptance.
            Err(VerifyError::InvalidSignature)
        }
    }
}

// --- Non-generic, returns BitVec ---
#[cfg(feature = "pq44-runtime")]
pub fn verify_many(msgs: &[LegacyMsg], chain_id: [u8; 20], certs: &dyn CertLookupT4) -> BitVec {
    msgs.iter()
        .map(|m| verify_core(m, &chain_id, certs).is_ok())
        .collect::<BitVec>()
}

/// Suite-aware batch (T34.0). Default `verify_many` keeps ML-DSA behavior.
#[cfg(feature = "pq44-runtime")]
pub fn verify_many_with_suite(
    msgs: &[LegacyMsg],
    chain_id: [u8; 20],
    certs: &dyn CertLookupT4,
    suite: CryptoSuite,
) -> BitVec {
    msgs.iter()
        .map(|m| verify_core_with_suite(m, &chain_id, certs, suite).is_ok())
        .collect()
}


// ================= Non-PQ stubs (baseline build) =================
#[cfg(not(feature = "pq44-runtime"))]
pub fn verify_core(
    _msg: &LegacyMsg,
    _chain_id: &[u8],
    _certs: &dyn CertLookupT4,
) -> Result<(), VerifyError> {
    Err(VerifyError::InvalidSignature)
}

#[cfg(not(feature = "pq44-runtime"))]
pub fn verify_core_with_suite(
    _msg: &LegacyMsg,
    _chain_id: &[u8],
    _certs: &dyn CertLookupT4,
    _suite: CryptoSuite,
) -> Result<(), VerifyError> {
    Err(VerifyError::InvalidSignature)
}

#[cfg(not(feature = "pq44-runtime"))]
pub fn verify_many(msgs: &[LegacyMsg], _chain_id: [u8; 20], _certs: &dyn CertLookupT4) -> BitVec {
    std::iter::repeat(false).take(msgs.len()).collect()
}

#[cfg(not(feature = "pq44-runtime"))]
pub fn verify_many_with_suite(
    msgs: &[LegacyMsg],
    _chain_id: [u8; 20],
    _certs: &dyn CertLookupT4,
    _suite: CryptoSuite,
) -> BitVec {
    std::iter::repeat(false).take(msgs.len()).collect()
}

// --- Optional: concrete helper for signing legacy messages in tests ---
#[cfg(feature = "pq44-runtime")]
pub fn sign_legacy_pq44(sk: &pq44::SecretKey, msg_bytes: &[u8]) -> pq44::DetachedSignature {
    pq44::detached_sign(msg_bytes, sk)
}

// --- Legacy sign_core retained for benches/compat (non-generic, but uses trait methods) ---
pub fn sign_core(
    core: &crate::consensus::ConsensusMsgCore,
    chain_id: &[u8],
    sk: &pq44::SecretKey,
    pk: &pq44::PublicKey,
) -> (
    crate::consensus::PkBytes,
    crate::consensus::SigBytes,
    crate::consensus::SignerId,
) {
    use crate::consensus::{
        bound_domain, height_round_of, kind_of, signer_id_from_pk, static_prefix, PkBytes, SigBytes,
    };

    let kind = kind_of(core);
    let (height, round) = height_round_of(core);

    let dom = bound_domain(&static_prefix(kind, chain_id), height, round);
    let core_bytes = bincode::serialize(core).expect("tmp encode");

    let mut hasher = Sha3_256::new();
    hasher.update(&dom);
    hasher.update(&core_bytes);
    let bound = hasher.finalize();

    let sig_det = pq44::detached_sign(&bound, sk);

    let mut sig = SigBytes([0u8; crate::consensus::SIG_LEN]);
    sig.0.copy_from_slice(sig_det.as_bytes());

    let pk_bytes_vec = pk.as_bytes();
    let mut pkb = PkBytes([0u8; crate::consensus::PK_LEN]);
    pkb.0.copy_from_slice(pk_bytes_vec);

    let signer_id = signer_id_from_pk(&pkb);
    (pkb, sig, signer_id)
}

// QC message format helper for checkpoints
pub fn qc_message_bytes(chain_id: [u8; 20], height: u64, block_hash: &[u8; 32]) -> Vec<u8> {
    const QC_DOMAIN: &[u8] = b"EEZO:QC:v1";

    let mut msg = Vec::with_capacity(QC_DOMAIN.len() + 20 + 8 + 32);
    msg.extend_from_slice(QC_DOMAIN);
    msg.extend_from_slice(&chain_id);
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(block_hash);
    msg
}
/// T41.3: deterministic builder for QC sidecar v2 (no crypto verify/enforce).
/// Uses the canonical QC preimage and SHA3-256 to derive stable placeholder fields.
#[inline]
pub fn build_qc_sidecar_v2(
    height: u64,
    block_hash: &[u8; 32],
    suite_id: u8,
    reason: ReanchorReason,
) -> QcSidecarV2 {
    // until enforcement lands, use a fixed chain id to keep format deterministic
    let fake_chain: [u8; 20] = [0u8; 20];
    let preimage = qc_message_bytes(fake_chain, height, block_hash);
    // derive stable, bounded bytes
    let d1 = Sha3_256::digest(&preimage);
    let d2 = Sha3_256::digest(b"EEZO:QC|anchor|v2");
    let mut anchor_sig = Vec::with_capacity(64);
    anchor_sig.extend_from_slice(&d1);
    anchor_sig.extend_from_slice(&d2);
    let anchor_pub = Sha3_256::digest(b"EEZO:QC|anchor-pk|v2").to_vec();
    QcSidecarV2 {
        anchor_suite: suite_id,
        anchor_sig,
        anchor_pub,
        anchor_height: height,
        reason,
    }
}
