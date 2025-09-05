//! T4: Sign/verify API (stubs now) — wire to your MlDsaLike + sig_adapter cache.

use thiserror::Error;
use sha3::{Digest, Sha3_256};
use pqcrypto_traits::sign::{DetachedSignature as SigTrait, PublicKey as PkTrait};
use bitvec::prelude::BitVec;
use eezo_crypto::sig::SignatureScheme;

#[cfg(feature = "pq44-runtime")]
use pqcrypto_mldsa::mldsa44;

use crate::cert_store::CertLookup;
use crate::consensus::{SignedConsensusMsg, PkBytes, SigBytes, signer_id_from_pk, kind_of, height_round_of, bound_domain, static_prefix};

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("unknown validator")] UnknownValidator,
    #[error("expired or not-yet-valid cert")] BadCertWindow,
    #[error("revoked validator cert")] Revoked,
    #[error("invalid signature")] InvalidSignature,
    #[error("envelope mismatch")] EnvelopeMismatch,
}

// Batch wrapper for pq44-runtime
#[cfg(feature = "pq44-runtime")]
pub fn verify_batch(
    msgs: &[SignedConsensusMsg],
    chain_id: [u8; 20],
    certs: &(impl CertLookup + Sync + ?Sized),
) -> BitVec {
    verify_many::<crate::pq44_runtime::Pq44>(msgs, chain_id, certs)
}

// Serial fallback when pq44-runtime is off
#[cfg(not(feature = "pq44-runtime"))]
pub fn verify_batch(
    msgs: &[SignedConsensusMsg],
    chain_id: [u8; 20],
    certs: &(impl CertLookup + Sync + ?Sized),
) -> BitVec {
    BitVec::from_iter(
        msgs.iter()
            .map(|m| verify_core::<eezo_crypto::sig::ml_dsa::MlDsa2>(m, &chain_id, certs).is_ok()),
    )
}

// ================= PQ-enabled versions =================
#[cfg(feature = "pq44-runtime")]
pub fn verify_core<S>(
    msg: &SignedConsensusMsg,
    chain_id: &[u8],
    certs: &(impl CertLookup + Sync + ?Sized),
) -> Result<(), VerifyError>
where
    S: SignatureScheme<
        PublicKey = mldsa44::PublicKey,
        Signature = mldsa44::DetachedSignature,
    >,
{
    let kind = kind_of(&msg.core);
    let (h, r) = height_round_of(&msg.core);
    if h != msg.height || r != msg.round {
        return Err(VerifyError::EnvelopeMismatch);
    }

    let vpk = match certs.get_pk(&msg.signer_id, msg.height) {
        Some(v) => v,
        None => return Err(VerifyError::UnknownValidator),
    };
    if vpk.revoked {
        return Err(VerifyError::Revoked);
    }
    if vpk.valid_until < msg.height {
        return Err(VerifyError::BadCertWindow);
    }

    let dom = bound_domain(&static_prefix(kind, chain_id), msg.height, msg.round);
    let core_bytes = bincode::serialize(&msg.core).expect("tmp encode");

    let mut hasher = Sha3_256::new();
    hasher.update(&dom);
    hasher.update(&core_bytes);
    let bound = hasher.finalize();

    let sig_obj = <S::Signature as pqcrypto_traits::sign::DetachedSignature>::from_bytes(&msg.sig.0)
        .map_err(|_| VerifyError::InvalidSignature)?;

    if S::verify(&vpk.pk, &bound, &sig_obj) {
        Ok(())
    } else {
        Err(VerifyError::InvalidSignature)
    }
}

#[cfg(feature = "pq44-runtime")]
pub fn verify_many<S>(
    msgs: &[SignedConsensusMsg],
    chain_id: [u8; 20],
    certs: &(impl CertLookup + Sync + ?Sized),
) -> BitVec
where
    S: SignatureScheme<
        PublicKey = mldsa44::PublicKey,
        Signature = mldsa44::DetachedSignature,
    >,
{
    #[cfg(feature = "rayon")]
    {
        use rayon::prelude::*;
        let v: Vec<bool> = msgs.par_iter()
            .map(|m| verify_core::<S>(m, &chain_id, certs).is_ok())
            .collect();
        BitVec::from_iter(v)
    }
    #[cfg(not(feature = "rayon"))]
    {
        let v: Vec<bool> = msgs.iter()
            .map(|m| verify_core::<S>(m, &chain_id, certs).is_ok())
            .collect();
        BitVec::from_iter(v)
    }
}

// ================= Non-PQ stubs (baseline build) =================
#[cfg(not(feature = "pq44-runtime"))]
pub fn verify_core<S>(
    _msg: &SignedConsensusMsg,
    _chain_id: &[u8],
    _certs: &(impl CertLookup + Sync + ?Sized),
) -> Result<(), VerifyError>
where
    S: SignatureScheme,
{
    Err(VerifyError::InvalidSignature)
}

#[cfg(not(feature = "pq44-runtime"))]
pub fn verify_many<S>(
    msgs: &[SignedConsensusMsg],
    _chain_id: [u8; 20],
    _certs: &(impl CertLookup + Sync + ?Sized),
) -> BitVec
where
    S: SignatureScheme,
{
    BitVec::from_iter(std::iter::repeat(false).take(msgs.len()))
}

pub fn sign_core<S: SignatureScheme>(
    core: &crate::consensus::ConsensusMsgCore,
    chain_id: &[u8],
    sk: &S::SecretKey,
    pk: &S::PublicKey,
) -> (crate::consensus::PkBytes, crate::consensus::SigBytes, crate::consensus::SignerId)
where
    S::Signature: SigTrait,
    S::PublicKey: PkTrait,
{
    let kind = kind_of(core);
    let (height, round) = height_round_of(core);

    let dom = bound_domain(&static_prefix(kind, chain_id), height, round);
    let core_bytes = bincode::serialize(core).expect("tmp encode");
    
    let mut hasher = Sha3_256::new();
    hasher.update(&dom);
    hasher.update(&core_bytes);
    let bound = hasher.finalize();

    let sig_det = S::sign(sk, &bound);

    let mut sig = SigBytes([0u8; crate::consensus::SIG_LEN]);
    sig.0.copy_from_slice(sig_det.as_bytes());

    let pk_bytes_vec = pk.as_bytes();
    let mut pkb = PkBytes([0u8; crate::consensus::PK_LEN]);
    pkb.0.copy_from_slice(&pk_bytes_vec);

    let signer_id = signer_id_from_pk(&pkb);
    (pkb, sig, signer_id)
}