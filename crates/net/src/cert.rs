use pqcrypto_mldsa::mldsa44 as dsa;
use serde::{Deserialize, Serialize};
use thiserror::Error;
// bring in trait methods for as_bytes()/from_bytes()
use pqcrypto_traits::sign::{DetachedSignature as SigTrait, PublicKey as PkTrait};

#[derive(Clone)]
pub struct GenesisRoot {
    pub pk: dsa::PublicKey,
}

#[derive(Debug, Error)]
pub enum CertError {
    #[error("invalid signature")]
    InvalidSig,
    #[error("expired certificate")]
    Expired,
    #[error("not yet valid")]
    NotYetValid,
    #[error("revoked")]
    Revoked,
    #[error("parse error")]
    Parse,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ValidatorCertificate {
    pub validator_id: [u8; 20], // e.g., Address
    pub ml_dsa_pubkey: Vec<u8>, // ML-DSA-44 pk bytes
    pub valid_from: u64,        // block height
    pub valid_until: u64,       // block height
    #[serde(default)]
    pub revoked: bool, // simple revocation flag (T3.1)
    pub genesis_signature: Vec<u8>,
}

#[derive(Serialize)]
struct ValidatorCertificateCore<'a> {
    validator_id: &'a [u8; 20],
    ml_dsa_pubkey: &'a [u8],
    valid_from: u64,
    valid_until: u64,
    revoked: bool,
}

fn core_bytes(cert: &ValidatorCertificate) -> Vec<u8> {
    let core = ValidatorCertificateCore {
        validator_id: &cert.validator_id,
        ml_dsa_pubkey: &cert.ml_dsa_pubkey,
        valid_from: cert.valid_from,
        valid_until: cert.valid_until,
        revoked: cert.revoked,
    };
    bincode::serialize(&core).expect("serialize core")
}

pub fn verify_certificate(
    root: &GenesisRoot,
    at_height: u64,
    cert: &ValidatorCertificate,
) -> Result<dsa::PublicKey, CertError> {
    if cert.revoked {
        return Err(CertError::Revoked);
    }
    if at_height < cert.valid_from {
        return Err(CertError::NotYetValid);
    }
    if at_height > cert.valid_until {
        return Err(CertError::Expired);
    }

    let core = core_bytes(cert);
    let sig = dsa::DetachedSignature::from_bytes(&cert.genesis_signature)
        .map_err(|_| CertError::Parse)?;
    dsa::verify_detached_signature(&sig, &core, &root.pk).map_err(|_| CertError::InvalidSig)?;

    // parse ML-DSA pubkey contained in cert
    dsa::PublicKey::from_bytes(&cert.ml_dsa_pubkey).map_err(|_| CertError::Parse)
}
