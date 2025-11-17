//! T4: Validator Cert lookup with epoch-based cache facade.

use pqcrypto_mldsa::mldsa44::PublicKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// New: used only by the trait signature (ties to T27's ValidatorId = [u8;20])
use crate::consensus_msg::ValidatorId;

/// The validated public key plus policy flags at a given height.
#[derive(Clone, Debug)]
pub struct ValidatedPk {
    pub pk: PublicKey,
    pub valid_until: u64,
    pub revoked: bool,
}

impl ValidatedPk {
    pub fn from_pq(pk: &PublicKey) -> Self {
        // PublicKey is cheap to clone; keep the canonical type
        ValidatedPk {
            pk: pk.clone(),
            valid_until: u64::MAX,
            revoked: false,
        }
    }
}

// T4 trait for height-aware lookup, now address-based
pub trait CertLookupT4 {
    /// address-based lookup (legacy/compat path)
    fn get_pk(&self, signer: &[u8; 20], at_height: u64) -> Option<ValidatedPk>;
}

#[derive(Clone)]
pub struct CertStore {
    inner: std::collections::HashMap<[u8; 20], ValidatedPk>,
}

impl CertStore {
    pub fn new(map: HashMap<[u8; 20], ValidatedPk>) -> Self {
        Self { inner: map }
    }
}

// Remove or disable the CertLookup impl for CertStore
// impl CertLookup for CertStore {
//     fn public_key(&self, signer: ValidatorId) -> Option<PublicKey> {
//         self.inner.get(&signer.0).map(|v| v.pk.clone())
//     }
// }

impl CertLookupT4 for CertStore {
    fn get_pk(&self, signer: &[u8; 20], _at_height: u64) -> Option<ValidatedPk> {
        self.inner.get(signer).cloned()
    }
}

// --- T27: Consensus cert lookup trait and adapters ---

/// Minimal interface the consensus pipeline needs to verify signatures.
///
/// Note: We keep this focused on *key fetch* so that consensus can choose
/// batch- or single-verify as needed.
pub trait CertLookup: Send + Sync {
    /// Return the current (non-revoked, height-valid) ML-DSA public key for `signer`,
    /// or None if unavailable.
    fn public_key(&self, signer: ValidatorId) -> Option<PublicKey>;
}

/// Simple in-memory map { ValidatorId ([u8;20]) -> PublicKey }.
/// Useful for tests or single-node dev.
#[derive(Default, Clone)]
pub struct StaticCertStore {
    inner: Arc<RwLock<HashMap<ValidatorId, PublicKey>>>,
}

impl StaticCertStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_map(m: HashMap<ValidatorId, PublicKey>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(m)),
        }
    }

    pub fn insert(&self, who: ValidatorId, pk: PublicKey) {
        if let Ok(mut g) = self.inner.write() {
            g.insert(who, pk);
        }
    }
}

impl CertLookup for StaticCertStore {
    fn public_key(&self, signer: ValidatorId) -> Option<PublicKey> {
        self.inner.read().ok()?.get(&signer).cloned()
    }
}

// Default/noop impl for StaticCertStore for the address-based T4 trait
impl CertLookupT4 for StaticCertStore {
    fn get_pk(&self, _signer: &[u8; 20], _at_height: u64) -> Option<ValidatedPk> {
        None
    }
}
