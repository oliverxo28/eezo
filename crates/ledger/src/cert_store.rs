//! T4: Validator Cert lookup with epoch-based cache facade.

#[cfg(feature = "pq44-runtime")]
use pqcrypto_mldsa::mldsa44::PublicKey;
#[cfg(feature = "pq44-runtime")]
use pqcrypto_traits::sign::PublicKey as PkTrait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The validated public key plus policy flags at a given height.
#[derive(Clone, Debug)]
pub struct ValidatedPk {
    pub pk: PublicKey,
    pub valid_until: u64,
    pub revoked: bool,
}

#[cfg(feature = "pq44-runtime")]
impl ValidatedPk {
    pub fn from_pq(pk: &PublicKey) -> Self {
        let bs = pk.as_bytes(); // Works directly with PkTrait in scope
        let mut a = [0u8; 1312]; // Matches PK_LEN from consensus.rs
        a.copy_from_slice(bs);
        ValidatedPk {
            pk: <PublicKey as PkTrait>::from_bytes(&a).expect("valid public key bytes"), // UFCS
            valid_until: u64::MAX, // Default, assuming policy set elsewhere
            revoked: false,        // Default, assuming policy set elsewhere
        }
    }
}

pub trait CertLookup {
    /// Returns the validator pk if valid at `at_height`, else None.
    /// Implementations must enforce not-yet-valid, expired, and revoked.
    fn get_pk(&self, signer: &[u8; 20], at_height: u64) -> Option<ValidatedPk>;
}

#[derive(Clone)]
pub struct CertStore {
    inner: Arc<RwLock<HashMap<[u8; 20], ValidatedPk>>>,
}

impl CertStore {
    pub fn new(map: HashMap<[u8; 20], ValidatedPk>) -> Self {
        Self { inner: Arc::new(RwLock::new(map)) }
    }
}

impl CertLookup for CertStore {
    fn get_pk(&self, signer: &[u8; 20], at_height: u64) -> Option<ValidatedPk> {
        let map = self.inner.read().ok()?;
        map.get(signer).and_then(|pk| {
            if pk.revoked || pk.valid_until < at_height {
                None
            } else {
                Some(pk.clone())
            }
        })
    }
}

// Optional guidance (not doc-comments to avoid EOF issues):
// epoch cache key: (validator_id, epoch) where epoch = height / EPOCH_LEN.