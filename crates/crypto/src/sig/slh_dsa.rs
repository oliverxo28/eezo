//! SLH-DSA (SPHINCS+) 128f wrapper over `pqcrypto-sphincsplus`.

use super::{AlgoId, SignatureScheme, PkBytes, SkBytes, SigBytes};
// Deterministic backend selection (feature-agnostic fallbacks):
// 1) Prefer SHAKE if explicitly enabled
// 2) Else use SHA2 if enabled
// 3) Else default to SHAKE (no extra feature flag required)
#[cfg(feature = "slh-dsa")]
mod backend {
    // --- Prefer SHAKE if present ---
    #[cfg(feature = "slh-dsa-backend-shake-128f-simple")]
    pub use pqcrypto_sphincsplus::sphincsshake128fsimple::{
        keypair, detached_sign, verify_detached_signature,
        PublicKey, SecretKey, DetachedSignature,
    };
// --- Else use SHA2 if present ---
    #[cfg(all(
        not(feature = "slh-dsa-backend-shake-128f-simple"),
        feature = "slh-dsa-backend-sha2-128f-simple"
    ))]
    pub use pqcrypto_sphincsplus::sphincssha2128fsimple::{
        keypair, detached_sign, verify_detached_signature,
        PublicKey, SecretKey, DetachedSignature,
    };
// --- Else default to SHAKE when nothing is selected ---
    #[cfg(all(
        not(feature = "slh-dsa-backend-shake-128f-simple"),
        not(feature = "slh-dsa-backend-sha2-128f-simple")
    ))]
    pub use pqcrypto_sphincsplus::sphincsshake128fsimple::{
        keypair, detached_sign, verify_detached_signature,
        PublicKey, SecretKey, DetachedSignature,
    };
    // ADD THE TRAIT IMPORTS RIGHT HERE (after the backend selection):
    pub use pqcrypto_traits::sign::{
        PublicKey as _, SecretKey as _, DetachedSignature as _,
    };
    
// Sizes are the same for the 128f simple variants.
    pub const PK_LEN: usize = 32;
pub const SK_LEN: usize = 64;
    // Generous upper bound for 128f signatures (backend-agnostic).
    pub const SIG_MAX_LEN: usize = 17_088;
}

// Fallback when slh-dsa is not enabled at all
#[cfg(not(feature = "slh-dsa"))]
mod backend {
    pub const PK_LEN: usize = 32;
pub const SK_LEN: usize = 64;
    pub const SIG_MAX_LEN: usize = 17_088;
    pub const VARIANT_NAME: &str = "none";
// Dummy types for compilation
    #[derive(Debug)]
    pub struct PublicKey(Vec<u8>);
#[derive(Debug)] 
    pub struct SecretKey(Vec<u8>);
    #[derive(Debug)]
    pub struct DetachedSignature(Vec<u8>);
impl PublicKey {
        pub fn as_bytes(&self) -> &[u8] { &self.0 }
        pub fn from_bytes(_: &[u8]) -> Result<Self, &'static str> { Err("no backend") }
    }
    
    impl SecretKey {
        pub fn as_bytes(&self) -> &[u8] { &self.0 }
        pub fn from_bytes(_: &[u8]) -> Result<Self, &'static str> { Err("no backend") }
    }
    
    impl DetachedSignature {
  
      pub fn as_bytes(&self) -> &[u8] { &self.0 }
        pub fn from_bytes(_: &[u8]) -> Result<Self, &'static str> { Err("no backend") }
    }
    
    pub fn keypair() -> (PublicKey, SecretKey) {
        (PublicKey(vec![0; PK_LEN]), SecretKey(vec![0; SK_LEN]))
    }
    
    pub fn detached_sign(_: &[u8], _: &SecretKey) -> DetachedSignature {
        DetachedSignature(vec![0; SIG_MAX_LEN])
    }
    
  
  pub fn verify_detached_signature(_: &DetachedSignature, _: &[u8], _: &PublicKey) -> Result<(), &'static str> {
        Err("no backend")
    }
}

// Ensure symbols are available under any cfg combo:
use backend::{PublicKey, SecretKey, DetachedSignature, keypair, detached_sign, verify_detached_signature, PK_LEN, SK_LEN, SIG_MAX_LEN};

// Bring trait methods (as_bytes, from_bytes) into **this** module’s scope
// so calls like pk.as_bytes() / PublicKey::from_bytes(...) resolve here.
#[cfg(feature = "slh-dsa")]
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};

/// SLH-DSA-128f implementation
pub struct SlhDsa128f;

impl SignatureScheme for SlhDsa128f {
    const ALGO_ID: AlgoId = AlgoId::SlhDsa128f;
const PK_LEN: usize = PK_LEN;
    const SK_LEN: usize = SK_LEN;
    const SIG_MAX_LEN: usize = SIG_MAX_LEN;

    type PublicKey = PkBytes;
type SecretKey = SkBytes; 
    type Signature = SigBytes;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        #[cfg(feature = "slh-dsa")]
        {
            let (pk, sk) = keypair();
(PkBytes(pk.as_bytes().to_vec()), SkBytes(sk.as_bytes().to_vec()))
        }
        #[cfg(not(feature = "slh-dsa"))]
        {
            (PkBytes(vec![0u8; Self::PK_LEN]), SkBytes(vec![0u8; Self::SK_LEN]))
        }
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        #[cfg(feature = "slh-dsa")]
        {
            if let Ok(sk_inner) = SecretKey::from_bytes(&sk.0) 
{
                let sig = detached_sign(msg, &sk_inner);
return SigBytes(sig.as_bytes().to_vec());
            }
            SigBytes(Vec::new())
        }
        #[cfg(not(feature = "slh-dsa"))]
        {
            SigBytes(Vec::new())
        }
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        #[cfg(feature = "slh-dsa")]
        {
     
       if let (Ok(pk_inner), Ok(sig_inner)) = (
                PublicKey::from_bytes(&pk.0),
                DetachedSignature::from_bytes(&sig.0),
            ) {
                return verify_detached_signature(&sig_inner, msg, &pk_inner).is_ok();
}
            false
        }
        #[cfg(not(feature = "slh-dsa"))]
        {
            false
        }
    }

    #[inline]
    fn pk_as_bytes(pk: &Self::PublicKey) -> &[u8] { &pk.0 }
    #[inline]
    fn sk_as_bytes(sk: &Self::SecretKey) -> &[u8] { &sk.0 }
}

/// Raw bytes verification for SLH-DSA
#[cfg(feature = "slh-dsa")]
pub 
fn verify_bytes(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use backend::{PublicKey, DetachedSignature, verify_detached_signature};
if pk.len() != PK_LEN || sig.len() > SIG_MAX_LEN {
        return false;
}

    match (PublicKey::from_bytes(pk), DetachedSignature::from_bytes(sig)) {
        (Ok(pk_inner), Ok(sig_inner)) => verify_detached_signature(&sig_inner, msg, &pk_inner).is_ok(),
        _ => false,
    }
}

#[cfg(not(feature = "slh-dsa"))]
pub fn verify_bytes(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
    false
}