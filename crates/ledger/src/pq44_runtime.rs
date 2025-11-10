// crates/ledger/src/pq44_runtime.rs
use pqcrypto_mldsa::mldsa44 as pq44;
use pqcrypto_traits::sign::PublicKey as PkTrait;
use pqcrypto_traits::sign::SecretKey as SkTrait;

use eezo_crypto::sig::{AlgoId, SignatureScheme, SkBytes};

/// Adapter used as `S = crate::pq44_runtime::Pq44` in consensus verification.
pub struct Pq44;

impl SignatureScheme for Pq44 {
    // Use the concrete pqcrypto types for PK and Signature to match `verify_core` bounds.
    type PublicKey = pq44::PublicKey;
    type SecretKey = SkBytes; // bytes wrapper from eezo-crypto (Zeroize)
    type Signature = pq44::DetachedSignature;

    // Pick the best available AlgoId variant in your crypto crate.
    // If you have `AlgoId::MlDsa44`, prefer that. Otherwise keep MlDsa2 (not used in verification logic).
    const ALGO_ID: AlgoId = AlgoId::MlDsa44;

    // pqcrypto exposes const fns for sizes.
    const PK_LEN: usize = pq44::public_key_bytes();
    const SK_LEN: usize = pq44::secret_key_bytes();
    const SIG_MAX_LEN: usize = pq44::signature_bytes();

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let (pk, sk) = pq44::keypair();
        // Wrap SK in Zeroize-able bytes for keystore compatibility
        (pk, SkBytes(sk.as_bytes().to_vec()))
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        // Convert back to pqcrypto SecretKey to sign
        let sk_obj = pq44::SecretKey::from_bytes(&sk.0).expect("valid pq44 secret key bytes");
        pq44::detached_sign(msg, &sk_obj)
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        // Correct pqcrypto API: (sig, msg, pk) -> Result<(), _>
        pq44::verify_detached_signature(sig, msg, pk).is_ok()
    }

    #[inline]
    fn pk_as_bytes(pk: &Self::PublicKey) -> &[u8] {
        pk.as_bytes()
    }

    #[inline]
    fn sk_as_bytes(sk: &Self::SecretKey) -> &[u8] {
        &sk.0
    }
}
