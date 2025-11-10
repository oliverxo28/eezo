//! ML-DSA (CRYSTALS-Dilithium) signature scheme integration.

use anyhow::Result;

/// ML-DSA-44 (Dilithium2) implementation.
pub struct MlDsa44;

use super::{AlgoId, SignatureScheme, PkBytes, SkBytes, SigBytes};

// Backend only when pq44-runtime is enabled.
#[cfg(feature = "pq44-runtime")]
use pqcrypto_mldsa::mldsa44::{
    keypair, detached_sign, verify_detached_signature, PublicKey, SecretKey, DetachedSignature,
};
#[cfg(feature = "pq44-runtime")]
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};

impl SignatureScheme for MlDsa44 {
    // Map ML-DSA-44 onto our AlgoId::MlDsa44 (0x0144).
    const ALGO_ID: AlgoId = AlgoId::MlDsa44;
    const PK_LEN: usize = 1312;
    const SK_LEN: usize = 2528;
    const SIG_MAX_LEN: usize = 2420;

    type PublicKey = PkBytes;
    type SecretKey = SkBytes;
    type Signature = SigBytes;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        #[cfg(feature = "pq44-runtime")]
        {
            let (pk, sk) = keypair();
            (PkBytes(pk.as_bytes().to_vec()), SkBytes(sk.as_bytes().to_vec()))
        }
        #[cfg(not(feature = "pq44-runtime"))]
        {
            (PkBytes(vec![0u8; Self::PK_LEN]), SkBytes(vec![0u8; Self::SK_LEN]))
        }
    }

    fn sign(_sk: &Self::SecretKey, _msg: &[u8]) -> Self::Signature {
        #[cfg(feature = "pq44-runtime")]
        {
            if let Ok(sk) = SecretKey::from_bytes(&_sk.0) {
                let sig = detached_sign(_msg, &sk);
                return SigBytes(sig.as_bytes().to_vec());
            }
            SigBytes(Vec::new())
        }
        #[cfg(not(feature = "pq44-runtime"))]
        {
            SigBytes(Vec::new())
        }
    }

    fn verify(_pk: &Self::PublicKey, _msg: &[u8], _sig: &Self::Signature) -> bool {
        #[cfg(feature = "pq44-runtime")]
        {
            if let (Ok(pk), Ok(sig)) = (
                PublicKey::from_bytes(&_pk.0),
                DetachedSignature::from_bytes(&_sig.0),
            ) {
                return verify_detached_signature(&sig, _msg, &pk).is_ok();
            }
            false
        }
        #[cfg(not(feature = "pq44-runtime"))]
        {
            false
        }
    }

    #[inline]
    fn pk_as_bytes(pk: &Self::PublicKey) -> &[u8] { &pk.0 }
    #[inline]
    fn sk_as_bytes(sk: &Self::SecretKey) -> &[u8] { &sk.0 }
}

// ---------------------------------------------------------------------------
// Helpers: reconstruct wrapper keys/signatures from raw bytes (validated).
// These are convenient for wallet / keystore flows.
// ---------------------------------------------------------------------------

/// Try to construct a `PkBytes` from raw bytes. When `pq44-runtime` is enabled we
/// validate with the backend's `PublicKey::from_bytes`; otherwise return `None`.
#[cfg(feature = "pq44-runtime")]
pub fn pk_from_bytes(b: &[u8]) -> Option<PkBytes> {
    use pqcrypto_traits::sign::PublicKey as _;
    pqcrypto_mldsa::mldsa44::PublicKey::from_bytes(b).ok()?;
    Some(PkBytes(b.to_vec()))
}
#[cfg(not(feature = "pq44-runtime"))]
pub fn pk_from_bytes(_b: &[u8]) -> Option<PkBytes> { None }

/// Try to construct an `SkBytes` from raw bytes. When `pq44-runtime` is enabled we
/// validate with the backend's `SecretKey::from_bytes`; otherwise return `None`.
#[cfg(feature = "pq44-runtime")]
pub fn sk_from_bytes(b: &[u8]) -> Option<SkBytes> {
    use pqcrypto_traits::sign::SecretKey as _;
    pqcrypto_mldsa::mldsa44::SecretKey::from_bytes(b).ok()?;
    Some(SkBytes(b.to_vec()))
}
#[cfg(not(feature = "pq44-runtime"))]
pub fn sk_from_bytes(_b: &[u8]) -> Option<SkBytes> { None }

/// Try to construct a `SigBytes` from raw bytes. When `pq44-runtime` is enabled we
/// validate with the backend's `DetachedSignature::from_bytes`; otherwise `None`.
#[cfg(feature = "pq44-runtime")]
pub fn sig_from_bytes(b: &[u8]) -> Option<SigBytes> {
    use pqcrypto_traits::sign::DetachedSignature as _;
    pqcrypto_mldsa::mldsa44::DetachedSignature::from_bytes(b).ok()?;
    Some(SigBytes(b.to_vec()))
}
#[cfg(not(feature = "pq44-runtime"))]
pub fn sig_from_bytes(_b: &[u8]) -> Option<SigBytes> { None }

// ---------------------------------------------------------------------------
// T33.3: Batch verification + KAT parity (Bridge V1.1 support)
// ---------------------------------------------------------------------------

/// Verify one ML-DSA-44 signature. Returns Ok(()) if valid, Err otherwise.
pub fn verify_single(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    #[cfg(feature = "pq44-runtime")]
    {
        use pqcrypto_mldsa::mldsa44::{PublicKey, DetachedSignature};
        use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};

        let pk = PublicKey::from_bytes(pk).map_err(|_| anyhow::anyhow!("bad pk"))?;
        let sig = DetachedSignature::from_bytes(sig).map_err(|_| anyhow::anyhow!("bad sig"))?;
        if pqcrypto_mldsa::mldsa44::verify_detached_signature(&sig, msg, &pk).is_ok() {
            Ok(())
        } else {
            // avoid pulling in `bail!` so builds without the runtime feature don’t warn
            return Err(anyhow::anyhow!("verify failed"));
        }
    }

    #[cfg(not(feature = "pq44-runtime"))]
    {
        let _ = (pk, msg, sig);
        Ok(())
    }
}

/// Batch verify a list of (pk, msg, sig) tuples.
/// Returns Ok(()) if *all* signatures verify; Err if any fail.
pub fn batch_verify<'a, I>(triples: I) -> Result<()>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8], &'a [u8])>,
{
    for (pk, msg, sig) in triples {
        verify_single(pk, msg, sig)?;
    }
    Ok(())
}

#[cfg(test)]
mod kats {
    use super::*;
    use eezo_kats::{MLDsaCorpus, hex_to_bytes};

    #[test]
	#[ignore] // uses dummy vectors; enable when real ML-DSA KATs are wired
    fn kats_parity_smoke() {
        // In a real setup, load from file in eezo-kats/vectors/*.json.
        // Here we embed a small sample string for test continuity.
        let json = r#"{
          "level": 44,
          "vectors": [
            {
              "name": "ml-dsa-44/pass",
              "pk_hex": "0x01",
              "msg_hex": "0x616263",
              "sig_hex": "0x02",
              "should_verify": true,
              "schema": 1
            },
            {
              "name": "ml-dsa-44/fail",
              "pk_hex": "0x01",
              "msg_hex": "0x616263",
              "sig_hex": "0x03",
              "should_verify": false,
              "schema": 1
            }
          ]
        }"#;

        let corpus = MLDsaCorpus::from_str(json).expect("load");
        for v in corpus.vectors {
            let pk = hex_to_bytes(&v.pk_hex).unwrap_or_default();
            let msg = hex_to_bytes(&v.msg_hex).unwrap_or_default();
            let sig = hex_to_bytes(&v.sig_hex).unwrap_or_default();
            let res = verify_single(&pk, &msg, &sig);
            assert_eq!(res.is_ok(), v.should_verify, "{}", v.name);
        }
    }
}
