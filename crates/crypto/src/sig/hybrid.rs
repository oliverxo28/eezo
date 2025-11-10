//! Hybrid signature support (optional). We do **not** enable this in EEZO by default.
//! This file is compiled **only** when the `hybrid-sig` feature is set.
#![cfg(feature = "hybrid-sig")]
#![allow(dead_code)]

use super::{SignatureScheme, AlgoId, PkBytes, SkBytes, SigBytes};

/// Placeholder hybrid scheme (PQC + classical). Not used in production.
pub struct HybridSig;

impl SignatureScheme for HybridSig {
    // We don’t have a Hybrid variant in AlgoId; use a benign placeholder to compile.
    // This module is gated behind `hybrid-sig`, so it won’t affect production code.
    const ALGO_ID: AlgoId = AlgoId::SlhDsa128f;

    // Placeholder sizes for a hypothetical hybrid key (do not use in prod).
    const PK_LEN: usize = 1312;
    const SK_LEN: usize = 2528;
    const SIG_MAX_LEN: usize = 2420 + 96;

    type PublicKey = PkBytes;
    type SecretKey = SkBytes;
    type Signature = SigBytes;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        (PkBytes(vec![0u8; Self::PK_LEN]), SkBytes(vec![0u8; Self::SK_LEN]))
    }

    fn sign(_sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        // Stub: embed a prefix of the message and pad to fixed size.
        let mut out = Vec::with_capacity(Self::SIG_MAX_LEN);
        out.extend_from_slice(&msg[..msg.len().min(32)]);
        out.resize(Self::SIG_MAX_LEN, 0);
        SigBytes(out)
    }

    fn verify(_pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        // Stub: shape check only.
        sig.0.len() == Self::SIG_MAX_LEN && !msg.is_empty()
    }

    #[inline]
    fn pk_as_bytes(pk: &Self::PublicKey) -> &[u8] { &pk.0 }
    #[inline]
    fn sk_as_bytes(sk: &Self::SecretKey) -> &[u8] { &sk.0 }
}