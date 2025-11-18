//! ML-DSA-44 adapter with domain separation, LRU verify cache, and rate limiting.

use lru::LruCache;
use once_cell::sync::Lazy;
use pqcrypto_mldsa::mldsa44 as dsa;
use sha3::{Digest, Sha3_256};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;
// needed for as_bytes()/from_bytes() on PublicKey & DetachedSignature
use pqcrypto_traits::sign::{DetachedSignature as SigTrait, PublicKey as PkTrait};
// v-- IMPORT HandshakeError --v
use crate::handshake::HandshakeError;

/// Domain separator for T3/T3.1 auth.
const T3_DOMAIN: &[u8] = b"EEZO-PQC-AUTH-V1";

// <-- DELETED SigAdapterError ENUM -->

/// Build a domain-separated message: "EEZO-PQC-AUTH-V1|ctx|msg"
fn bind_context(ctx: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(T3_DOMAIN.len() + 1 + ctx.len() + 1 + msg.len());
    v.extend_from_slice(T3_DOMAIN);
    v.extend_from_slice(b"|");
    v.extend_from_slice(ctx);
    v.extend_from_slice(b"|");
    v.extend_from_slice(msg);
    v
}

/// Token-bucket rate limiter.
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec,
            last: Instant::now(),
        }
    }
    fn allow(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        let dt = (now - self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

// PATCH: Add type alias for the complex LruCache type
type VerifyCacheInner = LruCache<(Vec<u8>, [u8; 32]), bool>;

/// Global LRU verify cache: key = (pk_bytes, msg_hash) → bool (valid?)
// PATCH: Use the new type alias
static VERIFY_CACHE: Lazy<Mutex<VerifyCacheInner>> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap())));

/// Global rate limiter: ~200 verifications/second burst with 200 capacity.
static VERIFY_RATELIMIT: Lazy<Mutex<TokenBucket>> =
    Lazy::new(|| Mutex::new(TokenBucket::new(200.0, 200.0)));

/// Utility: SHA3-256 of bytes.
fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(bytes);
    h.finalize().into()
}

pub struct MlDsa;

impl MlDsa {
    pub fn keypair() -> (dsa::PublicKey, dsa::SecretKey) {
        dsa::keypair()
    }

    /// Sign (detached) with explicit domain separation.
    pub fn sign(sk: &dsa::SecretKey, msg: &[u8], ctx: &[u8]) -> dsa::DetachedSignature {
        let bound = bind_context(ctx, msg);
        dsa::detached_sign(&bound, sk)
    }

    /// Verify with rate limit + LRU cache.
    pub fn verify(
        pk: &dsa::PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &dsa::DetachedSignature,
    ) -> bool {
        // rate limit first
        if let Ok(mut tb) = VERIFY_RATELIMIT.lock() {
            if !tb.allow(1.0) {
                // Deny under DoS pressure (fail closed)
                return false;
            }
        }

        // build bound message and cache key
        let bound = bind_context(ctx, msg);
        let msg_hash = sha3_256(&bound);
        let pk_bytes = pk.as_bytes().to_vec();

        // check cache
        if let Ok(mut c) = VERIFY_CACHE.lock() {
            if let Some(&cached) = c.get(&(pk_bytes.clone(), msg_hash)) {
                return cached;
            }
            let ok = dsa::verify_detached_signature(sig, &bound, pk).is_ok();
            c.put((pk_bytes, msg_hash), ok);
            ok
        } else {
            // fallback path if mutex poisoned
            dsa::verify_detached_signature(sig, &bound, pk).is_ok()
        }
    }

    pub fn pk_to_bytes(pk: &dsa::PublicKey) -> Vec<u8> {
        pk.as_bytes().to_vec()
    }
    pub fn pk_from_bytes(bs: &[u8]) -> Result<dsa::PublicKey, HandshakeError> { // <-- CHANGED
        dsa::PublicKey::from_bytes(bs).map_err(|_| HandshakeError::InvalidBytes) // <-- CHANGED
    }

    pub fn sig_to_bytes(sig: &dsa::DetachedSignature) -> Vec<u8> {
        sig.as_bytes().to_vec()
    }
    pub fn sig_from_bytes(bs: &[u8]) -> Result<dsa::DetachedSignature, HandshakeError> { // <-- CHANGED
        dsa::DetachedSignature::from_bytes(bs).map_err(|_| HandshakeError::InvalidBytes) // <-- CHANGED
    }
}

// --- Bridge MlDsa to the handshake's MlDsaLike trait ---

pub struct MlDsaLikeImpl;

impl crate::handshake::MlDsaLike for MlDsaLikeImpl {
    type PublicKey = dsa::PublicKey;
    type SecretKey = dsa::SecretKey;
    type Signature = dsa::DetachedSignature;

    fn sign(sk: &Self::SecretKey, msg: &[u8], ctx: &[u8]) -> Self::Signature {
        MlDsa::sign(sk, msg, ctx)
    }
    fn verify(pk: &Self::PublicKey, msg: &[u8], ctx: &[u8], sig: &Self::Signature) -> bool {
        MlDsa::verify(pk, msg, ctx, sig)
    }
    fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8> {
        MlDsa::pk_to_bytes(pk)
    }
    fn pk_from_bytes(bs: &[u8]) -> Result<Self::PublicKey, HandshakeError> { // <-- CHANGED
        MlDsa::pk_from_bytes(bs)
    }
    fn pk_eq(a: &Self::PublicKey, b: &Self::PublicKey) -> bool {
        a.as_bytes() == b.as_bytes()
    }
    fn sig_to_bytes(sig: &Self::Signature) -> Vec<u8> {
        MlDsa::sig_to_bytes(sig)
    }
    fn sig_from_bytes(bs: &[u8]) -> Result<Self::Signature, HandshakeError> { // <-- CHANGED
        MlDsa::sig_from_bytes(bs)
    }
}