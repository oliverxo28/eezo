//! # Element Zero — Post-Quantum Cryptography Core
//!
//! This crate provides all low-level PQC primitives used across the EEZO
//! network stack, including:
//!
//! * **Signatures** — ML-DSA-44 (default) and optional SLH-DSA-SHA2-128s
//! * **Key Encapsulation** — ML-KEM-768 (default KEM for handshake)
//! * **Hashing** — SHA3-256, SHA3-512, and domain-separated variants
//! * **Constant-time utilities** for safe comparison and zeroization
//!
//! ## Algorithm Registry
//!
//! | Family | Variant | Algo ID | Notes |
//! |---------|----------|----------|--------|
//! | ML-DSA | 44 | `0x0144` | Default PQ signature (fast, NIST PQC) |
//! | SLH-DSA | 128s | `0x0244` | Optional fallback via `slh-dsa` feature |
//! | ML-KEM | 768 | `0x0344` | Default KEM for 1-RTT handshake |
//!
//! All public key, signature, and ciphertext formats are canonical and binary-stable.
//! Higher-level crates (ledger, wallet, net) depend on this registry for safe decoding.

pub mod ct;
pub mod error;
pub mod hash;
pub mod kem;
pub mod sig;
pub mod suite;

// Commonly used verifier shortcut
// Only re-export when a verifier is actually compiled in.
// This avoids unresolved-import errors if someone builds eezo-crypto with no
// signature scheme (or only KEM) features enabled.
#[cfg(any(feature = "mldsa", feature = "slh-dsa", feature = "skip-sig-verify"))]
pub use crate::sig::verify_sig;

// T34: make suite identifiers easy to import from the crate root.
pub use crate::suite::{CryptoSuite, SuiteError};
