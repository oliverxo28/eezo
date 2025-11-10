//! KEM module for EEZO Crypto
//!
//! Currently supports post-quantum ML-KEM variants.

// This line declares the submodule `ml_kem` (which corresponds to 
// the file `crates/crypto/src/kem/ml_kem.rs`).
// It is only compiled if the "mlkem" feature is enabled.
#[cfg(feature = "mlkem")]
pub mod ml_kem;

// This line re-exports the contents of that module.
// It is also only compiled if the "mlkem" feature is enabled.
#[cfg(feature = "mlkem")]
pub use ml_kem::*;

