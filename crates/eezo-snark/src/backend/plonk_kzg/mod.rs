#![cfg(feature = "plonk_kzg")]

// T39.1/2 — PLONK-KZG backend integration

pub mod types;
pub mod circuit;
pub mod prove;
pub mod verify;

// ✅ NEW in T39.2: keys/crs helpers (file I/O stubs)
pub mod keys;

pub use types::{PlonkProof, PlonkPk, PlonkVk};
pub use prove::prove_plonk;
pub use verify::verify_plonk;
