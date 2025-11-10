//! ETH-style SSZ surface (opt-in via `eth-ssz` feature).
//! Phase 0: traits + minimal scalar impls + placeholder HTR (blake3).
//! No Merkle proofs yet; stable root bytes only.

pub mod encode;
pub mod decode;
pub mod hash;

pub use encode::Encode;
pub use decode::{Decode, MAX_SSZ_BYTES, MAX_SSZ_LIST, MAX_SSZ_TOTAL};
pub use hash::{HashTreeRoot, hash_tree_root_of};

// Simple error type shared by encode/decode for Phase 0.
// Extended with bounded-decode variants to prevent OOM on malformed inputs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SerdeError {
    // --- existing variants (kept for compatibility) ---
    #[error("invalid length")]
    InvalidLength,
    #[error("out of bounds")]
    OutOfBounds,
    #[error("malformed input")]
    Malformed,

    // --- new variants used by safe decoders ---
    /// Reached the end of input while reading.
    #[error("unexpected EOF")]
    Eof,
    /// Declared/parsed length exceeds our configured maximum.
    #[error("declared length {have} exceeds maximum {max}")]
    TooLong { have: usize, max: usize },
    /// Offset/length math overflow (e.g., offset+len > usize::MAX).
    #[error("overflow or invalid offset")]
    Overflow,
}

pub type Result<T> = core::result::Result<T, SerdeError>;
