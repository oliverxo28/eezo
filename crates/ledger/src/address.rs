//! Canonical account address type for the EEZO ledger.
//!
//! # Definition (mainnet)
//! An address is **exactly 20 bytes**. It is derived from the account’s public key as:
//! `Keccak256(pubkey)[12..32]` (i.e., the **right-most 20 bytes** of the 32-byte hash).
//!
//! This keeps the on-chain/state key compact (160-bit), while authentication strength
//! comes from signature verification on transactions (ML-DSA / SLH-DSA, etc.).
//!
//! # Encodings
//! * Internally and on disk: raw 20 bytes.
//! * At API boundaries: clients may present either hex (`0x...`) or Bech32 strings which
//!   MUST decode to the same 20 bytes before reaching state. The node normalizes inputs.
//! * This type intentionally does **not** depend on any encoding crate.
//!
//! # Stability
//! The 20-byte size is **canonical** for the ledger. If a future format is introduced,
//! it should be gated at the parsing/compat layer, not here.

use serde::{Deserialize, Serialize};

#[derive(
    Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Construct from a 20-byte array (canonical form).
    #[inline]
    pub fn from_bytes(b: [u8; 20]) -> Self {
        Address(b)
    }

    /// Borrow the underlying 20-byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl AsRef<[u8]> for Address {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}