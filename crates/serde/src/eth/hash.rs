/// Phase-0 HashTreeRoot: stable 32-byte root via blake3 over SSZ bytes.
/// (Merkleization will replace this in Phase 1+; root stays stable for now.)
use blake3;
use super::encode::Encode;

/// Trait for computing a stable 32-byte root of any SSZ-encodable value.
pub trait HashTreeRoot {
    fn hash_tree_root(&self) -> [u8; 32];
}

/// Blanket implementation: all types that implement `Encode` get `HashTreeRoot`.
impl<T: Encode> HashTreeRoot for T {
    fn hash_tree_root(&self) -> [u8; 32] {
        let bytes = self.ssz_bytes();
        *blake3::hash(&bytes).as_bytes()
    }
}

/// Convenience helper for tests and manual calls:
/// compute the root of any SSZ-encodable value without importing the trait.
#[inline]
pub fn hash_tree_root_of<T: Encode>(v: &T) -> [u8; 32] {
    let bytes = v.ssz_bytes();
    *blake3::hash(&bytes).as_bytes()
}
