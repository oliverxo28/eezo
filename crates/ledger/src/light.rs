// crates/ledger/src/light.rs
#![cfg(feature = "eth-ssz")]

use eezo_serde::eth::{Decode, Encode, HashTreeRoot, SerdeError};

#[derive(Clone, Debug)]
pub struct LightHeader {
    pub height: u64,
    /// Crypto suite used to produce the header’s signatures/roots.
    /// This gets committed into the SSZ container so the HTR changes across rotations.
    pub suite_id: u32,
    pub parent_root: [u8; 32],
    pub tx_root_v2: [u8; 32],
    #[cfg(feature = "checkpoints")]
    pub qc_root: [u8; 32],
    pub timestamp_ms: u64,
}

// Implement ETH-SSZ traits so we can hash_tree_root() headers deterministically.
impl Encode for LightHeader {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        // Minimal container encoding (fixed fields concatenated). Your eth::Encode
        // for primitives handles u64 and [u8;32] already.
        self.height.ssz_write(out);
        self.suite_id.ssz_write(out); // <— widened to u32 for T34.2
        out.extend_from_slice(&self.parent_root);
        out.extend_from_slice(&self.tx_root_v2);
        #[cfg(feature = "checkpoints")]
        out.extend_from_slice(&self.qc_root);
        self.timestamp_ms.ssz_write(out);
    }
}
// Blanket impl<T: Encode> HashTreeRoot is already provided by eezo_serde.

// Add Decode so persistence.rs -> LightAnchor::get_light_anchor() can call LightHeader::ssz_decode
impl Decode for LightHeader {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize), SerdeError> {
        let mut off = 0usize;

        // height (u64 LE)
        let (height, n1) = u64::ssz_read(&input[off..])?;
        off += n1;

        // suite_id (u32)
        let (suite_id, n1b) = u32::ssz_read(&input[off..])?;
        off += n1b;

        // parent_root (32 bytes)
        let (parent_root, n2) = <[u8; 32]>::ssz_read(&input[off..])?;
        off += n2;

        // tx_root_v2 (32 bytes)
        let (tx_root_v2, n3) = <[u8; 32]>::ssz_read(&input[off..])?;
        off += n3;

        // qc_root (optional, only if checkpoints enabled)
        #[cfg(feature = "checkpoints")]
        let (qc_root, n4) = <[u8; 32]>::ssz_read(&input[off..])?;
        #[cfg(feature = "checkpoints")]
        {
            off += n4;
        }

        // timestamp_ms (u64)
        let (timestamp_ms, n5) = u64::ssz_read(&input[off..])?;
        off += n5;

        Ok((
            LightHeader {
                height,
                suite_id,
                parent_root,
                tx_root_v2,
                #[cfg(feature = "checkpoints")]
                qc_root,
                timestamp_ms,
            },
            off,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct TxProofBundle {
    pub tx_index: usize,
    pub leaf: Vec<u8>,         // 32-byte tx HTR
    pub branch: Vec<[u8; 32]>, // bottom→top
}

#[derive(Debug)]
pub enum LightError {
    Link,  // parent linkage broken
    TxProof, // inclusion proof fails
    Time,  // timestamp monotonicity violated
    Codec, // malformed inputs
}

/// Verify parent→child linkage and a tx proof against the child's root.
/// Also checks timestamp monotonicity; if checkpoints are on, ensure qc_root is shaped.
pub fn light_verify(
    child: &LightHeader,
    parent: &LightHeader,
    proof: &TxProofBundle,
) -> Result<(), LightError> {
    // 1) Parent linkage: HTR(parent) == child.parent_root
    let parent_htr: [u8; 32] = parent.hash_tree_root();
    if parent_htr != child.parent_root {
        return Err(LightError::Link);
    }

    // 2) Timestamp monotonic (non-decreasing; tighten if you require strict >)
    if child.timestamp_ms < parent.timestamp_ms {
        return Err(LightError::Time);
    }

    // 3) Tx proof checks (bounded via merkle::verify_tx_inclusion)
    if proof.leaf.len() != 32 || proof.branch.len() > 64 {
        return Err(LightError::Codec);
    }
    if !crate::merkle::verify_tx_inclusion(
        &proof.leaf,
        &proof.branch,
        child.tx_root_v2,
        proof.tx_index,
    ) {
        return Err(LightError::TxProof);
    }

    // 4) If checkpoints enabled, require a well-formed qc_root (non-zero)
    #[cfg(feature = "checkpoints")]
    {
        if child.qc_root == [0u8; 32] {
            return Err(LightError::Codec);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eezo_serde::eth::{Encode as _, Decode as _};

    #[test]
    fn ssz_roundtrip_with_suite_u32() {
        let h = LightHeader {
            height: 123,
            suite_id: 1, // ml-dsa-44
            parent_root: [9u8; 32],
            tx_root_v2: [7u8; 32],
            #[cfg(feature = "checkpoints")]
            qc_root: [5u8; 32],
            timestamp_ms: 999,
        };
        let mut buf = Vec::new();
        h.ssz_write(&mut buf);
        let (h2, used) = LightHeader::ssz_read(&buf).expect("decode");
        assert_eq!(used, buf.len());
        assert_eq!(h2.suite_id, 1u32);
        assert_eq!(h2.height, 123);
        assert_eq!(h2.parent_root, [9u8; 32]);
        assert_eq!(h2.tx_root_v2, [7u8; 32]);
        assert_eq!(h2.timestamp_ms, 999);
        #[cfg(feature = "checkpoints")]
        assert_eq!(h2.qc_root, [5u8; 32]);
    }

    #[test]
    fn htr_changes_when_suite_changes() {
        let base = LightHeader {
            height: 1,
            suite_id: 1, // ml-dsa-44
            parent_root: [1u8; 32],
            tx_root_v2: [2u8; 32],
            #[cfg(feature = "checkpoints")]
            qc_root: [3u8; 32],
            timestamp_ms: 10,
        };
        let mut alt = base.clone();
        alt.suite_id = 2; // sphincs+
        let htr1 = base.hash_tree_root();
        let htr2 = alt.hash_tree_root();
        assert_ne!(htr1, htr2, "suite_id must influence HTR");
    }
}
