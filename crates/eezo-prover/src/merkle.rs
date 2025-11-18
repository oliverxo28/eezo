// T38.5 — Merkle commitment layer.
// Provides:
//   - blake3-based leaf hashing
//   - merkle root computation
//   - sibling proof generation
//   - verification helper
//
// This version is deterministic and lightweight.
// Later we will add parallel hashing and zero-copy slices.

use crate::hash_b3::Blake3Lanes;

/// A single Merkle proof node (sibling hash + position)
#[derive(Clone, Debug)]
pub struct ProofNode {
    pub sibling: [u8; 32],
    pub is_left: bool,
}

/// Merkle proof structure: sibling path up to root
#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub path: Vec<ProofNode>,
    pub root: [u8; 32],
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut layer = leaves.to_vec();

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));

        // First collect all pair inputs for this layer into a temporary buffer.
        let mut pair_bytes: Vec<[u8; 64]> = Vec::with_capacity(layer.len() / 2);
        for i in (0..layer.len()).step_by(2) {
            if i + 1 < layer.len() {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&layer[i]);
                buf[32..].copy_from_slice(&layer[i + 1]);
                pair_bytes.push(buf);
            }
        }

        // Hash all pairs in one shot using the lanes abstraction.
        let parent_hashes = if pair_bytes.is_empty() {
            Vec::new()
        } else {
            Blake3Lanes::hash_many(pair_bytes.iter().map(|b| b.as_slice()))
        };

        // Now rebuild the next layer in the same order as the original implementation:
        // parents in sequence, with odd nodes promoted in-place.
        let mut parent_iter = parent_hashes.into_iter();
        for i in (0..layer.len()).step_by(2) {
            if i + 1 < layer.len() {
                let h = parent_iter
                    .next()
                    .expect("parent_hashes length must match number of pairs");
                next.push(h);
            } else {
                // odd leaf promoted
                next.push(layer[i]);
            }
        }

        layer = next;
    }

    layer[0]
}

/// Build Merkle proof for a given index.
pub fn merkle_proof(leaves: &[[u8; 32]], index: usize) -> Option<MerkleProof> {
    if index >= leaves.len() || leaves.is_empty() {
        return None;
    }

    let mut path = Vec::new();
    let mut layer = leaves.to_vec();
    let mut idx = index;

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for i in (0..layer.len()).step_by(2) {
            if i + 1 < layer.len() {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&layer[i]);
                buf[32..].copy_from_slice(&layer[i + 1]);
                let digest = Blake3Lanes::hash_one(&buf);
                next.push(digest);

                if i == idx || i + 1 == idx {
                    let is_left = i == idx;
                    let sibling = if is_left { layer[i + 1] } else { layer[i] };
                    path.push(ProofNode { sibling, is_left });
                    idx = next.len() - 1;
                }
            } else {
                // odd node promoted
                next.push(layer[i]);
                if i == idx {
                    idx = next.len() - 1;
                }
            }
        }
        layer = next;
    }

    let root = layer[0];
    Some(MerkleProof { leaf: leaves[index], path, root })
}

/// Verify a Merkle proof.
pub fn verify_proof(proof: &MerkleProof) -> bool {
    let mut current = proof.leaf;

    for node in &proof.path {
        let mut buf = [0u8; 64];
        if node.is_left {
            buf[..32].copy_from_slice(&current);
            buf[32..].copy_from_slice(&node.sibling);
        } else {
            buf[..32].copy_from_slice(&node.sibling);
            buf[32..].copy_from_slice(&current);
        }
        current = Blake3Lanes::hash_one(&buf);
    }

    current == proof.root
}