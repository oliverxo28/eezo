// crates/ledger/src/merkle.rs
#![cfg(feature = "eth-ssz")]

use crate::bridge::{mint_leaf, BridgeMintVoucher};
use crate::SignedTx;
use eezo_serde::eth::HashTreeRoot;
use sha3::{Digest, Sha3_256};

/// Hard upper bound on branch depth (covers up to 2^64 leaves; far above any realistic block).
const MAX_BRANCH_DEPTH: usize = 64;

/// Hash two 32-byte nodes (left||right) -> 32-byte node.
#[inline(always)]
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    let out = hasher.finalize();
    let mut node = [0u8; 32];
    node.copy_from_slice(&out);
    node
}

/// Next power-of-two >= n (min 1)
#[inline]
fn next_pow2(mut n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    #[cfg(target_pointer_width = "64")]
    {
        n |= n >> 32;
    }
    n + 1
}

/// Build a Merkle branch over 32-byte **leaf hashes**. We use the leaf as the
/// ETH-SSZ HashTreeRoot of the SignedTx (not raw bytes), so the top root
/// matches the v2 `tx_root_v2` the header stores.
#[inline]
fn build_branch(leaves: &[[u8; 32]], index: usize) -> (Vec<[u8; 32]>, [u8; 32]) {
    let n = leaves.len();
    let width = next_pow2(n);
    // pad with last leaf for perfect tree
    debug_assert!(n > 0, "build_branch requires at least one leaf");
    let mut level: Vec<[u8; 32]> = (0..width)
        .map(|i| if i < n { leaves[i] } else { leaves[n - 1] })
        .collect();

    let mut branch = Vec::new();
    let mut idx = index.min(n - 1);

    // climb the tree, collecting siblings
    let mut w = width;
    while w > 1 {
        let sib = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        branch.push(level[sib]);
        // compress level to parents
        let mut next = Vec::with_capacity((w + 1) / 2);
        for i in (0..w).step_by(2) {
            next.push(hash_pair(&level[i], &level[i + 1]));
        }
        level = next;
        idx /= 2;
        w /= 2;
    }

    let root = level[0];
    (branch, root)
}

/// Public API: construct a proof for `block_txs[tx_index]`.
///
/// Leaf = 32-byte ETH-SSZ HashTreeRoot(SignedTx) (returned additionally as `leaf` bytes)
/// Branch = list of 32-byte siblings bottom→top
/// Root = Merkle root over all tx-leaf HTRs (should equal BlockHeader.tx_root_v2)
#[inline]
pub fn tx_inclusion_proof(
    block_txs: &[SignedTx],
    tx_index: usize,
) -> Option<(Vec<u8>, Vec<[u8; 32]>, [u8; 32])> {
    if block_txs.is_empty() || tx_index >= block_txs.len() {
        return None;
    }
    // Bounded leaf count (anti-DoS): cap at 1<<20 (~1M) for safety in tests.
    if block_txs.len() > (1 << 20) {
        return None;
    }

    // Compute 32-byte HTR per tx (ETH-SSZ container root).
    let leaves: Vec<[u8; 32]> = block_txs
        .iter()
        .map(|tx| -> [u8; 32] { tx.hash_tree_root() })
        .collect();
    debug_assert!(!leaves.is_empty());

    let (branch, root) = build_branch(&leaves, tx_index);
    let leaf = leaves[tx_index].to_vec();
    Some((leaf, branch, root))
}

/// Public API: construct a proof for `mints[mint_index]` over bridge-mint leaves.
///
/// Leaf = sha3_256(canonical_mint_msg(chain_id, voucher)) (returned additionally as `leaf` bytes)
/// Branch = list of 32-byte siblings bottom→top
/// Root = Merkle root over all **bridge-mint** leaves (used for checkpoint/light-client proofs)
#[inline]
pub fn mint_inclusion_proof(
    mints: &[BridgeMintVoucher],
    mint_index: usize,
    chain_id: [u8; 20],
) -> Option<(Vec<u8>, Vec<[u8; 32]>, [u8; 32])> {
    if mints.is_empty() || mint_index >= mints.len() {
        return None;
    }
    // Bounded leaf count to avoid pathological allocations in tests.
    if mints.len() > (1 << 20) {
        return None;
    }

    // Compute 32-byte leaf per voucher (domain-separated via canonical message).
    let leaves: Vec<[u8; 32]> = mints.iter().map(|v| mint_leaf(chain_id, v)).collect();
    debug_assert!(!leaves.is_empty());

    let (branch, root) = build_branch(&leaves, mint_index);
    let leaf = leaves[mint_index].to_vec();
    Some((leaf, branch, root))
}

/// Verify a tx inclusion proof built by `tx_inclusion_proof`.
///
/// `tx_index` is 0-based; `branch` is bottom→top; `leaf` must be 32 bytes.
#[inline]
pub fn verify_tx_inclusion(
    leaf: &[u8],
    branch: &[[u8; 32]],
    expected_root: [u8; 32],
    tx_index: usize,
) -> bool {
    if leaf.len() != 32 {
        return false;
    }
    // hard bound: > 2^64 leaves is impossible here; also protects against malicious huge inputs
    if branch.len() > MAX_BRANCH_DEPTH {
        return false;
    }

    let mut node = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(leaf);
        arr
    };

    let mut idx = tx_index;
    for sib in branch {
        node = if idx % 2 == 0 {
            hash_pair(&node, sib)
        } else {
            hash_pair(sib, &node)
        };
        idx /= 2;
    }
    node == expected_root
}

/// Verify a **bridge-mint** inclusion proof (same mechanics as tx proofs).
#[inline]
pub fn verify_mint_inclusion(
    leaf: &[u8],
    branch: &[[u8; 32]],
    expected_root: [u8; 32],
    mint_index: usize,
) -> bool {
    verify_tx_inclusion(leaf, branch, expected_root, mint_index)
}
