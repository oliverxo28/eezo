// ======================================================================
// T38.4 — txs_root_v2 gadget (variable-length SSZ vector) — skeleton
//  * software witness only (BLAKE3 over SSZ(len:u32 LE || leaves[*]))
//  * constraint/enforce stub = Ok(())
//  * place_* stub (we'll wire lanes in witness.rs next step)
//
// T43.1 — GPU hashing lanes v1:
//  * The digest computation now routes through `Blake3Lanes::hash_one`,
//    so the witness stays identical but the backend is lane-aware and
//    ready for GPU offload in later T43.x tasks.
// ======================================================================

use crate::hash_b3::Blake3Lanes;

#[derive(Clone, Debug)]
pub struct TxsWitness {
    pub digest: [u8; 32],
    pub leaves: Vec<[u8; 32]>,
}

fn ssz_vec_bytes(leaves: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * leaves.len());
    let len = leaves.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    for l in leaves {
        out.extend_from_slice(l);
    }
    out
}

/// Build software witness for txs_root_v2 (sorted leaves expected).
///
/// T43.1 note:
///   The digest is now computed via the BLAKE3 lanes abstraction
///   (`Blake3Lanes::hash_one`). This keeps the hash definition:
///     digest = BLAKE3(len:u32 LE || leaf_0[32] || ... || leaf_n[32])
///   but lets us later swap in a GPU-backed implementation without
///   changing the witness format or callers.
pub fn prove_txs_root_digest(sorted_leaves: &[[u8; 32]]) -> TxsWitness {
    let bytes = ssz_vec_bytes(sorted_leaves);
    let digest = Blake3Lanes::hash_one(&bytes);
    TxsWitness {
        digest,
        leaves: sorted_leaves.to_vec(),
    }
}

/// Stub constraints for now (phase-0 of T38.4). Always Ok.
pub fn enforce_txs_root_constraints(
    _rows: &mut [crate::trace::Row],
    _w: &TxsWitness,
) -> Result<(), &'static str> {
    Ok(())
}

/// Stub: we’ll place digest lanes in witness.rs next.
pub fn place_txs_digest_into_trace(
    _row: &mut crate::trace::Row,
    _w: &TxsWitness,
) {
    // no-op for skeleton
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3;

    #[test]
    fn prove_txs_root_digest_matches_direct_blake3() {
        let leaves: Vec<[u8; 32]> = vec![
            [0u8; 32],
            [1u8; 32],
            *b"0123456789abcdef0123456789abcdef",
        ];

        let ssz_bytes = ssz_vec_bytes(&leaves);
        let expected = *blake3::hash(&ssz_bytes).as_bytes();

        let w = prove_txs_root_digest(&leaves);
        assert_eq!(w.digest, expected);
    }
}