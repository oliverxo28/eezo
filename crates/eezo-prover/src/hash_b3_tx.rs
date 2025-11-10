#![cfg(feature = "stark-air")]

// ======================================================================
// T38.4 — txs_root_v2 gadget (variable-length SSZ vector) — skeleton
//  * software witness only (BLAKE3 over SSZ(len:u32 LE || leaves[*]))
//  * constraint/enforce stub = Ok(())
//  * place_* stub (we'll wire lanes in witness.rs next step)
// ======================================================================

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
pub fn prove_txs_root_digest(sorted_leaves: &[[u8; 32]]) -> TxsWitness {
    let bytes = ssz_vec_bytes(sorted_leaves);
    let digest = *blake3::hash(&bytes).as_bytes();
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
