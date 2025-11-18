// T38.5 — End-to-end STARK proof scaffold.
// This connects:
//   - trace.rows()
//   - domain + blowup
//   - polynomial interpolation
//   - LDE evaluation
//   - Merkle trace commitment
//   - Constraint evaluation (placeholder)
//   - FRI folding & commitments
//
// This version is deterministic & structural.
// T38.6–T38.7 will replace placeholder math with real Goldilocks FFTs.

use crate::trace::Trace;
use crate::air_spec::AirSpec;
use crate::domain::Domain;
use crate::poly::Polynomial;
use crate::merkle::{merkle_root, merkle_proof, MerkleProof};
use crate::constraints::compose_constraints_row;
use crate::fri::{fri_prove, FriProof};

use blake3::hash;

#[derive(Clone, Debug)]
pub struct StarkProof {
    pub trace_root: [u8; 32],
    pub fri: FriProof,
    pub public_inputs_hash: [u8; 32],
    /// T38.6 — query indices derived from the transcript (stabilized format).
    /// The same indices are opened across every FRI layer.
    pub query_indices: Vec<usize>,
    /// T38.6 — per-layer Merkle openings at the query indices.
    /// Layout: layers[layer_id][query_id] = proof for that layer/leaf.
    pub layer_openings: Vec<Vec<MerkleProof>>,
    /// T38.6 — values opened at each (layer, index).
    /// Layout mirrors `layer_openings`.
    pub layer_values: Vec<Vec<u64>>,
    /// T38.6.2 — previous-layer paired openings (for fold checks) — left child at 2*i
    /// Layout: prev_left_openings[layer_id-1][query_id] (for layer_id >= 1)
    pub prev_left_openings: Vec<Vec<MerkleProof>>,
    /// T38.6.2 — previous-layer paired openings — right child at 2*i+1
    pub prev_right_openings: Vec<Vec<MerkleProof>>,
    /// T38.6.2 — previous-layer left values at 2*i
    pub prev_left_values: Vec<Vec<u64>>,
    /// T38.6.2 — previous-layer right values at 2*i + 1
    pub prev_right_values: Vec<Vec<u64>>,
    // --- T38.6.3: DEEP / constraints commitment & query openings ---
    pub constraints_root: [u8; 32],
    pub constraints_openings: Vec<MerkleProof>,
    pub constraints_values: Vec<u64>,
    // --- T38.6.4: final-layer low-degree check (commitment to final_poly coeffs) ---
    pub final_poly_root: [u8; 32],	
}

/// Main proving entry point.
///
/// Produces:
///   - trace Merkle commitment
///   - FRI proof on polynomial evaluations
///
/// NOTE:
///   Real STARKs commit to *each column* of the trace independently.
///   This T38.5 scaffold commits to a single polynomial derived from
///   all rows → this allows structure testing without full columnization.
///
pub fn prove(trace: &Trace, air: &AirSpec) -> StarkProof {
    // ---------------------------------------------------------------------
    // 1. Extract raw rows from trace
    // ---------------------------------------------------------------------
    let rows = trace.rows();
    let row_count = rows.len();
    if row_count == 0 {
        panic!("empty trace");
    }

    // ---------------------------------------------------------------------
    // 2. Build evaluation domain (based on row count)
    // ---------------------------------------------------------------------
    let domain = Domain::new(row_count);

    // ---------------------------------------------------------------------
    // 3. Turn trace into a polynomial (placeholder)
    //
    // For T38.5:
    //     interpolate(value[i] = hash(row[i]))  → polynomial coeffs
    //
    // Later:
    //     interpolate each column → column polys → DEEP composition
    // ---------------------------------------------------------------------
    let mut row_hashes = Vec::with_capacity(row_count);
    for r in rows {
        let h = *hash(&r.to_le_bytes()).as_bytes();
        // reduce 32 bytes → u64
        let mut v = 0u64;
        for (i, &byte) in h.iter().take(8).enumerate() {
            v |= (byte as u64) << (8 * i);
        }
        row_hashes.push(v);
    }

    let poly = Polynomial::interpolate(&row_hashes);

    // ---------------------------------------------------------------------
    // 4. Low-degree extension evaluation (placeholder LDE)
    // ---------------------------------------------------------------------
    let evals = poly.evaluate_over(&domain);

    // ---------------------------------------------------------------------
    // 5. Merkle commit to the LDE evaluations
    // ---------------------------------------------------------------------
    let eval_leaves: Vec<[u8; 32]> = evals
        .iter()
        .map(|x| hash(&x.to_le_bytes()).into())
        .collect();

    let trace_root = merkle_root(&eval_leaves);

    // ---------------------------------------------------------------------
    // 6. Build FRI proof on these evaluations
    // ---------------------------------------------------------------------
    let fri = fri_prove(evals, &domain);

    // ---------------------------------------------------------------------
    // 7. Derive query set from committed roots (stabilize proof format)
    //
    // We re-derive indices from a transcript seeded by the layer roots,
    // then open those indices in every layer. This does not validate them yet
    // (the verifier will do it in the next patch), but it stabilizes the
    // proof object format without changing existing behavior.
    //
    // For now, pick a small fixed sample size (e.g., 4).
    let sample_k: usize = 4;
    let mut t_q = crate::fri::Transcript::new();
    for layer in &fri.layers {
        t_q.absorb(&layer.root);
    }
    let mut query_indices = Vec::with_capacity(sample_k);
    // First layer length determines index modulus; subsequent layers will mod their own lengths.
    let l0_len = fri.layers[0].evals.len();
    for _ in 0..sample_k {
        let r = t_q.challenge_u64() as usize;
        query_indices.push(r % l0_len.max(1));
    }

    // For each layer, compute Merkle proofs & record claimed values at those indices.
    let mut layer_openings: Vec<Vec<MerkleProof>> = Vec::with_capacity(fri.layers.len());
    let mut layer_values:   Vec<Vec<u64>>        = Vec::with_capacity(fri.layers.len());
    for layer in fri.layers.iter() {
        let m = layer.evals.len().max(1);
        // Hash each eval into a leaf to match the commitment rule.
        let leaves: Vec<[u8; 32]> = layer
            .evals
            .iter()
            .map(|x| hash(&x.to_le_bytes()).into())
            .collect();

        let mut proofs_for_layer = Vec::with_capacity(sample_k);
        let mut values_for_layer = Vec::with_capacity(sample_k);
        for &qi in &query_indices {
            let idx = qi % m;
            let val = layer.evals[idx];
            let proof = merkle_proof(&leaves, idx).expect("proof exists for index");
            proofs_for_layer.push(proof);
            values_for_layer.push(val);
        }
        layer_openings.push(proofs_for_layer);
        layer_values.push(values_for_layer);
    }
    // 7.1 For each layer k>=1, also open paired siblings from layer k-1 at (2*idx, 2*idx+1)
    let mut prev_left_openings:  Vec<Vec<MerkleProof>> = Vec::with_capacity(fri.layers.len().saturating_sub(1));
    let mut prev_right_openings: Vec<Vec<MerkleProof>> = Vec::with_capacity(fri.layers.len().saturating_sub(1));
    let mut prev_left_values:    Vec<Vec<u64>>         = Vec::with_capacity(fri.layers.len().saturating_sub(1));
    let mut prev_right_values:   Vec<Vec<u64>>         = Vec::with_capacity(fri.layers.len().saturating_sub(1));

    for lid in 1..fri.layers.len() {
        let prev = &fri.layers[lid - 1];
        let m_prev = prev.evals.len().max(1);
        // leaves in previous layer (to match commitment rule)
        let prev_leaves: Vec<[u8; 32]> = prev
            .evals
            .iter()
            .map(|x| hash(&x.to_le_bytes()).into())
            .collect();

        let mut left_proofs  = Vec::with_capacity(query_indices.len());
        let mut right_proofs = Vec::with_capacity(query_indices.len());
        let mut left_vals    = Vec::with_capacity(query_indices.len());
        let mut right_vals   = Vec::with_capacity(query_indices.len());

        // for each query index on layer lid, map back to (2*i, 2*i+1) on previous layer
        for &qi in &query_indices {
            let idx_k   = qi % fri.layers[lid].evals.len().max(1);
            let i_left  = (2 * idx_k) % m_prev;
            let i_right = (i_left + 1) % m_prev;

            let v_left  = prev.evals[i_left];
            let v_right = prev.evals[i_right];
            let p_left  = merkle_proof(&prev_leaves, i_left).expect("prev-left proof");
            let p_right = merkle_proof(&prev_leaves, i_right).expect("prev-right proof");

            left_proofs.push(p_left);
            right_proofs.push(p_right);
            left_vals.push(v_left);
            right_vals.push(v_right);
        }

        prev_left_openings.push(left_proofs);
        prev_right_openings.push(right_proofs);
        prev_left_values.push(left_vals);
        prev_right_values.push(right_vals);
    }
    // 7.2 Compose constraint scalars per row, commit, and open at the same queries
    let mut c_evals = Vec::with_capacity(row_count);
    for i in 0..row_count {
        c_evals.push(compose_constraints_row(trace, i));
    }
    let c_leaves: Vec<[u8; 32]> =
        c_evals.iter().map(|x| hash(&x.to_le_bytes()).into()).collect();
    let constraints_root = merkle_root(&c_leaves);
    let mut constraints_openings = Vec::with_capacity(query_indices.len());
    let mut constraints_values   = Vec::with_capacity(query_indices.len());
    for &qi in &query_indices {
        let idx = qi % c_evals.len().max(1);
        constraints_values.push(c_evals[idx]);
        constraints_openings.push(merkle_proof(&c_leaves, idx).expect("c-proof"));
    }
	
    // 8. Public input digest (placeholder)
    //
    // Later:
    //     SSZ digest of AirSpec.public_inputs_v2()
    // ---------------------------------------------------------------------
    let pi_hash = hash(&air.public_inputs_v2().to_le_bytes());
    let mut pi_digest = [0u8; 32];
    pi_digest.copy_from_slice(pi_hash.as_bytes());
	
    // 8.5 Commit to final polynomial coefficients (degree bound will be checked by verifier)
    //     Commitment rule matches all others: leaf = blake3(u64::to_le_bytes()).
    let final_leaves: Vec<[u8; 32]> = fri
        .final_poly
        .coeffs
        .iter()
        .map(|c| hash(&c.to_le_bytes()).into())
        .collect();
    let final_poly_root = merkle_root(&final_leaves);
	
    // ---------------------------------------------------------------------
    // 9. Package final proof
    // ---------------------------------------------------------------------
    StarkProof {
        trace_root,
        fri,
        public_inputs_hash: pi_digest,
        query_indices,
        layer_openings,
        layer_values,
        prev_left_openings,
        prev_right_openings,
        prev_left_values,
        prev_right_values,
        constraints_root,
        constraints_openings,
        constraints_values,
        final_poly_root,		
    }
}
