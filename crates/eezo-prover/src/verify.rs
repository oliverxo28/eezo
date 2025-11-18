// T38.6 — minimal verifier scaffold that matches current proof.rs/fri.rs.
// Validates:
//  - public_inputs_hash consistency
//  - each FRI layer's root re-computed from evals
//  - transcript challenges re-derived from committed roots
//
// NOTE: This does NOT yet check Merkle paths/openings or DEEP constraints.
// We'll extend StarkProof in a follow-up step and upgrade these checks.

use blake3::hash;

use crate::air_spec::AirSpec;
use crate::fri::Transcript;
use crate::merkle::{merkle_root, verify_proof};
use crate::proof::StarkProof;

#[derive(Debug)]
pub enum VerifyError {
    PublicInputsHashMismatch,
    FriLayerRootMismatch { layer: usize },
    TranscriptChallengeMismatch { round: usize },
    QueryIndexMismatch,
    OpeningCountMismatch { layer: usize },
    OpeningLeafHashMismatch { layer: usize, query: usize },
    OpeningPathInvalid { layer: usize, query: usize },
    ConstraintsOpeningCountMismatch,
    ConstraintsLeafHashMismatch { query: usize },
    ConstraintsPathInvalid { query: usize },
    FinalPolyTooLarge,
    FinalPolyRootMismatch,	
}

pub fn stark_verify(proof: &StarkProof, air: &AirSpec) -> Result<(), VerifyError> {
    // 1) recheck public inputs hash (placeholder to match proof.rs)
    let pi_hash = hash(&air.public_inputs_v2().to_le_bytes());
    if proof.public_inputs_hash != *pi_hash.as_bytes() {
        return Err(VerifyError::PublicInputsHashMismatch);
    }

    // 2) rebuild transcript exactly like fri_prove()
    let mut t = Transcript::new();

    // layer 0: recompute root from evals and absorb
    if proof.fri.layers.is_empty() {
        // trivial "proof" is invalid structurally; but we keep it simple: no layers => roots can't be checked
        return Err(VerifyError::FriLayerRootMismatch { layer: 0 });
    }

    let l0 = &proof.fri.layers[0];
    let recomputed0 = merkle_root(
        &l0.evals
            .iter()
            .map(|x| hash(&x.to_le_bytes()).into())
            .collect::<Vec<[u8; 32]>>(),
    );
    if recomputed0 != l0.root {
        return Err(VerifyError::FriLayerRootMismatch { layer: 0 });
    }
    t.absorb(&l0.root);

    // 3) iterate subsequent layers, re-derive alpha and validate root chaining
    // We cannot re-fold without openings yet; we only verify the same transcript
    // sequence and each layer's Merkle root match their evals.
    for (round, layer) in proof.fri.layers.iter().enumerate().skip(1) {
        // derive alpha deterministically
        let expected_alpha = t.challenge_u64();
        // check it matches the stored challenge stream
        let stored_alpha = *proof
            .fri
            .challenges
            .get(round - 1) // first challenge corresponds to producing layer 1
            .unwrap_or(&0);
        if expected_alpha != stored_alpha {
            return Err(VerifyError::TranscriptChallengeMismatch { round: round - 1 });
        }

        // recompute this layer's commitment root
        let recomputed = merkle_root(
            &layer
                .evals
                .iter()
                .map(|x| hash(&x.to_le_bytes()).into())
                .collect::<Vec<[u8; 32]>>(),
        );
        if recomputed != layer.root {
            return Err(VerifyError::FriLayerRootMismatch { layer: round });
        }

        // absorb for next round
        t.absorb(&layer.root);
    }
    // 4) Re-derive the same query indices from all layer roots (deterministic).
    let mut tq = Transcript::new();
    for layer in &proof.fri.layers { tq.absorb(&layer.root); }
    let expected_q = proof.query_indices.len();
    let l0_len = proof.fri.layers[0].evals.len().max(1);
    let mut derived = Vec::with_capacity(expected_q);
    for _ in 0..expected_q {
        let r = tq.challenge_u64() as usize;
        derived.push(r % l0_len);
    }
    if derived != proof.query_indices {
        return Err(VerifyError::QueryIndexMismatch);
    }

    // 5) For each layer, verify openings against roots; check value->leaf hashing.
    if proof.layer_openings.len() != proof.fri.layers.len()
        || proof.layer_values.len() != proof.fri.layers.len()
    {
        return Err(VerifyError::OpeningCountMismatch { layer: 0 });
    }

    for (lid, layer) in proof.fri.layers.iter().enumerate() {
        let proofs = &proof.layer_openings[lid];
        let vals   = &proof.layer_values[lid];
        if proofs.len() != expected_q || vals.len() != expected_q {
            return Err(VerifyError::OpeningCountMismatch { layer: lid });
        }
        for (qix, (&_qi, (mp, &val))) in proof.query_indices.iter()
            .zip(proofs.iter().zip(vals.iter()))
            .enumerate()
        {
            // value -> leaf hashing must match your commitment rule (hash(u64::to_le_bytes()))
            let expected_leaf: [u8;32] = hash(&val.to_le_bytes()).into();
            if mp.leaf != expected_leaf {
                return Err(VerifyError::OpeningLeafHashMismatch { layer: lid, query: qix });
            }
            // path must verify to this layer's root
            if mp.root != layer.root || !verify_proof(mp) {
                return Err(VerifyError::OpeningPathInvalid { layer: lid, query: qix });
            }
        }
    }
	
    // 6) Fold-correctness at queries:
    // For each layer k>=1, check f_k[i] == f_{k-1}[2i] + alpha * f_{k-1}[2i+1]
    for lid in 1..proof.fri.layers.len() {
        let prev = &proof.fri.layers[lid - 1];
        let cur  = &proof.fri.layers[lid];

        let alpha = *proof
            .fri
            .challenges
            .get(lid - 1)
            .ok_or(VerifyError::TranscriptChallengeMismatch { round: lid - 1 })?;

        // lengths for modulo mapping
        let m_prev = prev.evals.len().max(1);
        let m_cur  = cur.evals.len().max(1);

        // the current-layer opened values
        let cur_vals = &proof.layer_values[lid];
        // the previous-layer paired openings (must exist for k>=1)
        let left_proofs  = proof.prev_left_openings.get(lid - 1).ok_or(VerifyError::OpeningCountMismatch { layer: lid })?;
        let right_proofs = proof.prev_right_openings.get(lid - 1).ok_or(VerifyError::OpeningCountMismatch { layer: lid })?;
        let left_vals    = proof.prev_left_values.get(lid - 1).ok_or(VerifyError::OpeningCountMismatch { layer: lid })?;
        let right_vals   = proof.prev_right_values.get(lid - 1).ok_or(VerifyError::OpeningCountMismatch { layer: lid })?;

        if left_proofs.len() != expected_q || right_proofs.len() != expected_q
            || left_vals.len() != expected_q || right_vals.len() != expected_q
        {
            return Err(VerifyError::OpeningCountMismatch { layer: lid });
        }

        for (qix, &qi) in proof.query_indices.iter().enumerate() {
            // map index to current and previous layers
            let idx_cur   = qi % m_cur;
            let _i_left   = (2 * idx_cur) % m_prev;
            let _i_right  = (_i_left + 1) % m_prev;

            // verify prev-left & prev-right merkle paths against prev.root
            let lp = &left_proofs[qix];
            let rp = &right_proofs[qix];
            if lp.root != prev.root || !verify_proof(lp) {
                return Err(VerifyError::OpeningPathInvalid { layer: lid - 1, query: qix });
            }
            if rp.root != prev.root || !verify_proof(rp) {
                return Err(VerifyError::OpeningPathInvalid { layer: lid - 1, query: qix });
            }

            // check leaf hashes match the opened values
            let v_left  = left_vals[qix];
            let v_right = right_vals[qix];
            let leaf_l: [u8;32] = blake3::hash(&v_left.to_le_bytes()).into();
            let leaf_r: [u8;32] = blake3::hash(&v_right.to_le_bytes()).into();
            if lp.leaf != leaf_l || rp.leaf != leaf_r {
                return Err(VerifyError::OpeningLeafHashMismatch { layer: lid - 1, query: qix });
            }

            // finally, folding relation (wrapping u64 consistent with prover)
            let expected = v_left.wrapping_add(v_right.wrapping_mul(alpha));
            let got      = cur_vals[qix];
            if got != expected {
                // reuse TranscriptChallengeMismatch would be misleading; we keep structure simple here
                return Err(VerifyError::TranscriptChallengeMismatch { round: lid - 1 });
            }
        }
    }
    // 7) Constraint DEEP openings: verify leaves & Merkle paths at the same indices
    if proof.constraints_openings.len() != expected_q
        || proof.constraints_values.len() != expected_q
    {
        return Err(VerifyError::ConstraintsOpeningCountMismatch);
    }
    for (qix, (&_qi, (mp, &val))) in proof.query_indices
        .iter()
        .zip(proof.constraints_openings.iter().zip(proof.constraints_values.iter()))
        .enumerate()
    {
        // value → leaf hash rule matches prover (blake3(u64_le))
        let expected_leaf: [u8; 32] = blake3::hash(&val.to_le_bytes()).into();
        if mp.leaf != expected_leaf {
            return Err(VerifyError::ConstraintsLeafHashMismatch { query: qix });
        }
        if mp.root != proof.constraints_root || !verify_proof(mp) {
            return Err(VerifyError::ConstraintsPathInvalid { query: qix });
        }
    }
    // 8) Final-layer low-degree check:
    //    - degree bound via coeffs length (your fri stops at <=16; enforce here)
    //    - commitment root must match blake3(u64_le) over coeffs
    let coeffs = &proof.fri.final_poly.coeffs;
    if coeffs.len() > 16 {
        return Err(VerifyError::FinalPolyTooLarge);
    }
    let leaves: Vec<[u8;32]> =
        coeffs.iter().map(|c| blake3::hash(&c.to_le_bytes()).into()).collect();
    let root = merkle_root(&leaves);
    if root != proof.final_poly_root {
        return Err(VerifyError::FinalPolyRootMismatch);
    }	
		
    // If we reached here, the proof is structurally consistent with the current format.
    Ok(())
}