// T38.8 — STARK → SNARK preparation layer
// Feature-gated: no effect on production unless `stark-air` is enabled.

#![cfg(feature = "stark-air")]

use crate::proof::StarkProof;
use crate::fri::{FriProof, FriLayer, Transcript as FriTranscript};
use crate::merkle::MerkleProof;

/// Public, circuit‑friendly representation of a STARK proof.
/// This struct contains only data required by future SNARK circuits.
#[derive(Clone, Debug)]
pub struct StarkProofPublic {
    pub pi_digest: [u8; 32],
    pub fri_roots: Vec<[u8; 32]>,
    pub fri_challenges: Vec<u64>,
    pub final_poly_coeffs: Vec<u64>,
    pub final_poly_root: [u8; 32],
    pub queries: Vec<SnarkQuery>,
}

/// A single SNARK‑friendly query bundle.
#[derive(Clone, Debug)]
pub struct SnarkQuery {
    pub index: usize,
    pub layer_values: Vec<u64>,
    pub layer_roots: Vec<[u8; 32]>,
    pub openings: Vec<(MerkleProof, u64)>,
    pub prev_left: Vec<(MerkleProof, u64)>,
    pub prev_right: Vec<(MerkleProof, u64)>,
    pub constraint_opening: Option<(MerkleProof, u64)>,
}

/// Main entry: extract all circuit‑friendly public components.
pub fn prepare_for_snark(p: &StarkProof) -> StarkProofPublic {
    // gather roots
    let mut fri_roots = Vec::with_capacity(p.fri.layers.len());
    for layer in &p.fri.layers {
        fri_roots.push(layer.root);
    }

    // gather final polynomial
    let final_poly_coeffs = p.fri.final_poly.coeffs.clone();

    // build queries
    let mut queries = Vec::with_capacity(p.query_indices.len());
    for (qi_pos, &qi) in p.query_indices.iter().enumerate() {
        let mut layer_values = Vec::new();
        let mut layer_roots = Vec::new();
        let mut openings = Vec::new();
        let mut prev_left = Vec::new();
        let mut prev_right = Vec::new();

        for (lid, layer) in p.fri.layers.iter().enumerate() {
            let val = p.layer_values[lid][qi_pos];
            let proof = p.layer_openings[lid][qi_pos].clone();
            layer_values.push(val);
            layer_roots.push(layer.root);
            openings.push((proof, val));

            if lid > 0 {
                let left_val = p.prev_left_values[lid - 1][qi_pos];
                let left_pf = p.prev_left_openings[lid - 1][qi_pos].clone();
                prev_left.push((left_pf, left_val));

                let right_val = p.prev_right_values[lid - 1][qi_pos];
                let right_pf = p.prev_right_openings[lid - 1][qi_pos].clone();
                prev_right.push((right_pf, right_val));
            }
        }

        let constraint_opening = p.constraints_openings.get(qi_pos).map(|mp| {
            let val = p.constraints_values[qi_pos];
            (mp.clone(), val)
        });

        queries.push(SnarkQuery {
            index: qi,
            layer_values,
            layer_roots,
            openings,
            prev_left,
            prev_right,
            constraint_opening,
        });
    }

    StarkProofPublic {
        pi_digest: p.public_inputs_hash,
        fri_roots,
        fri_challenges: p.fri.challenges.clone(),
        final_poly_coeffs,
        final_poly_root: p.final_poly_root,
        queries,
    }
}

/// SNARK transcript replay: deterministic byte transcript.
pub fn build_snark_transcript(sp: &StarkProofPublic) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&sp.pi_digest);

    for r in &sp.fri_roots {
        out.extend_from_slice(r);
    }

    for &c in &sp.fri_challenges {
        out.extend_from_slice(&c.to_le_bytes());
    }

    for q in &sp.queries {
        out.extend_from_slice(&(q.index as u64).to_le_bytes());

        for &v in &q.layer_values {
            out.extend_from_slice(&v.to_le_bytes());
        }

        for &(ref proof, val) in &q.openings {
            out.extend_from_slice(&val.to_le_bytes());
            out.extend_from_slice(&proof.root);
        }
    }

    out.extend_from_slice(&sp.final_poly_root);
    for &c in &sp.final_poly_coeffs {
        out.extend_from_slice(&c.to_le_bytes());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::Trace;
    use crate::air_spec::AirSpec;
    use crate::proof::prove;

    #[test]
    fn prep_roundtrip_test() {
        // placeholder trace + air
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();
        let proof = prove(&t, &a);
        let pubp = prepare_for_snark(&proof);
        assert!(pubp.fri_roots.len() > 0);
    }

    #[test]
    fn prep_transcript_replay_test() {
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();
        let proof = prove(&t, &a);
        let pubp = prepare_for_snark(&proof);
        let tr1 = build_snark_transcript(&pubp);
        let tr2 = build_snark_transcript(&pubp);
        assert_eq!(tr1, tr2);
    }

    #[test]
    fn prep_tamper_breaks_test() {
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();
        let proof = prove(&t, &a);
        let mut pubp = prepare_for_snark(&proof);
        let tr1 = build_snark_transcript(&pubp);
        // tamper
        if !pubp.fri_roots.is_empty() {
            pubp.fri_roots[0][0] ^= 1;
        }
        let tr2 = build_snark_transcript(&pubp);
        assert_ne!(tr1, tr2);
    }
}
