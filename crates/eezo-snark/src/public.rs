#![cfg(feature = "snark-mini")]

// T38.9 — pack StarkProofPublic into circuit-friendly field words.
//
// For now we use plain u64 "field words" (backend-agnostic). Later, when we
// pick a concrete SNARK field, we’ll swap packing to that field’s modulus.
//
// Invariants:
// - Little-endian packing of integers (matches eezo-prover).
// - [u8;32] values are packed into four u64 limbs (LE).
// - Order is canonical and stable (must not change without a version bump).

use eezo_prover::stark_snark_prep::StarkProofPublic;

/// Packed, circuit-ready public input buffer (backend-agnostic).
#[derive(Clone, Debug, Default)]
pub struct PublicPack {
    /// flat u64 words the circuit will consume (later: field elements)
    pub words: Vec<u64>,
}

#[inline]
fn pack_u32_le(words: &mut Vec<u64>, x: u32) {
    words.push(x as u64);
}

#[inline]
fn pack_u64_le(words: &mut Vec<u64>, x: u64) {
    words.push(x);
}

#[inline]
fn pack_bytes32_le(words: &mut Vec<u64>, b32: &[u8;32]) {
    // pack as 4 little-endian u64 limbs
    for k in 0..4 {
        let mut limb = 0u64;
        for i in 0..8 {
            limb |= (b32[k*8 + i] as u64) << (8*i);
        }
        words.push(limb);
    }
}

/// Canonical, deterministic packing for StarkProofPublic.
/// This is the *only* place the ordering is defined for the SNARK mini-circuit.
/// Keep this stable; modify only with a version bump.
pub fn pack_public(sp: &StarkProofPublic) -> PublicPack {
    let mut out = PublicPack { words: Vec::with_capacity(1024) };

    // 1) pi_digest
    pack_bytes32_le(&mut out.words, &sp.pi_digest);

    // 2) fri roots
    pack_u32_le(&mut out.words, sp.fri_roots.len() as u32);
    for r in &sp.fri_roots {
        pack_bytes32_le(&mut out.words, r);
    }

    // 3) fri challenges (u64 LE)
    pack_u32_le(&mut out.words, sp.fri_challenges.len() as u32);
    for &c in &sp.fri_challenges {
        pack_u64_le(&mut out.words, c);
    }

    // 4) queries: index, layer values, openings (root + val minimal for mini-circuit)
    pack_u32_le(&mut out.words, sp.queries.len() as u32);
    for q in &sp.queries {
        // index
        pack_u64_le(&mut out.words, q.index as u64);

        // layer values
        pack_u32_le(&mut out.words, q.layer_values.len() as u32);
        for &v in &q.layer_values {
            pack_u64_le(&mut out.words, v);
        }

        // layer roots (mirror for convenience in-circuit)
        pack_u32_le(&mut out.words, q.layer_roots.len() as u32);
        for r in &q.layer_roots {
            pack_bytes32_le(&mut out.words, r);
        }

        // openings (mini: commit only to root + val; full paths later)
        pack_u32_le(&mut out.words, q.openings.len() as u32);
        for (mp, val) in q.openings.iter() {
            pack_u64_le(&mut out.words, *val);
            pack_bytes32_le(&mut out.words, &mp.root);
        }

        // prev_left / prev_right (same minimal commitment)
        pack_u32_le(&mut out.words, q.prev_left.len() as u32);
        for (mp, val) in q.prev_left.iter() {
            pack_u64_le(&mut out.words, *val);
            pack_bytes32_le(&mut out.words, &mp.root);
        }

        pack_u32_le(&mut out.words, q.prev_right.len() as u32);
        for (mp, val) in q.prev_right.iter() {
            pack_u64_le(&mut out.words, *val);
            pack_bytes32_le(&mut out.words, &mp.root);
        }

        // constraint opening (optional)
        match &q.constraint_opening {
            Some((mp, val)) => {
                pack_u32_le(&mut out.words, 1);
                pack_u64_le(&mut out.words, *val);
                pack_bytes32_le(&mut out.words, &mp.root);
            }
            None => pack_u32_le(&mut out.words, 0),
        }
    }

    // 5) final poly
    pack_bytes32_le(&mut out.words, &sp.final_poly_root);
    pack_u32_le(&mut out.words, sp.final_poly_coeffs.len() as u32);
    for &c in &sp.final_poly_coeffs {
        pack_u64_le(&mut out.words, c);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use eezo_prover::proof::prove;
    use eezo_prover::stark_snark_prep::prepare_for_snark;
    use eezo_prover::trace::Trace;
    use eezo_prover::air_spec::AirSpec;

    #[test]
    fn packing_is_stable_and_nonempty() {
        // minimal 1-row trace to satisfy prover scaffold
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let proof = prove(&t, &a);
        let sp = prepare_for_snark(&proof);
        let packed = pack_public(&sp);

        assert!(!packed.words.is_empty(), "packed public must not be empty");
        // deterministic across calls
        let packed2 = pack_public(&sp);
        assert_eq!(packed.words, packed2.words, "packing must be stable");
    }
}
