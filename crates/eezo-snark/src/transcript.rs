#![cfg(feature = "snark-mini")]

// T38.9 — mini transcript over packed public words.
// Intended to model an in-circuit hash over the same data the host commits to.
//
// For now we use a plain Blake3 over little-endian u64 limbs (backend-agnostic).
// Later, when we wire a real circuit, this will become a Poseidon/Blake gadget.

use blake3::Hasher;
use eezo_prover::stark_snark_prep::StarkProofPublic;

// Hash u64 words as LE bytes (exactly like eezo-prover encodings expect).
#[inline]
fn absorb_words_le(hasher: &mut Hasher, words: &[u64]) {
    for w in words {
        hasher.update(&w.to_le_bytes());
    }
}

/// Compute the circuit-side commitment over the packed public words.
/// This is what the mini-circuit will re-create.
pub fn circuit_public_digest_from_packed(words: &[u64]) -> [u8; 32] {
    let mut h = Hasher::new();
    absorb_words_le(&mut h, words);
    *h.finalize().as_bytes()
}

/// Circuit-side digest that mirrors EXACTLY the host commitment order/bytes.
/// This must match `host_public_digest` in `src/lib.rs`.
pub fn circuit_public_digest(sp: &StarkProofPublic) -> [u8; 32] {
    let mut h = Hasher::new();
    // 1) pi digest
    h.update(&sp.pi_digest);
    // 2) fri roots (raw 32B each)
    for r in &sp.fri_roots {
        h.update(r);
    }
    // 3) fri challenges (u64 LE)
    for &c in &sp.fri_challenges {
        h.update(&c.to_le_bytes());
    }
    // 4) queries: index (u64 LE), layer_values (u64 LE each), openings (val u64 LE + root 32B)
    for q in &sp.queries {
        h.update(&(q.index as u64).to_le_bytes());
        for &v in &q.layer_values {
            h.update(&v.to_le_bytes());
        }
        for (mp, val) in q.openings.iter() {
            h.update(&(*val).to_le_bytes());
            h.update(&mp.root);
        }
    }
    // 5) final polynomial
    h.update(&sp.final_poly_root);
    for &c in &sp.final_poly_coeffs {
        h.update(&c.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_public_digest;
    use eezo_prover::stark_snark_prep::{prepare_for_snark};
    use eezo_prover::proof::prove;
    use eezo_prover::trace::Trace;
    use eezo_prover::air_spec::AirSpec;

    #[test]
    fn circuit_digest_matches_host_commitment() {
        // minimal 1-row trace to satisfy prover scaffold
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let proof = prove(&t, &a);
        let sp = prepare_for_snark(&proof);

        // host-side digest (defined in lib.rs)
        let host = host_public_digest(&sp);
        // circuit-side digest (over packed words)
        let circ = circuit_public_digest(&sp);

        // For the prototype, both must be equal. This guarantees that when we
        // replace this with a true in-circuit gadget, the public commitment
        // stays identical.
        assert_eq!(host, circ, "circuit digest must match host commitment");
    }

    #[test]
    fn circuit_digest_tamper_detects() {
        // minimal 1-row trace
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let proof = prove(&t, &a);
        let mut sp = prepare_for_snark(&proof);

        let good = circuit_public_digest(&sp);

        // tamper one byte of a root
        if let Some(first) = sp.fri_roots.first_mut() {
            first[0] ^= 1;
        }
        let bad = circuit_public_digest(&sp);

        assert_ne!(good, bad, "tampering must change the digest");
    }
}
