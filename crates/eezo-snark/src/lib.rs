// T38.9 — eezo-snark: mini-circuit wrapper prototype (feature-gated)
//
// This crate intentionally keeps everything behind `snark-mini` so it has
// zero impact on production builds. We only depend on eezo-prover for the
// public STARK→SNARK interface types.

#![cfg(feature = "snark-mini")]

pub mod public;
pub mod transcript;
pub mod circuit;
pub mod prove;
pub mod verify;
// ✅ NEW: expose backend tree when plonk_kzg is enabled
#[cfg(feature = "plonk_kzg")]
pub mod backend;

// Re-export the core public types so downstream callers can depend on a
// single crate when wiring the wrapper.
pub use eezo_prover::stark_snark_prep::StarkProofPublic;

// A tiny helper: build the same host-side digest the circuit will bind to.
// This is NOT the final SNARK; it’s the agreed commitment that both
// host and circuit must reproduce bit-for-bit.
pub fn host_public_digest(sp: &StarkProofPublic) -> [u8; 32] {
    use blake3::Hasher;

    let mut h = Hasher::new();
    // pi digest
    h.update(&sp.pi_digest);
    // fri roots
    for r in &sp.fri_roots { h.update(r); }
    // challenges (LE)
    for &c in &sp.fri_challenges { h.update(&c.to_le_bytes()); }
    // queries (stable packing for the mini-circuit phase)
    for q in &sp.queries {
        h.update(&(q.index as u64).to_le_bytes());
        for &v in &q.layer_values { h.update(&v.to_le_bytes()); }
        for (mp, val) in &q.openings {
            h.update(&val.to_le_bytes());
            h.update(&mp.root); // minimal root-commit for proto (paths added later)
        }
    }
    // final poly
    h.update(&sp.final_poly_root);
    for &c in &sp.final_poly_coeffs { h.update(&c.to_le_bytes()); }

    *h.finalize().as_bytes()
}

// --- basic smoke test (gated) ---
#[cfg(test)]
mod tests {
    use super::*;
    use eezo_prover::stark_snark_prep::{prepare_for_snark, build_snark_transcript};
    use eezo_prover::proof::prove;
    use eezo_prover::trace::Trace;
    use eezo_prover::air_spec::AirSpec;

    #[test]
    fn host_digest_is_deterministic() {
        // minimal 1-row trace to satisfy prover scaffold
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let proof = prove(&t, &a);
        let sp = prepare_for_snark(&proof);

        let d1 = host_public_digest(&sp);
        let d2 = host_public_digest(&sp);
        assert_eq!(d1, d2, "host digest must be stable");

        // transcript builder still deterministic alongside
        let tr1 = build_snark_transcript(&sp);
        let tr2 = build_snark_transcript(&sp);
        assert_eq!(tr1, tr2, "prep transcript must be stable");
    }
}
