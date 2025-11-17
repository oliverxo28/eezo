#![cfg(feature = "snark-mini")]

use crate::transcript::circuit_public_digest;
use crate::prove::SnarkProof;
use eezo_prover::stark_snark_prep::StarkProofPublic;

/// “Verify” by recomputing the circuit commitment and comparing to the proof.
pub fn verify_public(sp: &StarkProofPublic, proof: &SnarkProof) -> bool {
    circuit_public_digest(sp) == proof.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prove::prove_public;
    use eezo_prover::stark_snark_prep::prepare_for_snark;
    use eezo_prover::proof::prove;
    use eezo_prover::trace::Trace;
    use eezo_prover::air_spec::AirSpec;

    #[test]
    fn snark_roundtrip_test() {
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let stark = prove(&t, &a);
        let sp = prepare_for_snark(&stark);

        let pf = prove_public(&sp);
        assert!(verify_public(&sp, &pf), "roundtrip verify must succeed");
    }

    #[test]
    fn snark_tamper_breaks_test() {
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let stark = prove(&t, &a);
        let mut sp = prepare_for_snark(&stark);

        let pf = prove_public(&sp);
        assert!(verify_public(&sp, &pf));

        // tamper one byte → verify must fail
        if let Some(first) = sp.fri_roots.first_mut() {
            first[0] ^= 1;
        }
        assert!(!verify_public(&sp, &pf), "tampering must be detected by verify");
    }

    #[test]
    fn snark_replay_test() {
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let stark = prove(&t, &a);
        let sp = prepare_for_snark(&stark);

        let p1 = prove_public(&sp);
        let p2 = prove_public(&sp);
        assert_eq!(p1, p2, "same inputs must produce identical proof object");
    }
}
