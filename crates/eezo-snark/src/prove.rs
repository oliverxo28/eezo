#![cfg(feature = "snark-mini")]

use crate::transcript::circuit_public_digest;
use eezo_prover::stark_snark_prep::StarkProofPublic;

/// Prototype proof object — just the 32-byte commitment for now.
/// (This type stays the same when we introduce a real backend.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnarkProof(pub [u8; 32]);

/// “Prove” by computing the circuit commitment over StarkProofPublic.
/// Later this will call the real SNARK backend to produce a succinct proof.
pub fn prove_public(sp: &StarkProofPublic) -> SnarkProof {
    SnarkProof(circuit_public_digest(sp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eezo_prover::stark_snark_prep::prepare_for_snark;
    use eezo_prover::proof::prove;
    use eezo_prover::trace::Trace;
    use eezo_prover::air_spec::AirSpec;

    #[test]
    fn snark_prove_produces_commitment() {
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let stark = prove(&t, &a);
        let sp = prepare_for_snark(&stark);

        let pf = prove_public(&sp);
        assert_ne!(pf.0, [0u8; 32], "proof commitment must be non-zero");
    }
}
