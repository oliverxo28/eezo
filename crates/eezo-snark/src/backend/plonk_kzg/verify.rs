#![cfg(feature = "plonk_kzg")]

use crate::backend::plonk_kzg::{PlonkProof, PlonkVk};
use crate::backend::plonk_kzg::keys::load_vk;
use crate::transcript::circuit_public_digest;
use eezo_prover::stark_snark_prep::StarkProofPublic;

/// Verify a placeholder proof using the digest embedded in proof bytes.
/// Real backend will perform pairing checks with VK here.
pub fn verify_plonk(sp: &StarkProofPublic, proof: &PlonkProof) -> bool {
    if proof.bytes.len() != 32 {
        return false;
    }
    let _vk: PlonkVk = load_vk().unwrap_or(PlonkVk { bytes: vec![0x11, 0x22] });

    let expected = circuit_public_digest(sp);
    proof.bytes == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::plonk_kzg::prove_plonk;
    use eezo_prover::stark_snark_prep::prepare_for_snark;
    use eezo_prover::proof::prove;
    use eezo_prover::trace::Trace;
    use eezo_prover::air_spec::AirSpec;

    #[test]
    fn plonk_verify_smoke() {
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let stark = prove(&t, &a);
        let sp = prepare_for_snark(&stark);

        let pf = prove_plonk(&sp);
        assert!(verify_plonk(&sp, &pf));
    }
}