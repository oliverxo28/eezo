#![cfg(feature = "plonk_kzg")]

use crate::backend::plonk_kzg::{PlonkPk, PlonkProof};
use crate::backend::plonk_kzg::circuit::PlonkCircuit;
use crate::backend::plonk_kzg::keys::{load_crs_bytes, load_pk};
use crate::public::pack_public;
use crate::transcript::circuit_public_digest;
use eezo_prover::stark_snark_prep::StarkProofPublic;

/// Generate proving key from circuit (still stubbed).
pub fn generate_pk(_circuit: &PlonkCircuit) -> PlonkPk {
    // In a real backend, you would derive PK from CRS + circuit shape here.
    PlonkPk { bytes: vec![0xAA, 0xBB, 0xCC] }
}

/// Produce a placeholder proof today, but through real-shaped plumbing:
/// - read CRS
/// - build circuit
/// - load/derive PK
/// - return proof bytes (digest for now)
pub fn prove_plonk(sp: &StarkProofPublic) -> PlonkProof {
    let _crs = load_crs_bytes().expect("load CRS");
    let packed = pack_public(sp);
    let digest = circuit_public_digest(sp);

    let circuit = PlonkCircuit::new(sp, &packed.words, digest);
    let _pk = load_pk().unwrap_or_else(|_| generate_pk(&circuit));

    // T39.2 skeleton: embed digest as proof bytes (replace in T39.3 with real proof)
    PlonkProof { bytes: digest.to_vec() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eezo_prover::stark_snark_prep::prepare_for_snark;
    use eezo_prover::proof::prove;
    use eezo_prover::trace::Trace;
    use eezo_prover::air_spec::AirSpec;

    #[test]
    fn plonk_prove_smoke() {
        let mut t = Trace::new();
        t.push_row(0);
        let a = AirSpec::default();

        let stark = prove(&t, &a);
        let sp = prepare_for_snark(&stark);

        let pf = prove_plonk(&sp);
        assert_eq!(pf.bytes.len(), 32, "placeholder proof carries digest");
    }
}