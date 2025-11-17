#![cfg(feature = "plonk_kzg")]

use eezo_prover::stark_snark_prep::StarkProofPublic;

/// Circuit parameters placeholder (domain size knobs, hash params, etc.)
#[derive(Clone, Debug, Default)]
pub struct PlonkParams {
    pub max_queries: usize,
}

/// Circuit witness for the digest-consistency constraint.
/// Real circuit will expose advice/fixed columns and constraints.
#[derive(Clone, Debug)]
pub struct PlonkWitness {
    pub packed_inputs: Vec<u64>,   // from pack_public()
    pub expected_digest: [u8; 32], // host/circuit must match this
}

/// "Circuit" object (shape + params + witness). For halo2/arkworks you'll
/// implement the proper trait here (ConstraintSystem, Circuit, etc.).
#[derive(Clone, Debug)]
pub struct PlonkCircuit {
    pub params: PlonkParams,
    pub wit: PlonkWitness,
}

impl PlonkCircuit {
    pub fn new(sp: &StarkProofPublic, packed_words: &[u64], expected_digest: [u8; 32]) -> Self {
        let params = PlonkParams { max_queries: sp.queries.len() };
        let wit = PlonkWitness {
            packed_inputs: packed_words.to_vec(),
            expected_digest,
        };
        Self { params, wit }
    }
}