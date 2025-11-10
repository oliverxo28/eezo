#![cfg(feature = "plonk_kzg")]

// Placeholder types for PLONK-KZG backend.
// Later these will wrap halo2/arkworks concrete types.

#[derive(Clone, Debug)]
pub struct PlonkPk {
    pub bytes: Vec<u8>, // proving key bytes
}

#[derive(Clone, Debug)]
pub struct PlonkVk {
    pub bytes: Vec<u8>, // verifying key bytes
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkProof {
    pub bytes: Vec<u8>, // proof bytes
}
