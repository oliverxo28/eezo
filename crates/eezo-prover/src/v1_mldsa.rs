//! V1.1 ML-DSA batch-verification circuit (Bridge V1.1)
//!
//! This module defines the public-input layout and stub for the
//! STARK circuit that verifies a batch of ML-DSA-44 signatures.
//! The actual field arithmetic / NTT logic will be filled in
//! when the STARK backend is integrated.

use anyhow::Result;
use blake3::Hasher;
use eezo_crypto::suite::CryptoSuite;

/// Public inputs for circuitVersion = 2 (bridge V1.1)
/// T34.2: extended with `suite_id` (binds rotation) and `chain_id20`.
#[derive(Clone, Debug)]
pub struct PublicInputsV2 {
    pub circuit_version: u32,   // always 2
    pub height: u64,            // block height proved
    pub tx_root_v2: [u8; 32],   // transaction root
    pub state_root_v2: [u8; 32],
    pub sig_batch_digest: [u8; 32],
    pub batch_len: u32,
    /// EVM-style chain id (20 bytes) bound in the proof → contract checks.
    pub chain_id20: [u8; 20],
    /// Crypto suite used to produce/verify anchors at this height.
    /// Must be `CryptoSuite::MlDsa44.as_id()` for this ML-DSA circuit.
    pub suite_id: u32,
}

/// Compute a deterministic digest over a batch of signatures.
/// Used both by prover and verifier as the binding input.
pub fn compute_sig_batch_digest<'a, I>(triples: I) -> [u8; 32]
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8], &'a [u8])>,
{
    let mut h = Hasher::new();
    for (pk, msg, sig) in triples {
        h.update(pk);
        h.update(msg);
        h.update(sig);
    }
    *h.finalize().as_bytes()
}

/// Stub proving entrypoint: accepts the public inputs and the batch
/// of (pk, msg, sig) tuples; returns placeholder proof bytes.
///
/// Later this will build the real STARK trace with NTT gadgets.
pub fn prove_mldsa_batch<'a, I>(
    pis: &PublicInputsV2,
    batch: I,
) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8], &'a [u8])>,
{
    // placeholder: recompute digest for logging
    let _digest = compute_sig_batch_digest(batch);
    // serialize dummy proof with version + height only
    let mut proof = Vec::new();
    proof.extend_from_slice(&pis.circuit_version.to_le_bytes());
    proof.extend_from_slice(&pis.height.to_le_bytes());
    Ok(proof)
}

impl PublicInputsV2 {
    /// Construct a well-formed PI for ML-DSA-44 (suite is enforced here).
    pub fn for_mldsa44(
        height: u64,
        tx_root_v2: [u8; 32],
        state_root_v2: [u8; 32],
        sig_batch_digest: [u8; 32],
        batch_len: u32,
        chain_id20: [u8; 20],
    ) -> Self {
        Self {
            circuit_version: 2,
            height,
            tx_root_v2,
            state_root_v2,
            sig_batch_digest,
            batch_len,
            chain_id20,
            suite_id: u32::from(CryptoSuite::MlDsa44.as_id()),
        }
    }

    /// ABI shape expected by the EezoLightClient v2 path (Solidity):
    /// (uint32,uint64,bytes32,bytes32,bytes32,uint32,bytes20,uint32)
    /// = (circuit_version,height,tx_root_v2,state_root_v2,sig_batch_digest,batch_len,chain_id20,suite_id)
	#[allow(clippy::type_complexity)]
    pub fn as_abi_tuple(&self) -> (
        u32, u64, [u8;32], [u8;32], [u8;32], u32, [u8;20], u32
    ) {
        (
            self.circuit_version,
            self.height,
            self.tx_root_v2,
            self.state_root_v2,
            self.sig_batch_digest,
            self.batch_len,
            self.chain_id20,
            self.suite_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_stable() {
        let triples = [(&[1u8][..], &[2u8][..], &[3u8][..])];
        let d1 = compute_sig_batch_digest(triples);
        let d2 = compute_sig_batch_digest([(&[1u8][..], &[2u8][..], &[3u8][..])]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn prove_stub_runs() {
        let pis = PublicInputsV2::for_mldsa44(
            123,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            1,
            [0u8; 20],
        );
        let proof = prove_mldsa_batch(&pis, [(&[1u8][..], &[2u8][..], &[3u8][..])]).unwrap();
        assert!(!proof.is_empty());
    }

    #[test]
    fn abi_tuple_layout() {
        let pis = PublicInputsV2::for_mldsa44(
            42,
            [1u8;32],
            [2u8;32],
            [3u8;32],
            4,
            [9u8;20],
        );
        let tup = pis.as_abi_tuple();
        assert_eq!(tup.0, 2);
        assert_eq!(tup.1, 42);
        assert_eq!(tup.5, 4);
        assert_eq!(tup.6, [9u8;20]);
        assert_eq!(tup.7, u32::from(CryptoSuite::MlDsa44.as_id()));
    }
}
