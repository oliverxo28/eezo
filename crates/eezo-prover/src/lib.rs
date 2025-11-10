pub mod v1_mldsa;

// === T37.4: Automatic proving pipeline modules ===
pub mod pi_builder;
pub mod proof_writer;
pub mod prover_loop;
pub mod metrics;
// === T38.1: STARK AIR design spec (pure spec, no execution yet) ===
#[cfg(feature = "stark-air")]
pub mod air_spec;
// === T38.3: Goldilocks field helpers ===
#[cfg(feature = "stark-air")]
pub mod field;
// === T38.2: Trace container (mock witness rows) ===
#[cfg(feature = "stark-air")]
pub mod trace;
// === T38.2: Witness builder (absorption schedule; stub sponge) ===
#[cfg(feature = "stark-air")]
pub mod witness;
// === T38.2: Basic constraints (constant cols, sorted leaves, boundary) ===
#[cfg(feature = "stark-air")]
pub mod constraints;
// ✅ T38.3: expose BLAKE3 gadget skeleton
#[cfg(feature = "stark-air")]
pub mod hash_b3;
// T38.4 — txs_root_v2 gadget (variable-length SSZ vector)
#[cfg(feature = "stark-air")]
pub mod hash_b3_tx;
// === T38.5: STARK domain (evaluation domain + LDE) ===
#[cfg(feature = "stark-air")]
pub mod domain;
// === T38.5: Polynomial backend (interpolation + LDE evaluation) ===
#[cfg(feature = "stark-air")]
pub mod poly;
// === T38.5: Merkle commitments (trace + constraints + FRI layers) ===
#[cfg(feature = "stark-air")]
pub mod merkle;
// === T38.5: FRI folding engine ===
#[cfg(feature = "stark-air")]
pub mod fri;
// === T38.5: End-to-end STARK proof generator ===
#[cfg(feature = "stark-air")]
pub mod proof;
// === T38.6: Verifier scaffold (matches current proof format) ===
#[cfg(feature = "stark-air")]
pub mod verify;
// === T38.6: Proof encoding (binary, versioned) ===
#[cfg(feature = "stark-air")]
pub mod proof_encoding;
#[cfg(feature = "stark-air")]
pub mod pi_canonical;
#[cfg(feature = "stark-air")]
pub mod stark_snark_prep;




