#![cfg(feature = "stark-air")]

// T38.2 — mock trace builder (no real hashing yet).
// Builds rows in the exact absorption order from the AIR spec,
// but uses a stub sponge (we'll replace in T38.3).
//
// T43.1 — GPU hashing lanes (v1 hookup).
// The *witness* values for state_root_v2 and txs_root_v2 are obtained
// via `prove_state_root_digest` and `prove_txs_root_digest`, which now
// internally use the BLAKE3 lanes abstraction (CPU-only today, GPU-ready
// in later T43.x tasks). The trace layout stays unchanged; only the
// hashing backend becomes lane-aware.

use crate::air_spec::{AirPiV2, Boundary, Col, Step};
use crate::hash_b3::prove_state_root_digest;
use crate::hash_b3_tx::prove_txs_root_digest;
use crate::trace::{Trace, Row};

#[inline]
fn idx(c: Col) -> usize { c as usize }

#[inline]
fn u32_le(n: u32) -> [u8; 4] { n.to_le_bytes() }

/// split 32 bytes into four u64 lanes (little-endian, 8 bytes each)
#[inline]
fn split32_to_u64x4(b: &[u8; 32]) -> [u64; 4] {
    let mut lanes = [0u64; 4];
    for i in 0..4 {
        let off = i * 8;
        lanes[i] = u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
    }
    lanes
}

#[inline]
fn set_htr_from_bytes(r: &mut Row, htr: &[u8;32]) {
    let lanes = split32_to_u64x4(htr);
    r.0[idx(Col::Htr_0)] = lanes[0];
    r.0[idx(Col::Htr_1)] = lanes[1];
    r.0[idx(Col::Htr_2)] = lanes[2];
    r.0[idx(Col::Htr_3)] = lanes[3];
}

/// Fill the invariant columns for a row.
#[inline]
fn set_block_constants(r: &mut Row, pi: &AirPiV2) {
    r.0[idx(Col::Height)] = pi.height as u64;
    r.0[idx(Col::SuiteId)] = pi.suite_id as u64;
    r.0[idx(Col::CircuitVer)] = pi.circuit_version as u64;
}

/// Build a mock trace per the absorption schedule (no hashing yet).
///
/// `sorted_tx_roots`: MUST be pre-sorted lexicographically (we'll assert this in constraints).
/// `state_pair`: (accounts_root, supply_root).
pub fn build_trace(
    pi: &AirPiV2,
    boundary: &Boundary,
    sorted_tx_roots: &[[u8; 32]],
    state_pair: ([u8; 32], [u8; 32]),
) -> Trace {
    let mut t = Trace::new();

    // ------------------------------------------------------------------
    // T38.3: state_root_v2 BLAKE3 gadget (phase-0)
    // Build the exact byte stream: len:u32 LE (=2), A[32], B[32]
    //
    // T43.1 note:
    //   `prove_state_root_digest` now routes through the BLAKE3 lanes
    //   abstraction (CPU-backed today, GPU-backed later), but the
    //   witness interface and trace layout remain identical.
    // ------------------------------------------------------------------
    let (accounts_root, supply_root) = state_pair;

    // len = 2 (two 32-byte elements)
    let mut state_bytes = Vec::with_capacity(4 + 32 + 32);
    state_bytes.extend_from_slice(&2u32.to_le_bytes());
    state_bytes.extend_from_slice(&accounts_root);
    state_bytes.extend_from_slice(&supply_root);

    // software digest → witness (used to place real digest into lanes)
    let state_witness = prove_state_root_digest(&state_bytes);

    // ------------------------------------------------------------------
    // T38.4 step-1: txs_root_v2 (variable-length SSZ vector) — software witness
    // digest = BLAKE3(len:u32 LE || leaf_0[32] || ... || leaf_n[32])
    // We'll place this digest into B3_0..3 at Finalize.
    //
    // T43.1 note:
    //   `prove_txs_root_digest` remains the single entrypoint for the
    //   tx-vector digest; in later T43.x we will refactor its internal
    //   hashing to also use the lanes abstraction for large batches.
    // ------------------------------------------------------------------
    let txs_witness = prove_txs_root_digest(sorted_tx_roots);

    // --------------------
    // [0] INIT
    // --------------------
    t.push_step(Step::Init, |r| {
        set_block_constants(r, pi);
        // Ensure boundary row-0 HTR is present for boundary checks.
        set_htr_from_bytes(r, &boundary.row0_parent_hash);
        
        // Set a recognizable mock IV for lanes (optional, any u64s are fine):
        r.0[idx(Col::B3_0)] = 0xEE00_0000u64;
        r.0[idx(Col::B3_1)] = 0xEE00_0001u64;
        r.0[idx(Col::B3_2)] = 0xEE00_0002u64;
        r.0[idx(Col::B3_3)] = 0xEE00_0003u64;
        r.0[idx(Col::B3_4)] = 0xEE00_0004u64;
        r.0[idx(Col::B3_5)] = 0xEE00_0005u64;
        r.0[idx(Col::B3_6)] = 0xEE00_0006u64;
        r.0[idx(Col::B3_7)] = 0xEE00_0007u64;
    });

    // ------------------------------------------------------------------
    // T38.4 step-3: explicit control-flow rows for tx vector
    //   TxsLen  → one row encoding the length (LE u32)
    //   TxsLeaf → one row per leaf with cursor + leaf lanes
    // ------------------------------------------------------------------
    t.push_step(Step::TxsLen, |r| {
        set_block_constants(r, pi);
        let len = sorted_tx_roots.len() as u32;
        let le = u32_le(len);
        r.0[idx(Col::TxVecLenLE32)] = u32::from_le_bytes(le) as u64;
        r.0[idx(Col::TxVecCursor)] = 0;
    });
    for (i, leaf) in sorted_tx_roots.iter().enumerate() {
        t.push_step(Step::TxsLeaf, |r| {
            set_block_constants(r, pi);
            let lanes = split32_to_u64x4(leaf);
            r.0[idx(Col::TxVecCursor)] = i as u64;
            r.0[idx(Col::TxVecLeaf0)] = lanes[0];
            r.0[idx(Col::TxVecLeaf1)] = lanes[1];
            r.0[idx(Col::TxVecLeaf2)] = lanes[2];
            r.0[idx(Col::TxVecLeaf3)] = lanes[3];
        });
    }

    // --------------------
    // [3] STATE_LEN = 2 (4 bytes LE)
    // --------------------
    t.push_step(Step::StateLen, |r| {
        set_block_constants(r, pi);
        r.0[idx(Col::StatePairLenLE32)] = 2u32 as u64; // store as u64; constraints know it's LE 2
    });

    // --------------------
    // [4] STATE_A (accounts_root, 32 bytes)
    // --------------------
    t.push_step(Step::StateA, |r| {
        set_block_constants(r, pi);
        let a = split32_to_u64x4(&accounts_root);
        r.0[idx(Col::StateA0)] = a[0];
        r.0[idx(Col::StateA1)] = a[1];
        r.0[idx(Col::StateA2)] = a[2];
        r.0[idx(Col::StateA3)] = a[3];
    });

    // --------------------
    // [5] STATE_B (supply_root, 32 bytes)
    // --------------------
    t.push_step(Step::StateB, |r| {
        set_block_constants(r, pi);
        let b = split32_to_u64x4(&supply_root);
        r.0[idx(Col::StateB0)] = b[0];
        r.0[idx(Col::StateB1)] = b[1];
        r.0[idx(Col::StateB2)] = b[2];
        r.0[idx(Col::StateB3)] = b[3];
    });
    // digest will be placed into lanes during FINALIZE (phase-1).

    // --------------------
    // [6] FINALIZE
    // In the mock, we simply copy PI+boundary outputs into the final row slots.
    // Constraints will compare these directly in T38.2 (no real hashing yet).
    // --------------------
    t.push_step(Step::Finalize, |r| {
        set_block_constants(r, pi);
        // Optional but nice: place expected final header HTR for boundary check symmetry.
        set_htr_from_bytes(r, &boundary.row_last_header_htr);

        // write the **real** txs_root_v2 digest (from txs_witness) into B3_0..3
        let tx = split32_to_u64x4(&txs_witness.digest);
        // and write the **real** state_root_v2 digest (from witness) into B3_4..7
        let st = split32_to_u64x4(&state_witness.digest);
        // convention: B3_0..3 = txs_root_v2 ; B3_4..7 = state_root_v2 (real digest)
        r.0[idx(Col::B3_0)] = tx[0];
        r.0[idx(Col::B3_1)] = tx[1];
        r.0[idx(Col::B3_2)] = tx[2];
        r.0[idx(Col::B3_3)] = tx[3];
        r.0[idx(Col::B3_4)] = st[0];
        r.0[idx(Col::B3_5)] = st[1];
        r.0[idx(Col::B3_6)] = st[2];
        r.0[idx(Col::B3_7)] = st[3];
    });

    t
}