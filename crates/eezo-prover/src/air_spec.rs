// (c) eezo — T38.1 AIR spec scaffold (no dependencies, no wiring yet)
#![allow(dead_code)]
//! minimal, conflict-free AIR spec for T38.1.
//! this mirrors current PI v2 & SSZ/blake3 rules exactly (phase-0 semantics).
//!
//! sources:
//! - pi packing: crates/eezo-prover/src/pi_builder.rs
//! - header layout: crates/ledger/src/block.rs
//! - checkpoint fields: crates/ledger/src/checkpoints.rs
//! - ssz rules & hash: crates/serde/src/eth/{encode,hash,decode}.rs + ssz.rs
//! - ledger ssz facade: crates/ledger/src/eth_ssz.rs

// ========================================================================
//  T38.1 — AIR ABSORPTION SCHEDULE (FULL FORMAL SPEC)
// ========================================================================
//
//  This schedule is the authoritative definition of how the STARK trace
//  absorbs SSZ byte streams to recompute:
//      - txs_root_v2
//      - state_root_v2
//      - legacy header HTR
//      - enforce PI boundary consistency
//
//  All absorption happens through a Blake3-like sponge (8 lanes), and
//  StepKind tells the AIR which kind of bytes are entering at each row.
//
// ------------------------------------------------------------------------
//  ROW PHASES
// ------------------------------------------------------------------------
//
//  [0] INIT
//      - height, suite_id, circuit_version set as constants
//      - blake3 lanes = IV
//      - no bytes absorbed
//
//  [1] TX VECTOR ROOT v2
//      (a) absorb vec length:   len:u32 LE   (4 bytes)
//      (b) absorb each sorted leaf:
//              leaf_i[0..31]   (32 bytes)
//          leaves must satisfy lexicographic ordering
//          StepKind = TxsVecLen (1) and TxsLeaf (2)
//
//  [2] STATE ROOT v2
//      (a) absorb pair length:  02 00 00 00  (4 bytes)
//      (b) absorb accounts_root (32 bytes)
//      (c) absorb supply_root   (32 bytes)
//          StepKind = StateLen (3), StateA (4), StateB (5)
//
//  [3] LEGACY HEADER HTR (NON-v2)
//      absorb in EXACT order:
//          height        (u64 LE)
//          prev_hash     (32 bytes)
//          tx_root       (legacy SHA3, 32 bytes)
//          fee_total     (u128 LE)
//          tx_count      (u32 LE)
//          timestamp_ms  (u64 LE)
//          [qc_hash?]    (32 bytes only if checkpoint feature)
//
//      All absorbed into a SEPARATE Blake3 sponge (HTR lanes).
//
//  [4] FINALIZE
//      StepKind = Finalize (200)
//      Enforce boundary constraints:
//          - txs_root_v2 sponge_final   == PI.txs_root_v2
//          - state_root_v2 sponge_final == PI.state_root_v2
//          - header_htr_final           == PI.header_hash
//          - sig_batch_digest (from PI) matches PI.sig_batch_digest
//          - height constant and matches PI.height
//
//  [5] PAD ROWS
//      StepKind = Pad (255)
//      Identity transition:
//          - blake3 lanes unchanged
//          - constants unchanged
//          - no bytes absorbed
//
// ------------------------------------------------------------------------
//  BYTE ORDERING (CRITICAL)
// ------------------------------------------------------------------------
//
//  SSZ encoder rules (mirrored exactly):
//      - u32, u64, u128 = little-endian
//      - [u8;32], [u8;20] = raw dump
//      - Vec<T> = len:u32 LE || items...
//      - Option<T> = flag:u8 || item
//
//  txs_root_v2:
//      SSZ(bytes) = u32(len) || sorted( per_tx_root[32]... )
//
//  state_root_v2:
//      SSZ(bytes) = u32(2) || accounts_root[32] || supply_root[32]
//
//  header HTR:
//      SSZ(bytes) over legacy fields in order (above)
//
// ------------------------------------------------------------------------
//  ROW EXAMPLE (BLOCK WITH 2 TXS)
// ------------------------------------------------------------------------
//
//      0   INIT
//      1   TX_VEC_LEN (4 bytes)
//      2   TX_LEAF_0 (32 bytes)
//      3   TX_LEAF_1 (32 bytes)
//      4   STATE_LEN (4 bytes)
//      5   STATE_A (32 bytes)
//      6   STATE_B (32 bytes)
//      7   HDR::height (8 bytes)
//      8   HDR::prev_hash (32 bytes)
//      9   HDR::tx_root_legacy (32 bytes)
//     10   HDR::fee_total (16 bytes)
//     11   HDR::tx_count (4 bytes)
//     12   HDR::timestamp_ms (8 bytes)
//     13   FINALIZE
//     14.. pad rows (identity)
//
// ------------------------------------------------------------------------
//  TRANSITION RULE SUMMARY
// ------------------------------------------------------------------------
//
//  For each row i:
//      - If absorbing bytes, update Blake3 lanes deterministically.
//      - Height/Suite/CircuitVer remain constant.
//      - Sorted leaves must satisfy leaf_i <= leaf_(i+1).
//      - At FINALIZE: enforce boundary equalities.
//      - PAD rows keep state identical.
//
// ========================================================================

/// public inputs as consumed by the AIR boundary (aligned to current v2 packing).
#[derive(Debug, Clone)]
pub struct AirPiV2 {
    pub chain_id20: [u8; 20],
    pub height: u64,
    pub parent_hash: [u8; 32],
    pub txs_root_v2: [u8; 32],
    pub state_root_v2: [u8; 32],
    pub sig_batch_digest: [u8; 32],
    pub suite_id: u8,
    pub circuit_version: u8,
}

/// column identifiers for the per-block execution trace.
#[repr(u16)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum Col {
    // invariants / constants
    Height = 0,
    SuiteId,
    CircuitVer,

    // blake3 sponge lanes for byte-accurate SSZ hashing (phase-0)
    // we abstract as 8 lanes; actual arith constraints to be filled in T38.2.
    B3_0, B3_1, B3_2, B3_3, B3_4, B3_5, B3_6, B3_7,

    // tx_root_v2 builder (sorted vector-of-[u8;32])
    TxVecLenLE32,       // little-endian u32 length (bytes 0..3)
    TxVecCursor,        // which 32B leaf we’re on
    TxVecLeaf0, TxVecLeaf1, TxVecLeaf2, TxVecLeaf3, // 32 bytes (4×u64 lanes if needed)

    // state_root_v2 builder ([accounts_root, supply_root] as SSZ vec)
    StatePairLenLE32,   // always 2 as u32 LE
    StateA0, StateA1, StateA2, StateA3,
    StateB0, StateB1, StateB2, StateB3,

    // running header HTR (legacy fields digest)
    Htr_0, Htr_1, Htr_2, Htr_3,

    // step tagging
    StepKind,           // 0=init, 1=txs_len, 2=txs_leaf, 3=state_len, 4=state_a, 5=state_b, 200=finalize, 255=pad
}

/// per-row step kinds; keeps witness construction unambiguous.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Step {
    Init = 0,
    // txs gadget (T38.4)
    TxsLen = 1,
    TxsLeaf = 2,
    // state gadget
    StateLen = 3,
    StateA = 4,
    StateB = 5,
    // end
    Finalize = 200,
    Pad = 255,
}

/// boundary conditions the prover must satisfy at row 0 and last row.
#[derive(Debug, Clone)]
pub struct Boundary {
    pub row0_parent_hash: [u8; 32],
    pub row_last_header_htr: [u8; 32],
    pub row_last_txs_root_v2: [u8; 32],
    pub row_last_state_root_v2: [u8; 32],
    pub row_last_sig_batch_digest: [u8; 32],
}

/// static parameters chosen for phase-0 AIR (tunable in later tasks).
pub mod params {
    /// field choice is deferred to T38.3; for now we size the trace only.
    pub const BLOWUP: usize = 8;
    /// upper bound for rows per block; padded to next power-of-two (prover sets actual).
    pub const MAX_ROWS_PER_BLOCK: usize = 1 << 16;
}

/// english spec (concise) of the transition rules we will formalize in T38.2:
pub mod rules {
    //! * Height, SuiteId, CircuitVer: constant within a block.
    //! * Blake3 lanes evolve deterministically over the exact SSZ byte stream:
    //!   - `txs_root_v2`: bytes = `len:u32 LE` || sorted( per_tx_root[32]... )
    //!   - `state_root_v2`: bytes = `2:u32 LE` || A[32] || B[32]
    //! * StepKind encodes which byte-chunk is absorbed at each row.
    //! * Finalize row enforces:
    //!   - sponge tag == PI.txs_root_v2 for the txs machine
    //!   - sponge tag == PI.state_root_v2 for the state machine
    //!   - HTR lanes == legacy-header digest (recomputed)
    //!   - `sig_batch_digest == PI.sig_batch_digest`
}
// ========================================================================
//  T38.5 — minimal AirSpec shim (feature-gated, zero conflict)
// ========================================================================
#[cfg(feature = "stark-air")]
#[derive(Clone, Debug, Default)]
pub struct AirSpec {
    // later we can attach real PI & boundary references
}

#[cfg(feature = "stark-air")]
impl AirSpec {
    /// placeholder — real version will return packed PI v2 hash or struct
    pub fn public_inputs_v2(&self) -> u64 {
        1 // deterministic non-zero dummy
    }
}

