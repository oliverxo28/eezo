use crate::air_spec::{AirPiV2, Boundary, Col, Step};
use crate::trace::Trace;
use crate::hash_b3::{DigestWitness, enforce_state_root_constraints};
use crate::hash_b3_tx::{TxsWitness, enforce_txs_root_constraints};

#[inline]
fn idx(c: Col) -> usize { c as usize }

/// Check that given columns are constant across all rows.
pub fn assert_constant_cols(trace: &Trace, cols: &[Col]) -> Result<(), &'static str> {
    if trace.rows.is_empty() { return Err("trace empty"); }
    for &c in cols {
        let first = trace.rows[0].0[idx(c)];
        for (_i, r) in trace.rows.iter().enumerate().skip(1) { // <-- FIXED: unused variable `i`
            if r.0[idx(c)] != first {
                return Err(match c {
                    Col::Height => "height not constant",
                    Col::SuiteId => "suite_id not constant",
                    Col::CircuitVer => "circuit_version not constant",
                    _ => "column not constant",
                });
            }
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------
// T38.3 phase-2 (prep): ensure the expected step order for state bytes.
// We don't enforce algebra yet; just verify that the witness built rows
// in the intended sequence: StateLen -> StateA -> StateB -> Finalize.
// ----------------------------------------------------------------------
pub fn assert_state_step_sequence(trace: &Trace) -> Result<(), &'static str> {
    if trace.rows.is_empty() { return Err("trace empty"); }
    let mut seen_len = false;
    let mut seen_a = false;
    let mut seen_b = false;
    for r in &trace.rows {
        let k = r.0[idx(Col::StepKind)] as u64;
        if k == Step::StateLen as u64 {
            if seen_len { return Err("duplicate StateLen"); }
            if seen_a || seen_b { return Err("StateLen after StateA/StateB"); }
            seen_len = true;
        } else if k == Step::StateA as u64 {
            if !seen_len { return Err("StateA before StateLen"); }
            if seen_a { return Err("duplicate StateA"); }
            if seen_b { return Err("StateA after StateB"); }
            seen_a = true;
        } else if k == Step::StateB as u64 {
            if !seen_a { return Err("StateB before StateA"); }
            if seen_b { return Err("duplicate StateB"); }
            seen_b = true;
        } else if k == Step::Finalize as u64 && (!seen_len || !seen_a || !seen_b) { // <-- FIXED: simplified condition
            return Err("Finalize before completing state sequence");
        }
    }
    if !(seen_len && seen_a && seen_b) {
        return Err("incomplete state sequence");
    }
    Ok(())
}
/// T38.4 — tx path step sequence:
/// expects: TxsLen → (TxsLeaf)* → ... → Finalize (order only; count is free-form)
pub fn assert_txs_step_sequence(trace: &Trace) -> Result<(), &'static str> {
    if trace.rows.is_empty() { return Err("trace empty"); }
    let mut saw_len = false;
    for r in trace.rows.iter() {
        let k = r.0[idx(Col::StepKind)] as u64;
        match k {
            k if k == Step::TxsLen as u64 => {
                if saw_len { return Err("multiple TxsLen encountered"); }
                saw_len = true;
            }
            k if k == Step::TxsLeaf as u64 => {
                if !saw_len { return Err("TxsLeaf before TxsLen"); }
            }
            k if k == Step::Finalize as u64 => break,
            _ => {}
        }
    }
    if !saw_len { return Err("missing TxsLen"); }
    Ok(())
}

// ======================================================================
// T38.3 — state_root_v2 BLAKE3 gadget (phase-0, stub constraints)
// This verifies nothing yet; it only wires the witness into the constraint
// layer so tests and future milestones can call it.
// ======================================================================
pub fn assert_state_root_gadget(
    trace: &mut Trace,
    w: &DigestWitness,
) -> Result<(), &'static str> {
    // In T38.3 phase-0 this simply calls the stub in hash_b3.rs
    // which always returns Ok(()).
    enforce_state_root_constraints(&mut trace.rows[..], w)
}
/// T38.4 — txs_root_v2 gadget assertion (currently a stub that calls into
/// `hash_b3_tx::enforce_txs_root_constraints`, which is Ok(()) for now).
pub fn assert_txs_root_gadget(
    trace: &mut Trace,
    w: &TxsWitness,
) -> Result<(), &'static str> {
    enforce_txs_root_constraints(&mut trace.rows[..], w)
}
/// Lexicographic (byte-wise) compare a <= b.
#[inline]
fn le_bytes32(a: &[u8;32], b: &[u8;32]) -> bool {
    for k in 0..32 {
        if a[k] < b[k] { return true; }
        if a[k] > b[k] { return false; }
    }
    true
}

/// Ensure leaves are non-decreasing lexicographically.
pub fn assert_sorted_leaves(leaves: &[[u8;32]]) -> Result<(), &'static str> {
    if leaves.is_empty() { return Ok(()); }
    for i in 0..(leaves.len().saturating_sub(1)) {
        if !le_bytes32(&leaves[i], &leaves[i+1]) {
            return Err("tx roots not sorted (non-decreasing) at i/i+1");
        }
    }
    Ok(())
}

/// Boundary checks against first/last rows (mock layout per witness.rs).
pub fn assert_boundary(trace: &Trace, b: &Boundary, pi: &AirPiV2) -> Result<(), &'static str> {
    if trace.rows.is_empty() { return Err("trace empty"); }

    // row 0 must carry parent_hash in Htr_* lanes (mock convention)
    let r0 = &trace.rows[0].0;
    let mut r0_parent = [0u8;32];
    for (j, lane) in [Col::Htr_0, Col::Htr_1, Col::Htr_2, Col::Htr_3].iter().enumerate() {
        r0_parent[j*8..(j+1)*8].copy_from_slice(&r0[idx(*lane)].to_le_bytes()); // <-- FIXED: use `r0` instead of `trace.rows[0].0`
    }
    if r0_parent != b.row0_parent_hash { return Err("row0 parent hash mismatch"); }

    // last row must hold:
    // - header HTR in Htr_* lanes
    // - txs_root_v2 in B3_0..3
    // - state_root_v2 in B3_4..7
    let last = &trace.last().0;

    // header htr
    let mut htr = [0u8;32];
    for (j, lane) in [Col::Htr_0, Col::Htr_1, Col::Htr_2, Col::Htr_3].iter().enumerate() {
        htr[j*8..(j+1)*8].copy_from_slice(&last[idx(*lane)].to_le_bytes());
    }
    if htr != b.row_last_header_htr { return Err("final header HTR mismatch"); }

    // txs_root_v2
    let mut txv2 = [0u8;32];
    for (j, lane) in [Col::B3_0, Col::B3_1, Col::B3_2, Col::B3_3].iter().enumerate() {
        txv2[j*8..(j+1)*8].copy_from_slice(&last[idx(*lane)].to_le_bytes());
    }
    if txv2 != pi.txs_root_v2 { return Err("final txs_root_v2 mismatch"); }

    // state_root_v2
    let mut stv2 = [0u8;32];
    for (j, lane) in [Col::B3_4, Col::B3_5, Col::B3_6, Col::B3_7].iter().enumerate() {
        stv2[j*8..(j+1)*8].copy_from_slice(&last[idx(*lane)].to_le_bytes());
    }
    if stv2 != pi.state_root_v2 { return Err("final state_root_v2 mismatch"); }

    // sig batch digest equality (PI vs Boundary expectation)
    if pi.sig_batch_digest != b.row_last_sig_batch_digest {
        return Err("sig_batch_digest != boundary expectation");
    }

    Ok(())
}
// === T38.6.3: DEEP / constraint scalar composer (queryable) ===
/// Compose a single scalar from the row's key lanes.
/// Minimal, deterministic, and safe to evolve later.
#[inline]
pub fn compose_constraints_row(trace: &Trace, row: usize) -> u64 {
    let r = &trace.rows[row].0; // you already use this layout elsewhere
    // Simple linear combo over first few lanes; wrapping to mirror current math.
    let mut acc = 0u64;
    for (i, v) in r.iter().take(8).enumerate() {
        let w = (i as u64).wrapping_add(1);
        acc = acc.wrapping_add(v.wrapping_mul(w));
    }
    acc
}