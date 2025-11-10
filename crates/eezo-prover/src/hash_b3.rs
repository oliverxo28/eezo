#![cfg(feature = "stark-air")]

// ======================================================================
// T38.3 — BLAKE3 state_root_v2 gadget skeleton
// Minimal structure only; no real algebraic constraints yet.
// This file is safe, compiling, and ready for incremental filling.
// ======================================================================

use crate::field::{rotr32};

/// Witness data for the state_root_v2 BLAKE3 gadget.
/// For now this only contains the final digest bytes.
/// Later we will add per-round lanes, word ops, etc.
#[derive(Clone, Debug)]
pub struct DigestWitness {
    pub digest: [u8; 32],
}

/// Build the *witness* for the state_root_v2 digest.
/// For T38.3 step-2, this simply uses software BLAKE3.
/// Later milestones will produce per-round algebraic witnesses.
pub fn prove_state_root_digest(state_bytes: &[u8]) -> DigestWitness {
    // software reference hash for now
    let digest = blake3::hash(state_bytes).as_bytes().clone();

    DigestWitness { digest }
}

/// Enforce the algebraic constraints for the state_root_v2 gadget.
/// For T38.3 step-2 this is a **stub** and always passes.
/// In later steps we will verify add/xor/rot transitions and the lanes.
pub fn enforce_state_root_constraints(
    _rows: &mut [crate::trace::Row],
    _w: &DigestWitness,
) -> Result<(), &'static str> {
    // T38.3 phase-0: no constraints yet
    Ok(())
}

/// In later steps this will map the digest witness into final trace lanes.
/// For now we leave only a stub (called by witness builder).
pub fn place_digest_into_trace(
    _row: &mut crate::trace::Row,
    _w: &DigestWitness,
) {
    // Will fill during T38.3 → T38.4
}
// ======================================================================
// T38.3 phase-3 — first algebraic step (byte-aligned rotations)
//
// We enforce/validate the equivalence of 32-bit ROTR by 8 and 16 using
// a byte-lane rewire. This is a true algebraic identity at the limb
// (8-bit) level and requires no bit gadgets. ROTR by 12 and 7 will come
// later with bit-slicing.
// ======================================================================

#[inline]
fn u32_to_be_bytes(x: u32) -> [u8;4] { x.to_be_bytes() }

#[inline]
fn be_bytes_to_u32(b: [u8;4]) -> u32 { u32::from_be_bytes(b) }

/// Rotate-right by k ∈ {8,16} using byte-lane rewiring in BE order.
/// (We pick BE for a canonical limb order; choice is arbitrary as long as tests match.)
fn rotr_bytes_8_or_16_be(x: u32, k: u32) -> u32 {
    debug_assert!(k == 8 || k == 16);
    let mut v = u32_to_be_bytes(x);
    // rotr 8:  [b0,b1,b2,b3] -> [b3,b0,b1,b2]
    // rotr16: [b0,b1,b2,b3] -> [b2,b3,b0,b1]
    let out = match k {
        8  => [v[3], v[0], v[1], v[2]],
        16 => [v[2], v[3], v[0], v[1]],
        _  => unreachable!(),
    };
    be_bytes_to_u32(out)
}

/// Check that byte-lane rotation equals software rotate_right for k ∈ {8,16}.
pub fn check_rotr8_16_consistency(x: u32) -> bool {
    let r8_sw  = rotr32(x, 8);
    let r8_lm  = rotr_bytes_8_or_16_be(x, 8);
    let r16_sw = rotr32(x, 16);
    let r16_lm = rotr_bytes_8_or_16_be(x, 16);
    r8_sw == r8_lm && r16_sw == r16_lm
}

/// A tiny "mini-round" identity we can validate now without bit-gadgets:
/// x' = (x + y) ^ z (in 32-bit software), then ensure ROTR by {8,16}
/// matches the byte-lane rewire model above.
pub fn check_add_xor_then_rotr8_16(x: u32, y: u32, z: u32) -> bool {
    let x1 = x.wrapping_add(y) ^ z;
    check_rotr8_16_consistency(x1)
}
