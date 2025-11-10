//! Constant-time helpers (safe, no `unsafe`).

/// XOR `a` and `b` into `dst`. Slices must be the same length.
pub fn xor_into(dst: &mut [u8], a: &[u8], b: &[u8]) {
    assert_eq!(dst.len(), a.len(), "xor_into: length mismatch");
    assert_eq!(dst.len(), b.len(), "xor_into: length mismatch");
    for (d, (&x, &y)) in dst.iter_mut().zip(a.iter().zip(b.iter())) {
        *d = x ^ y;
    }
}

/// Constant-time select between two equal-length byte slices into `dst`.
/// If `mask` is 0xFF selects `x`; if `mask` is 0x00 selects `y`.
pub fn ct_select_into(dst: &mut [u8], x: &[u8], y: &[u8], mask: u8) {
    assert_eq!(dst.len(), x.len(), "ct_select_into: length mismatch");
    assert_eq!(dst.len(), y.len(), "ct_select_into: length mismatch");
    let not = !mask;
    for i in 0..dst.len() {
        dst[i] = (x[i] & mask) | (y[i] & not);
    }
}