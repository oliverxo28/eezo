#![cfg(feature = "stark-air")]

// T38.3 — minimal Goldilocks field helpers for AIR paths.
// We model F as u64 with arithmetic mod p = 2^64 - 2^32 + 1.
// NOTE: This is a tiny, local helper for tests/prototyping (no external dep).

/// Goldilocks modulus p = 2^64 - 2^32 + 1
pub const MOD: u128 = 0x1_0000_0000_0000_0000u128 - 0x1_0000_0000u128 + 1u128; // 2^64 - 2^32 + 1

/// Field element (stored as canonical u64).
pub type F = u64;

/// Canonicalize an arbitrary 128-bit value into [0, p).
#[inline]
pub fn reduce_u128(x: u128) -> F {
    // goldilocks fast reduction:
    // split x = lo + hi*2^64. since 2^64 ≡ 2^32 - 1 (mod p),
    // x ≡ lo + hi*(2^32 - 1) = lo + (hi<<32) - hi
    let lo = x as u64 as u128;
    let hi = (x >> 64) as u64 as u128;
    let t = lo + (hi << 32) - hi;
    // t may be in [-(2^64), 2^64 + something]; normalize with two folds.
    let mut y = t;
    // bring into a small positive range by adding MOD if negative (underflow in two's complement)
    if (y as i128) < 0 {
        y = y.wrapping_add(MOD);
    }
    // final conditional subtract to land in [0, MOD)
    let mut z = y;
    if z >= MOD { z -= MOD; }
    if z >= MOD { z -= MOD; }
    z as u64
}

#[inline]
pub fn add(a: F, b: F) -> F {
    let s = (a as u128) + (b as u128);
    reduce_u128(s)
}

#[inline]
pub fn sub(a: F, b: F) -> F {
    // a - b mod p
    if a >= b { a - b } else { (a as u128 + MOD - b as u128) as u64 }
}

#[inline]
pub fn mul(a: F, b: F) -> F {
    let m = (a as u128) * (b as u128);
    reduce_u128(m)
}

#[inline]
pub fn from_u64(x: u64) -> F { reduce_u128(x as u128) }

#[inline]
pub fn from_byte(b: u8) -> F { b as u64 }

#[inline]
pub fn to_byte(x: F) -> u8 { (x & 0xFF) as u8 }

/// Pack bytes (little-endian) into limbs with `limb_bits` per limb (use 8 for now).
#[inline]
pub fn pack_le(bytes: &[u8], limb_bits: usize) -> Vec<F> {
    assert!(limb_bits == 8, "only 8-bit limbs supported in T38.3");
    bytes.iter().map(|&b| from_byte(b)).collect()
}

/// Unpack limbs (8-bit) back to bytes (tests only).
#[inline]
pub fn unpack_le_8(limbs: &[F]) -> Vec<u8> {
    limbs.iter().map(|&x| to_byte(x)).collect()
}

/// Assert "bitness" in the field: x ∈ {0,1}. (used later for bit-columns)
#[inline]
pub fn assert_bit(x: F) -> bool {
    // x*(x-1) == 0 in the field
    mul(x, sub(x, from_u64(1))) == 0
}

/// Boolean XOR in a field: a ⊕ b = a + b - 2ab
#[inline]
pub fn xor_bool(a: F, b: F) -> F {
    sub(add(a, b), mul(from_u64(2), mul(a, b)))
}

/// Software 32-bit rotate-right (utility for tests & witnesses).
#[inline]
pub fn rotr32(x: u32, k: u32) -> u32 {
    x.rotate_right(k)
}
