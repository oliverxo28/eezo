/// Hash domain separation + constant-time helpers.

use eezo_crypto::hash::{sha3_256_domain, sha3_512_domain, blake3_domain};
use eezo_crypto::ct::{xor_into, ct_select_into};

#[test]
fn domain_separation_changes_digest() {
    let m = b"msg";

    let a1 = sha3_256_domain(b"tx", m);
    let a2 = sha3_256_domain(b"anchor", m);
    assert_ne!(a1, a2, "SHA3-256: domain should change digest");

    let b1 = sha3_512_domain(b"tx", m);
    let b2 = sha3_512_domain(b"anchor", m);
    assert_ne!(b1, b2, "SHA3-512: domain should change digest");

    let c1 = blake3_domain(b"tx", m);
    let c2 = blake3_domain(b"anchor", m);
    assert_ne!(c1, c2, "BLAKE3: domain should change digest");
}

#[test]
fn ct_xor_and_select_work() {
    let a = [0xFFu8; 8];
    let b = [0x0Fu8; 8];
    let mut dst = [0u8; 8];

    xor_into(&mut dst, &a, &b);
    assert_eq!(dst, [0xF0u8; 8], "xor_into should XOR elementwise");

    let x = [1u8; 4];
    let y = [2u8; 4];
    let mut out = [0u8; 4];

    // choose x when mask is all-ones
    ct_select_into(&mut out, &x, &y, 0xFF);
    assert_eq!(out, x);

    // choose y when mask is zero
    ct_select_into(&mut out, &x, &y, 0x00);
    assert_eq!(out, y);
}

#[test]
#[should_panic] // length mismatch should panic
fn xor_into_length_mismatch_panics() {
    let mut dst = [0u8; 4];
    let a = [0u8; 3];
    let b = [0u8; 4];
    xor_into(&mut dst, &a, &b);
}

#[test]
#[should_panic] // length mismatch should panic
fn ct_select_into_length_mismatch_panics() {
    let mut dst = [0u8; 4];
    let x = [0u8; 5];
    let y = [0u8; 4];
    ct_select_into(&mut dst, &x, &y, 0xFF);
}
