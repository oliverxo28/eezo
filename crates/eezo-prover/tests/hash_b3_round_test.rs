#![cfg(feature = "stark-air")]

use eezo_prover::hash_b3::{check_rotr8_16_consistency, check_add_xor_then_rotr8_16};

#[test]
fn rotr8_16_byte_model_matches_software() {
    // a few hand-picked words + some random-ish ones
    let samples: [u32; 8] = [
        0x00000000, 0xffffffff, 0x01234567, 0x89abcdef,
        0xdeadbeef, 0x10203040, 0xa5a5a5a5, 0x5a5a5a5a,
    ];
    for &x in &samples {
        assert!(check_rotr8_16_consistency(x));
    }
    // quick sweep
    for x in (0u32..1024).step_by(37) {
        assert!(check_rotr8_16_consistency(x));
    }
}

#[test]
fn add_xor_then_rotr8_16_holds_for_samples() {
    let triples: [(u32,u32,u32); 6] = [
        (0,0,0), (1,2,3), (0x01234567, 0x89abcdef, 0x0f0f0f0f),
        (0xdeadbeef, 0x01020304, 0xfedcba98),
        (0xaaaaaaaa, 0x55555555, 0xffffffff),
        (0x12345678, 0x9abcdef0, 0x0badc0de),
    ];
    for &(x,y,z) in &triples {
        assert!(check_add_xor_then_rotr8_16(x,y,z));
    }
}
