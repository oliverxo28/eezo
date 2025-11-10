#![cfg(feature = "eth-ssz")]

use eezo_serde::eth::{Encode, Decode, HashTreeRoot};

#[derive(Debug, PartialEq)]
struct Toy {
    flag: bool,
    n: u32,
    data: Vec<u8>,
}

// Manual impls just for the smoke test (Phase 0).
impl Encode for Toy {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        self.flag.ssz_write(out);
        self.n.ssz_write(out);
        self.data.ssz_write(out);
    }
}
impl Decode for Toy {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize), eezo_serde::eth::SerdeError> {
        let (flag, u1) = bool::ssz_read(input)?;
        let (n, u2) = u32::ssz_read(&input[u1..])?;
        let (data, u3) = Vec::<u8>::ssz_read(&input[u1+u2..])?;
        Ok((Toy { flag, n, data }, u1 + u2 + u3))
    }
}

#[test]
fn toy_roundtrip_and_root() {
    let t = Toy { flag: true, n: 42, data: b"hello".to_vec() };
    let bytes = t.ssz_bytes();

    let (t2, used) = Toy::ssz_read(&bytes).expect("decode ok");
    assert_eq!(used, bytes.len());
    assert_eq!(t, t2);

    let r1 = t.hash_tree_root();
    let r2 = t2.hash_tree_root();
    assert_eq!(r1, r2, "root stable");
}
