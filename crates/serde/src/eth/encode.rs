// no imports needed here

/// Minimal ETH-SSZ Encode trait (Phase 0).
pub trait Encode {
    fn ssz_write(&self, out: &mut Vec<u8>);
    fn ssz_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.ssz_write(&mut v);
        v
    }
}

/* -------- Scalars (Phase 0) -------- */

impl Encode for bool {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        out.push(if *self { 1 } else { 0 });
    }
}
impl Encode for u8 {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}
impl Encode for u16 {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}
impl Encode for u32 {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}
impl Encode for u64 {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}
impl Encode for u128 {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}
impl Encode for [u8; 32] {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Encode for [u8; 20] {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        let len = self.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        for item in self {
            item.ssz_write(out);
        }
    }
}

impl<T: Encode> Encode for Option<T> {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                v.ssz_write(out);
            }
        }
    }
}

