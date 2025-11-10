use super::{Result, SerdeError};

/// Hard limits to prevent OOM / pathological inputs.
/// Tune as you like; these are safe, conservative defaults.
pub const MAX_SSZ_BYTES: usize = 1 << 20; // 1 MiB for byte blobs
pub const MAX_SSZ_LIST: usize = 1 << 16; // up to 65,536 list elements
pub const MAX_SSZ_TOTAL: usize = 1 << 22; // ~4 MiB total nested decode work

/// Read a little-endian u32 length and enforce a maximum.
#[inline]
fn read_cap_len(input: &[u8], off: &mut usize, max: usize) -> Result<usize> {
    if *off + 4 > input.len() {
        return Err(SerdeError::Eof);
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&input[*off..*off + 4]);
    *off += 4;
    let len = u32::from_le_bytes(b) as usize;
    if len > max {
        return Err(SerdeError::TooLong { have: len, max });
    }
    Ok(len)
}

/// Minimal ETH-SSZ Decode trait (Phase 0).
pub trait Decode: Sized {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)>;
}

/* -------- Scalars (Phase 0) -------- */

impl Decode for bool {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        let b = *input.get(0).ok_or(SerdeError::InvalidLength)?;
        Ok((b != 0, 1))
    }
}
impl Decode for u8 {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        Ok((*input.get(0).ok_or(SerdeError::InvalidLength)?, 1))
    }
}
impl Decode for u16 {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < 2 {
            return Err(SerdeError::InvalidLength);
        }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&input[..2]);
        Ok((u16::from_le_bytes(buf), 2))
    }
}
impl Decode for u32 {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < 4 {
            return Err(SerdeError::InvalidLength);
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&input[..4]);
        Ok((u32::from_le_bytes(buf), 4))
    }
}
impl Decode for u64 {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < 8 {
            return Err(SerdeError::InvalidLength);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&input[..8]);
        Ok((u64::from_le_bytes(buf), 8))
    }
}
impl Decode for u128 {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < 16 {
            return Err(SerdeError::InvalidLength);
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&input[..16]);
        Ok((u128::from_le_bytes(buf), 16))
    }
}
impl Decode for [u8; 32] {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < 32 {
            return Err(SerdeError::InvalidLength);
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&input[..32]);
        Ok((buf, 32))
    }
}
impl Decode for [u8; 20] {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < 20 {
            return Err(SerdeError::InvalidLength);
        }
        let mut buf = [0u8; 20];
        buf.copy_from_slice(&input[..20]);
        Ok((buf, 20))
    }
}
impl<T: Decode> Decode for Vec<T> {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        // For byte-like element types (size == 1), cap by total bytes;
        // otherwise cap by number of list elements.
        let mut off = 0;
        let elem_cap = if core::mem::size_of::<T>() == 1 {
            MAX_SSZ_BYTES
        } else {
            MAX_SSZ_LIST
        };
        let n = read_cap_len(input, &mut off, elem_cap)?;

        let mut out = Vec::with_capacity(n);
        // Optional guard against deeply nested or adversarial structures.
        let mut total_used = 0usize;

        for _ in 0..n {
            let (v, used) = T::ssz_read(&input[off..])?;
            off += used;
            total_used = total_used.saturating_add(used);
            if total_used > MAX_SSZ_TOTAL {
                return Err(SerdeError::TooLong {
                    have: total_used,
                    max: MAX_SSZ_TOTAL,
                });
            }
            out.push(v);
        }
        Ok((out, off))
    }
}
impl<T: Decode> Decode for Option<T> {
    fn ssz_read(input: &[u8]) -> Result<(Self, usize)> {
        let (flag, used) = u8::ssz_read(input)?;
        if flag == 0 {
            Ok((None, used))
        } else {
            let (v, used2) = T::ssz_read(&input[used..])?;
            Ok((Some(v), used + used2))
        }
    }
}