use bech32::{self, ToBase32, Variant};
use tiny_keccak::{Hasher, Keccak};
use hex;

/// (Optional) HRP to use if you choose to render Bech32m alongside hex.
/// Not used by the default `pubkey_to_address` anymore.
pub const HRP: &str = "eezo";

/// Derive canonical **20-byte** address bytes: `Keccak256(pubkey)[12..]`.
#[inline]
fn addr20_from_pubkey(pk: &[u8]) -> [u8; 20] {
    let mut keccak = Keccak::v256();
    let mut hash32 = [0u8; 32];
    keccak.update(pk);
    keccak.finalize(&mut hash32);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash32[12..]); // rightmost 20 bytes
    out
}

/// Primary, human-display format (ETH-style): `0x` + 40 hex chars.
/// Still the same canonical 20-byte address under the hood.
pub fn pubkey_to_address(pk: &[u8]) -> String {
    let addr20 = addr20_from_pubkey(pk);
    format!("0x{}", hex::encode(addr20))
}

/// Optional Bech32m rendering of the same 20-byte address for UX (wallets/UIs).
pub fn pubkey_to_bech32m(pk: &[u8], hrp: &str) -> String {
    let addr20 = addr20_from_pubkey(pk);
    bech32::encode(hrp, addr20.to_base32(), Variant::Bech32m)
        .expect("bech32 encoding should not fail for 20-byte data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::FromBase32;

    #[test]
    fn hex_is_20_bytes() {
        let pk = [0xABu8; 32];
        let a = pubkey_to_address(&pk);
        assert!(a.starts_with("0x"));
        let raw = hex::decode(&a[2..]).unwrap();
        assert_eq!(raw.len(), 20);
    }

    #[test]
    fn bech32m_optional_roundtrip_20bytes() {
        let pk = [0xCDu8; 32];
        let b32 = pubkey_to_bech32m(&pk, HRP);
        assert!(b32.starts_with(HRP));
        let (_hrp, data, _var) = bech32::decode(&b32).unwrap();
        let raw = Vec::<u8>::from_base32(&data).unwrap();
        assert_eq!(raw.len(), 20);
    }
}