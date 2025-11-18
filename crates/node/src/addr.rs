// crates/node/src/addr.rs

use eezo_ledger::address::Address;

/// Parse a user-supplied address into the canonical 20-byte ledger `Address`.
///
/// **Hex-only (Ethereum-like) acceptance:**
/// - Hex with/without 0x/0X:
///   * 20-byte hex (exactly 40 nibbles)
///   * **Short hex** (≤40 nibbles) — left-padded with zeros to 40 nibbles (dev convenience)
///   * 32-byte hex (64 nibbles) — normalized to rightmost 20 bytes
pub fn parse_account_addr(s: &str) -> Option<Address> {
    let s = s.trim();
    parse_hex_lenient(s).map(Address::from_bytes)
}

/// Hex parser that accepts:
/// - ≤40 nibbles: left-pad with zeros to 40 → 20 bytes
/// - 64 nibbles: 32 bytes → normalize to rightmost 20
fn parse_hex_lenient(s: &str) -> Option<[u8; 20]> {
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);

    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let normalized = match h.len() {
        // dev convenience: accept short hex and left-pad to 40 nibbles
        0..=40 => {
            let mut s = String::with_capacity(40);
            for _ in 0..(40 - h.len()) {
                s.push('0');
            }
            s.push_str(h);
            s
        }
        // 64 nibbles (32 bytes) — keep as-is; we'll trim to rightmost 20 later
        64 => h.to_string(),
        // everything else is invalid (e.g., 41..63 nibbles)
        _ => return None,
    };

    let bytes = hex::decode(&normalized).ok()?;
    match bytes.len() {
        20 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        32 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes[12..]);
            Some(arr)
        }
        _ => None,
    }
}

/// Fast boolean guard that mirrors `parse_account_addr`.
pub fn is_valid_account_addr(s: &str) -> bool {
    parse_account_addr(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_20() {
        let a = parse_account_addr("0x0000000000000000000000000000000000000002").unwrap();
        assert_eq!(a.as_bytes()[19], 0x02);
    }

    #[test]
    fn parses_short_hex_left_padded() {
        // 0x01 => 19 zero bytes + 0x01
        let a = parse_account_addr("0x01").unwrap();
        assert_eq!(a.as_bytes().len(), 20);
        assert_eq!(a.as_bytes()[..19], [0u8; 19]);
        assert_eq!(a.as_bytes()[19], 0x01);

        // 0x123 => 18 zero bytes + 0x0123
        let a2 = parse_account_addr("0x123").unwrap();
        assert_eq!(a2.as_bytes().len(), 20);
        assert_eq!(a2.as_bytes()[..18], [0u8; 18]);
        assert_eq!(&a2.as_bytes()[18..], &[0x01, 0x23]);
    }

    #[test]
    fn parses_hex_32_normalizes_rightmost_20() {
        let hex32 = "0x11111111111111111111111100000000000000000000000000000000000000ab";
        let a = parse_account_addr(hex32).unwrap();
        assert_eq!(a.as_bytes()[19], 0xAB);
    }

    #[test]
    fn rejects_bad_hex() {
        // invalid length (41 nibbles)
        assert!(parse_account_addr("0x12345678901234567890123456789012345678901").is_none());
        // non-hex
        assert!(parse_account_addr("not-hex").is_none());
        assert!(parse_account_addr("0xgg").is_none());
    }
}
