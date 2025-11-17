use serde::{Deserialize, Serialize};

/// One ML-DSA-44 test vector (or negative case).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLDsaKat {
    /// e.g. "ml-dsa-44/kat-001"
    pub name: String,
    /// Public key (hex)
    pub pk_hex: String,
    /// Message bytes (hex)
    pub msg_hex: String,
    /// Signature bytes (hex)
    pub sig_hex: String,
    /// true for a passing vector; false for a deliberately invalid/mutated one
    pub should_verify: bool,
    /// schema version for forward-compat of this file format
    pub schema: u32,
}

/// A corpus of ML-DSA-44 vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLDsaCorpus {
    /// Level identifier (44 for ML-DSA-44)
    pub level: u8,
    pub vectors: Vec<MLDsaKat>,
}

impl MLDsaCorpus {
    /// Load a corpus from JSON bytes.
    pub fn from_slice(json: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(json)
    }

    /// Convenience: load from a &str.
    pub fn from_json_str(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

/// Helper to decode hex → Vec<u8>.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() % 2 != 0 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("bad hex".into());
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| "bad hex".to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal embedded sample (replace with real vectors in /vectors)
    const SAMPLE: &str = r#"
    {
      "level": 44,
      "vectors": [
        {
          "name": "ml-dsa-44/sample-pass",
          "pk_hex": "0x01",
          "msg_hex": "0x616263",          
          "sig_hex": "0x02",
          "should_verify": true,
          "schema": 1
        },
        {
          "name": "ml-dsa-44/sample-fail",
          "pk_hex": "0x01",
          "msg_hex": "0x616263",
          "sig_hex": "0x03",
          "should_verify": false,
          "schema": 1
        }
      ]
    }"#;

    #[test]
    fn loads_sample_corpus() {
        let c = MLDsaCorpus::from_json_str(SAMPLE).expect("parse ok");
        assert_eq!(c.level, 44);
        assert_eq!(c.vectors.len(), 2);
        assert!(c.vectors.iter().any(|v| v.should_verify));
        assert!(c.vectors.iter().any(|v| !v.should_verify));
    }

    #[test]
    fn hex_decode_works() {
        assert_eq!(hex_to_bytes("0x00ff").unwrap(), vec![0x00, 0xff]);
        assert!(hex_to_bytes("zz").is_err());
    }
}
