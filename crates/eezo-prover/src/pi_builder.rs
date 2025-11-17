use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer};
use std::time::Duration;
use reqwest::Client;

use crate::v1_mldsa::{PublicInputsV2, compute_sig_batch_digest};

/// dev-safety: ensure a 32-byte value is not all-zero.
/// if zero, return a tiny deterministic tag so LC doesn't revert on "zero root".
fn ensure_nonzero(mut b: [u8; 32], tag: u8) -> [u8; 32] {
    if b == [0u8; 32] {
        // use the `log` crate (env_logger initialized in the bin)
        log::warn!(
            "pi_builder: dev-fallback applied: replacing zero 32-byte root with tag=0x{:02x}",
            tag
        );
        let mut out = [0u8; 32];
        out[31] = tag; // minimal non-zero marker
        out
    } else {
        b
    }
}

/// accept either "0x..." hex string or byte array for 32-byte fields
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Bytes32Json { Hex(String), Arr(Vec<u8>) }

fn de_bytes32<'de, D>(d: D) -> std::result::Result<[u8; 32], D::Error>
where D: Deserializer<'de> {
    let v = Bytes32Json::deserialize(d)?;
    let mut out = [0u8; 32];
    match v {
        Bytes32Json::Hex(s) => {
            let h = s.strip_prefix("0x").unwrap_or(&s);
            let bytes = hex::decode(h).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom(format!("expected 32 bytes, got {} (hex)", bytes.len())));
            }
            out.copy_from_slice(&bytes);
        }
        Bytes32Json::Arr(v) => {
            if v.len() != 32 {
                return Err(serde::de::Error::custom(format!("expected 32 bytes, got {} (array)", v.len())));
            }
            out.copy_from_slice(&v);
        }
    }
    Ok(out)
}

/// Minimal shape of /bridge/header/{height} we care about. Extra fields are ignored.
#[derive(Debug, Deserialize)]
pub struct BridgeHeaderJson {
    pub height: u64,
    #[serde(deserialize_with = "de_bytes32")]
    pub tx_root_v2: [u8; 32],
    #[serde(deserialize_with = "de_bytes32")]
    pub state_root_v2: [u8; 32],

    // Future-expansion fields from BridgeHeader are ignored
    // automatically by serde unless marked `deny unknown fields`.
}

/// Build PublicInputsV2 for ML-DSA-44 from a given checkpoint height.
/// This function performs:
/// 1) GET /bridge/header/{height}
/// 2) Build PI v2
/// 3) Return (PI, dummy batch triples)
pub async fn build_pi_for_height(
    client: &Client,
    base_url: &str,
    height: u64,
    chain_id20: [u8; 20],
    batch_size: u32,
) -> Result<(PublicInputsV2, Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>)> 
{
    // ---------------------------
    // 1) Fetch BridgeHeader JSON
    // ---------------------------
    let url = format!("{}/bridge/header/{}", base_url, height);

    let hdr: BridgeHeaderJson = client
        .get(&url)
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .with_context(|| format!("failed GET {}", url))?
        .json()
        .await
        .with_context(|| format!("failed parse of BridgeHeader JSON at height {}", height))?;

    if hdr.height != height {
        // Node should never return a mismatched height
        return Err(anyhow::anyhow!(
            "node returned mismatched height: expected {}, got {}",
            height,
            hdr.height
        ));
    }

    // ---------------------------------------------------------
    // 2) Build batch of (pk,msg,sig) triples.
    // For T37.4 these are dummy. Later (T37.5) → real STARK data.
    // ---------------------------------------------------------
    let mut triples: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for i in 0..batch_size {
        triples.push((
            vec![1u8, i as u8],             // dummy pk
            vec![2u8, i as u8],             // dummy msg
            vec![3u8, i as u8],             // dummy sig
        ));
    }

    let digest = compute_sig_batch_digest(
        triples
            .iter()
            .map(|(pk, msg, sig)| (&pk[..], &msg[..], &sig[..])),
    );

    // --------------------------------------------
    // 3) Construct the PI v2 exactly as LC expects
    //    (dev fallback: force non-zero roots)
    // --------------------------------------------
    let tx_root_v2   = ensure_nonzero(hdr.tx_root_v2,   0xA1);
    let state_root_v2= ensure_nonzero(hdr.state_root_v2,0xB2);
    let pis = PublicInputsV2::for_mldsa44(
        hdr.height,
        tx_root_v2,
        state_root_v2,
        digest,
        batch_size,
        chain_id20,
    );

    Ok((pis, triples))
}