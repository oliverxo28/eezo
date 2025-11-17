// eezo-relay/src/snark.rs
// T39.3 — optional SNARK path (modular)
// Self-contained helper to talk to EezoSnarkVerifier and read proofs from disk.

use std::{path::{Path, PathBuf}, sync::Arc};
use anyhow::{Result, Context, anyhow};
use ethers::prelude::*;
use tokio::fs;
use std::str::FromStr; // <<< REQUIRED FOR ADDRESS PARSING

abigen!(
    EezoSnarkVerifier,
    r#"[ 
        function verifyAndStorePiDigest(uint64 height, bytes32 piDigest, bytes calldata snarkProof)
    ]"#
);

/// Thin client around the EezoSnarkVerifier contract.
pub struct SnarkClient<M: Middleware> {
    verifier: EezoSnarkVerifier<M>,
}

impl<M: Middleware + 'static> SnarkClient<M> { // <<< LIFETIME FIX HERE
    /// Construct a new client to the on-chain verifier.
    pub fn new(verifier_addr: Address, client: Arc<M>) -> Self {
        Self { verifier: EezoSnarkVerifier::new(verifier_addr, client) }
    }

    /// Construct a new client, returning Ok(None) if addr_hex is None.
    /// This allows the SNARK path to be optional and configured via environment variables.
    pub fn try_new(addr_hex: Option<String>, client: Arc<M>) -> Result<Option<Self>> {
        // sanitize: strip quotes + all whitespace, add 0x if missing for bare 40-hex strings
        fn sanitize(mut s: String) -> String {
            s.retain(|c| !c.is_whitespace() && c != '"' && c != '\'');
            if !s.starts_with("0x") && s.len() == 40 {
                s.insert_str(0, "0x");
            }
            s
        }
        if let Some(raw) = addr_hex {
            let s = sanitize(raw);
            // structural checks with explicit error messages
            if s.len() != 42 {
                return Err(anyhow!(
                    "SNARK_VERIFIER_ADDR must be 42 chars (0x + 40 hex), got len={} → `{}`",
                    s.len(),
                    s
                ));
            }
            if !s.starts_with("0x") || !s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                // show raw bytes to expose stray unicode / zero-width chars
                let bytes: Vec<u8> = s.as_bytes().to_vec();
                return Err(anyhow!(
                    "SNARK_VERIFIER_ADDR has non-hex/garbage chars: `{}` bytes={:?}",
                    s,
                    bytes
                ));
            }
            let addr = Address::from_str(&s)
                .with_context(|| format!("SNARK_VERIFIER_ADDR parse failed for `{}`", s))?;
            Ok(Some(Self::new(addr, client)))
        } else {
            Ok(None)
        }
    }

    /// Submit the SNARK proof. Returns Ok(Some(tx_hash)) on success,
    /// Ok(None) if mined but reverted, Err on send error.
    pub async fn submit(
        &self,
        height: u64,
        pi_digest: [u8; 32],
        proof_bytes: Vec<u8>,
    ) -> Result<Option<TxHash>> {
        let call = self
            .verifier
            .verify_and_store_pi_digest(height, pi_digest, proof_bytes.into());

        let pending = call.send().await.context("send verifyAndStorePiDigest")?;
        let receipt = pending
            .await
            .context("await verifyAndStorePiDigest")?;
        let ok = receipt
            .as_ref()
            .and_then(|r| r.status)
            .map(|s| s == U64::from(1))
            .unwrap_or(false);
        if ok { 
            Ok(receipt.map(|r| r.transaction_hash)) 
        } else { 
            Ok(None) 
        }
    }
}

/// Read `snark_proof.bin` (preferred) or `snark_proof.hex` from proof_dir/h{height}/
/// Returns Ok(Some(bytes)) if found; Ok(None) if neither file exists.
pub async fn read_snark_proof(proof_dir: &Path, height: u64) -> Result<Option<Vec<u8>>> {
    let hdir = proof_dir.join(format!("h{height}"));
    let bin = hdir.join("snark_proof.bin");
    let hexp = hdir.join("snark_proof.hex");

    if file_exists(&bin).await {
        let raw = fs::read(&bin).await.with_context(|| fmt_path("read", &bin))?;
        return Ok(Some(raw));
    }
    if file_exists(&hexp).await {
        let s = read_hex_file(&hexp).await?;
        let bytes = hex::decode(strip_0x(&s)).context("decode snark_proof.hex")?;
        return Ok(Some(bytes));
    }
    Ok(None)
}

/// Read `pi_digest.hex` from proof_dir/h{height}/ as 32-byte array.
/// Returns Ok(Some([u8;32])) if present and well-formed; Ok(None) otherwise.
pub async fn read_pi_digest_32(proof_dir: &Path, height: u64) -> Result<Option<[u8;32]>> {
    let hdir = proof_dir.join(format!("h{height}"));
    let p = hdir.join("pi_digest.hex");
    if !file_exists(&p).await { return Ok(None); }
    let s = read_hex_file(&p).await?;
    let b = hex::decode(strip_0x(&s)).context("decode pi_digest.hex")?;
    if b.len() != 32 {
        return Ok(None);
    }
    let mut arr = [0u8;32];
    arr.copy_from_slice(&b);
    Ok(Some(arr))
}

// ── small async fs helpers ─────────────────────────────────────────────────────

async fn file_exists(p: &PathBuf) -> bool {
    fs::metadata(p).await.is_ok()
}

async fn read_hex_file(p: &PathBuf) -> Result<String> {
    let s = fs::read_to_string(p).await.with_context(|| fmt_path("read_to_string", p))?;
    Ok(s.trim().to_string())
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn fmt_path(op: &str, p: &Path) -> String {
    format!("{op} {}", p.display())
}