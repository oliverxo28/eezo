//! eezo-relay — Ethereum Light Client Relayer

use rand::{thread_rng, Rng};
use anyhow::{anyhow, Context, Result};
use dotenvy::dotenv;
use std::{path::PathBuf, time::Duration};
use std::collections::HashSet;
use eezo_ssz_bridge::{log_ssz_versions, assert_compat_or_warn, ssz_versions};
use ethers::prelude::*;
use ethers::types::{H160, H256, U256};
#[cfg(feature = "kemtls-resume")]
use hex::FromHex;
use reqwest::Client;
use serde::Deserialize;
use serde_json;
use std::env;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
// ── T39.3: optional SNARK-on-chain path (verifier adapter) ──
mod snark; // <<< PATCH 1: Import the new snark module
mod checkpoint; // <<< NEW: read checkpoint JSONs for sidecar parsing
use tracing_subscriber::EnvFilter;

/// File name placed by the prover when h{H} is fully written (atomic ready signal)
const READY_FILE: &str = "READY";

// ── T37.1: optional KEMTLS resumption warm-up (feature-gated) ───────────────
#[cfg(feature = "kemtls-resume")]
use eezo_net::kem_adapter::MlKem768;
#[cfg(feature = "kemtls-resume")]
use eezo_net::secure::{client_connect_async, client_connect_resume_async, FramedSession};
#[cfg(feature = "kemtls-resume")]
use once_cell::sync::Lazy;
#[cfg(feature = "kemtls-resume")]
use pqcrypto_mlkem::mlkem768::PublicKey as MlkemPk;
#[cfg(feature = "kemtls-resume")]
use pqcrypto_traits::kem::PublicKey as _; // brings ::from_bytes into scope
#[cfg(feature = "kemtls-resume")]
use std::sync::Mutex;
#[cfg(feature = "kemtls-resume")]
use tokio::net::TcpStream;

#[inline]
fn align_up(n: u64, step: u64) -> u64 {
    if step == 0 { return n; }
    ((n + step - 1) / step) * step
}

// T37.6: jitter helper for backoff
fn jittered(ms: u64) -> Duration {
    let j: u64 = thread_rng().gen_range(0..=150);
    Duration::from_millis(ms + j)
}

// Keep the original ABI definition
abigen!(
    EezoLightClient,
    r#"[
        function verifyAndStore(bytes proof, bytes publicInputs)
        function assertInclusion(uint64 h, bytes32 leaf, uint256 idx, bytes32[] branch)
        function latestHeight() view returns (uint64)
        function activeSuiteId() view returns (uint32)
        function nextSuiteId() view returns (uint32)
        function dualAcceptUntil() view returns (uint64)
        function allowedCircuit(uint32 cv) view returns (bool)
		function expectedChainId20() view returns (bytes20)
        function storePiDigest(uint64 height, bytes32 digest)
        function piDigestOf(uint64 h) view returns (bytes32)		
    ]"#
);
// type alias used by submit_header()
type TxHash = H256;

#[derive(Deserialize)]
struct HeaderResp {
    // must match your prover output order in the contract
    proof: String,          // 0x...
    // V2 (T34.2): 0x... = abi.encode(
    //   uint32 circuit_version, uint64 height, bytes32 tx_root_v2, bytes32 state_root_v2,
    //   bytes32 sig_batch_digest, uint32 batch_len, bytes20 chain_id20, uint32 suite_id
    // )
    public_inputs: String,  // 0x...
    height: u64,
}

#[derive(Deserialize)]
#[allow(dead_code)] // Keep allow(dead_code) as it was in the original file
struct TxProofResp {
    height: u64,
    leaf: String,              // 0x..
    index: String,             // decimal or hex; we parse to U256
    branch: Vec<String>,       // ["0x..","0x.."]
}

#[derive(Deserialize)]
struct SummaryResp {
    latest_height: u64,
    // we ignore the rest for now: total, last_modified_unix, active_suite, next_suite
}
// ───────────────────────── T37.3: rotation view and gating ─────────────────────────
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RotationView {
    active_suite: u32,
    next_suite: u32,
    dual_accept_until: u64,
    allow_cv2: bool, // cached one-time preflight for circuit version 2
}

impl RotationView {
    fn suite_allowed_for_height(&self, h: u64, suite_in_pi: u32) -> bool {
        // inside the window: both active and next are accepted
        if h <= self.dual_accept_until {
            return suite_in_pi == self.active_suite || suite_in_pi == self.next_suite;
        }
        // after window closes: only active is accepted
        suite_in_pi == self.active_suite
    }
}

async fn refresh_rotation_view<C: Middleware>(
    lc: &EezoLightClient<C>
) -> Result<RotationView> {
    // note: treat presence of getters as canonical; errors map to defaults
    let active = lc.active_suite_id().call().await.unwrap_or(1u32);
    let next = lc.next_suite_id().call().await.unwrap_or(2u32);
    let dual = lc.dual_accept_until().call().await.unwrap_or(0u64);
    // single preflight for CV=2 allowance (we do NOT call this per height/suite ids)
    let allow_cv2 = lc.allowed_circuit(2u32).call().await.unwrap_or(false);
    Ok(RotationView {
        active_suite: active,
        next_suite: next,
        dual_accept_until: dual,
        allow_cv2,
    })
}

// parse public_inputs as ABI-encoded 8-word static tuple:
// [0] u32 circuit_version, [1] u64 height, ..., [6] bytes20 chain_id20, [7] u32 suite_id
// We only extract circuit_version and suite_id; optionally height for sanity checks.
fn parse_pi_cv_and_suite(pi_hex: &str) -> Result<(u32, u32, Option<u64>)> {
    let b = hex_to_bytes(pi_hex)?;
    // Expect at least 8 * 32 bytes for 8 static words
    if b.len() < 32 * 8 {
        return Err(anyhow!("public_inputs too short ({} bytes), need ≥256", b.len()));
    }
    // helper to read a 32-byte big-endian word at index i
    fn word(b: &[u8], i: usize) -> &[u8] { &b[i*32 .. (i+1)*32] }
    // circuit_version at word 0 (lower 4 bytes of the 32-byte word)
    let cv_w = word(&b, 0);
    let cv = u32::from_be_bytes(cv_w[28..32].try_into().unwrap());
    // height at word 1 (lower 8 bytes)
    let h_w = word(&b, 1);
    let height = u64::from_be_bytes(h_w[24..32].try_into().unwrap());
    // suite_id at word 7 (lower 4 bytes)
    let suite_w = word(&b, 7);
    let suite = u32::from_be_bytes(suite_w[28..32].try_into().unwrap());
    Ok((cv, suite, Some(height)))
}

fn env_flag(name: &str) -> bool {
    matches!(env::var(name).as_deref(), Ok("1") | Ok("true") | Ok("TRUE"))
}

#[derive(Clone)]
struct Config {
    rpc: String,
    pk: String,
    lc_addr: String, // Keep original env var name
    eezo: String,    // Keep original env var name (EEZO_NODE)
    evm_chain_id: u64,
    poll_secs: u64,
    backoff_max_secs: u64,
    // ~ fallback_dir removed, replaced by proof_dir
    /// Root directory where proofs are staged. We'll look in h{height}/ under this.
    proof_dir: PathBuf, // ~ Use PathBuf for the proof directory
    checkpoint_every: u64,
    dry_run: bool,
    dev_trusted_store: bool,
    keep_heights: u64, // T37.6: GC keep N heights
    metrics_bind: String,
    strict_pi: bool,   // T37.7: EEZO_PI_SSZ_STRICT toggle	
    // T39.3: optional on-chain SNARK verification path
    snark_onchain: bool, // <<< PATCH 2a: Config: add a runtime toggle for SNARK path
    // T41.5: enforce sidecar presence at first-eligible height
    qc_enforce: bool,	
    // T37.1 (optional): if provided, the relay will establish a resumable
    // KEMTLS connection to the node to exercise/measure session resumption.
    // EEZO_KEMTLS_ADDR example: "127.0.0.1:18281"
    // EEZO_KEMTLS_SERVER_PK: hex-encoded ML-KEM-768 public key bytes
    #[cfg(feature = "kemtls-resume")]
    kemtls_addr: Option<String>,
    #[cfg(feature = "kemtls-resume")]
    kemtls_server_pk: Option<String>,
}

impl Config {
    fn from_env() -> Result<Self> {
        let evm_chain_id = env::var("EVM_CHAIN_ID").unwrap_or_else(|_| "31337".into());
        let poll_secs = env::var("POLL_SECS").unwrap_or_else(|_| "5".into());
        let backoff_max_secs = env::var("BACKOFF_MAX_SECS").unwrap_or_else(|_| "30".into());
        let checkpoint_every = env::var("CHECKPOINT_EVERY").unwrap_or_else(|_| "32".into());
        let keep_heights = env::var("EEZO_RELAY_KEEP").unwrap_or_else(|_| "256".into());

        // + Back-compat: prefer EEZO_PROOF_DIR; fall back to existing FALLBACK_DIR; default "proof"
        let proof_root = env::var("EEZO_PROOF_DIR")
            .or_else(|_| env::var("FALLBACK_DIR")) // Keep FALLBACK_DIR for back-compat
            .unwrap_or_else(|_| "proof".to_string());

        Ok(Self {
            rpc: env::var("RPC").context("RPC env var missing")?,
            pk: env::var("PK").context("PK env var missing")?,
            lc_addr: env::var("LC_ADDR").context("LC_ADDR env var missing")?,
            eezo: env::var("EEZO_NODE").context("EEZO_NODE env var missing")?,
            proof_dir: PathBuf::from(proof_root),
            evm_chain_id: evm_chain_id.parse()?,
            poll_secs: poll_secs.parse()?,
            backoff_max_secs: backoff_max_secs.parse()?,
            checkpoint_every: checkpoint_every.parse()?,
            dry_run: env_flag("DRY_RUN"),
            dev_trusted_store: env_flag("DEV_TRUSTED_STORE"),
            keep_heights: keep_heights.parse()?,
            metrics_bind: env::var("METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:9899".into()),
            // accept either old EEZO_PI_SSZ_STRICT or the newer EEZO_RELAY_STRICT_CHECK
            strict_pi: env_flag("EEZO_PI_SSZ_STRICT") || env_flag("EEZO_RELAY_STRICT_CHECK"),
            // new: enable SNARK path with EEZO_SNARK_ONCHAIN=1/true
            snark_onchain: env_bool("EEZO_SNARK_ONCHAIN", false), // <<< PATCH 2b: Read SNARK config
            // new: enable relay-side sidecar enforcement logging path
            qc_enforce: env_bool("EEZO_QC_SIDECAR_ENFORCE", false),			
            #[cfg(feature = "kemtls-resume")]
            kemtls_addr: env::var("EEZO_KEMTLS_ADDR").ok(),
            #[cfg(feature = "kemtls-resume")]
            kemtls_server_pk: env::var("EEZO_KEMTLS_SERVER_PK").ok(),
        })
    }
}

// --- Helper functions (strip_0x, hex_to_bytes, fetch_summary, http_header_exists) remain unchanged ---
fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

// + NEW: Ensure hex strings have 0x prefix
fn ensure_0x(s: String) -> String {
    if s.starts_with("0x") || s.starts_with("0X") { 
        s 
    } else { 
        format!("0x{}", s) 
    }
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    let h = strip_0x(s);
    if h.len() % 2 != 0 {
        return Err(anyhow!("hex length must be even"));
    }
    Ok(hex::decode(h)?)
}
// NEW: a small bool env helper
fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => default,
    }
}

#[inline]
fn reason_str(r: &eezo_ledger::qc_sidecar::ReanchorReason) -> &'static str {
    use eezo_ledger::qc_sidecar::ReanchorReason::*;
    match r {
        RotationCutover => "rotation_cutover",
        MissedWindowRecovery => "missed_window_recovery",
        AdminOverride => "admin_override",
    }
}
// T41.5 — validate qc_sidecar_v2 if present; log one-liner + export metrics
async fn check_sidecar_for_height(
    metrics: &RelayMetrics,
    cfg: &Config,
    height: u64,
    rot_policy: &Option<eezo_ledger::rotation::RotationPolicy>,
) {
    use eezo_ledger::checkpoints::{validate_sidecar_v2_for_header, should_emit_qc_sidecar_v2};
    if let Ok(Some(hdr)) = checkpoint::read_checkpoint(&cfg.proof_dir, height) {
        if let Some(sc) = &hdr.qc_sidecar_v2 {
            metrics.sc_seen();
            // reader-side validation via ledger helper (format + suite match)
            match validate_sidecar_v2_for_header(&hdr) {
                Ok(()) => {
                    let lag = hdr.height.saturating_sub(sc.anchor_height);
                    metrics.sc_observe_lag(lag);
                    metrics.sc_set_last_anchor(sc.anchor_height);
                    info!(
                        "relay: sidecar_v2 ok at h={} anchor={} suite={} reason={} lag={}",
                        hdr.height, sc.anchor_height, hdr.suite_id, reason_str(&sc.reason), lag
                    );
                    metrics.sc_valid();
                }
                Err(code) => {
                    warn!("relay: sidecar_v2 reject at h={} code={}", hdr.height, code);
                    metrics.sc_rejected();
                }
            }
        } else {
            // missing — count only if enforce flag is on AND this height is first-eligible
            if cfg.qc_enforce {
                if let Some(rp) = rot_policy {
                    if should_emit_qc_sidecar_v2(height, rp) {
                        warn!("relay: sidecar_v2 missing at first-eligible h={}", height);
                        metrics.sc_missing();
                    }
                }
            }
        }
    }
}

async fn fetch_summary(http: &Client, base: &str) -> Result<SummaryResp> {
    let url = format!("{}/bridge/summary", base.trim_end_matches('/'));
    let r = http.get(&url).send().await?.error_for_status()?;
    Ok(r.json::<SummaryResp>().await?)
}

async fn http_header_exists(client: &Client, eezo: &str, h: u64) -> Result<bool> {
    let url = format!("{}/bridge/header/{}", eezo.trim_end_matches('/'), h);
    let resp = client.get(&url).send().await?;
    Ok(resp.status().is_success())
}

// Fetch header JSON and return its public_inputs hex for height H
async fn fetch_header_pi(client: &Client, eezo: &str, h: u64) -> Result<Option<String>> {
    let url = format!("{}/bridge/header/{}", eezo.trim_end_matches('/'), h);
    let resp = client.get(&url).send().await?;
    if resp.status().is_success() {
        let hdr = resp.json::<HeaderResp>().await?;
        Ok(Some(hdr.public_inputs))
    } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
        Ok(None)
    } else {
        Err(anyhow!("header fetch status {}", resp.status()))
    }
}

// Parse core v2 fields from public_inputs hex:
// tx_root_v2, state_root_v2, sig_batch_digest, batch_len
fn parse_pi_core(pi_hex: &str) -> Result<(H256, H256, H256, u32)> {
    let b = hex_to_bytes(pi_hex)?;
    if b.len() < 32 * 8 {
        return Err(anyhow!("public_inputs too short ({} bytes), need ≥256", b.len()));
    }
    fn word(b: &[u8], i: usize) -> &[u8] { &b[i*32 .. (i+1)*32] }
    // words: [2]=tx_root_v2, [3]=state_root_v2, [4]=sig_batch_digest, [5]=batch_len (low 4 bytes)
    let tx_root = H256::from_slice(word(&b, 2));
    let st_root = H256::from_slice(word(&b, 3));
    let sigdig  = H256::from_slice(word(&b, 4));
    let bl = u32::from_be_bytes(word(&b, 5)[28..32].try_into().unwrap());
    Ok((tx_root, st_root, sigdig, bl))
}

// Parse chainId20 from public_inputs (word[6], right-aligned in 32 bytes)
fn parse_pi_chainid20(pi_hex: &str) -> Result<H160> {
    let b = hex_to_bytes(pi_hex)?;
    if b.len() < 32 * 8 {
        return Err(anyhow!("public_inputs too short ({} bytes), need ≥256", b.len()));
    }
    fn word(b: &[u8], i: usize) -> &[u8] { &b[i*32 .. (i+1)*32] }
    // bytes20 is right-aligned; take the last 20 bytes of the 32-byte word
    let w = word(&b, 6);
    Ok(H160::from_slice(&w[12..32]))
}

// + --- ADDED new async height-scoped proof reader ---

/// Async read a hex file, trimming whitespace and ensuring 0x prefix.
async fn read_hex_file_async(p: &PathBuf) -> Result<String> {
    let s = tokio::fs::read_to_string(p).await
        .with_context(|| format!("read {}", p.display()))?;
    Ok(ensure_0x(s.trim().to_string()))
}

/// Read proof/public_inputs from height-scoped paths **only when READY marker exists** (ASYNC):
///   {proof_root}/h{height}/READY                 (must exist to proceed)
///   {proof_root}/h{height}/proof.hex
///   {proof_root}/h{height}/public_inputs.hex
/// Ok(Some(..)) -> all present and READY; Ok(None) -> not yet ready; Err(e) -> real IO error
async fn read_height_scoped_proof(height: u64, cfg: &Config) -> Result<Option<(String, String)>> {
    let hdir = cfg.proof_dir.join(format!("h{height}"));
    let ready_path = hdir.join(READY_FILE);	
    let proof_path = hdir.join("proof.hex");
    let pubin_path = hdir.join("public_inputs.hex");

    // Require READY first (prover's atomic-completion signal)
    if tokio::fs::metadata(&ready_path).await.is_err() {
        return Ok(None);
    }

    // Check for file existence async
    let proof_meta = tokio::fs::metadata(&proof_path).await;
    let pubin_meta = tokio::fs::metadata(&pubin_path).await;

    match (proof_meta, pubin_meta) {
        (Ok(_), Ok(_)) => {
            // Both files exist, try to read them
            let proof = read_hex_file_async(&proof_path).await
                .with_context(|| format!("failed reading {}", proof_path.display()))?;
            let pubin = read_hex_file_async(&pubin_path).await
                .with_context(|| format!("failed reading {}", pubin_path.display()))?;
            Ok(Some((proof, pubin)))
        },
        // If either file is not found, return Ok(None)
        (Err(e), _) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        (_, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        // If we get an error other than NotFound, propagate it
        (Err(e), _) => Err(e).with_context(|| format!("failed checking metadata for {}", proof_path.display())),
        (_, Err(e)) => Err(e).with_context(|| format!("failed checking metadata for {}", pubin_path.display())),
    }
}
// + --- END new height-scoped proof reader ---
/// Optional, returns 0x-prefixed hex string if present.
async fn read_height_scoped_pi_digest(height: u64, cfg: &Config) -> Result<Option<String>> {
    let hdir = cfg.proof_dir.join(format!("h{height}"));
    let path = hdir.join("pi_digest.hex");
    match tokio::fs::metadata(&path).await {
        Ok(_) => {
            let s = read_hex_file_async(&path).await
                .with_context(|| format!("failed reading {}", path.display()))?;
            Ok(Some(s))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed checking metadata for {}", path.display())),
    }
}
struct RelayMetrics {
    attempts: AtomicU64,        // -> eezo_relay_submit_total
    successes: AtomicU64,       // -> eezo_relay_store_success_total
    onchain_height: AtomicU64,  // -> eezo_relay_onchain_height
    node_latest: AtomicU64,     // -> eezo_relay_node_latest_height
    backoff_secs: AtomicU64,    // -> eezo_relay_backoff_seconds
    // T37.3 extras
    pi_cv_mismatch_total: AtomicU64,     // -> eezo_bridge_pi_cv_mismatch_total
    submit_revert_total: AtomicU64,      // -> eezo_bridge_submit_revert_total
    suite_mismatch_total: AtomicU64,     // -> eezo_bridge_suite_mismatch_total
    strict_skips_total: AtomicU64,       // -> eezo_relay_strict_skips_total
    strict_mismatches_total: AtomicU64,  // -> eezo_relay_strict_mismatches_total
    strict_header_mismatch_total: AtomicU64,   // -> eezo_relay_strict_header_mismatch_total
    strict_chainid_mismatch_total: AtomicU64,  // -> eezo_relay_strict_chainid_mismatch_total
    // T38.7: count when digest file is missing
    pi_digest_missing_total: AtomicU64,        // -> eezo_relay_pi_digest_missing_total
    pi_digest_store_ok_total: AtomicU64,       // -> eezo_relay_pi_digest_store_ok_total
    pi_digest_store_err_total: AtomicU64,      // -> eezo_relay_pi_digest_store_err_total
    // T41.5 — qc_sidecar_v2 metrics
    sc_seen_total: AtomicU64,                  // -> eezo_qc_sidecar_v2_seen_total
    sc_valid_total: AtomicU64,                 // -> eezo_qc_sidecar_v2_valid_total
    sc_rejected_total: AtomicU64,              // -> eezo_qc_sidecar_v2_rejected_total
    sc_missing_total: AtomicU64,               // -> eezo_qc_sidecar_v2_missing_total
    sc_last_anchor_height: AtomicU64,          // -> eezo_qc_sidecar_v2_last_anchor_height
    // simple histogram buckets for anchor lag in blocks:
    // [0,1,2,4,8,16,32,64,128,+Inf]
    sc_lag_buckets: [AtomicU64; 10],
    sc_lag_sum: AtomicU64,
    sc_lag_count: AtomicU64,	
}

impl Default for RelayMetrics {
    fn default() -> Self {
        Self {
            attempts: Default::default(),
            successes: Default::default(),
            onchain_height: Default::default(),
            node_latest: Default::default(),
            backoff_secs: Default::default(),
            pi_cv_mismatch_total: Default::default(),
            submit_revert_total: Default::default(),
            suite_mismatch_total: Default::default(),
            strict_skips_total: Default::default(),
            strict_mismatches_total: Default::default(),
            strict_header_mismatch_total: Default::default(),
            strict_chainid_mismatch_total: Default::default(),
            pi_digest_missing_total: Default::default(),
            pi_digest_store_ok_total: Default::default(),
            pi_digest_store_err_total: Default::default(),
            sc_seen_total: Default::default(),
            sc_valid_total: Default::default(),
            sc_rejected_total: Default::default(),
            sc_missing_total: Default::default(),
            sc_last_anchor_height: Default::default(),
            sc_lag_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            sc_lag_sum: Default::default(),
            sc_lag_count: Default::default(),
        }
    }
}

impl RelayMetrics {
    fn inc_attempts(&self) { self.attempts.fetch_add(1, Ordering::Relaxed); }
    fn inc_successes(&self) { self.successes.fetch_add(1, Ordering::Relaxed); }
    fn set_onchain(&self, h: u64) { self.onchain_height.store(h, Ordering::Relaxed); }
    fn set_node_latest(&self, h: u64) { self.node_latest.store(h, Ordering::Relaxed); }
    fn set_backoff(&self, s: u64) { self.backoff_secs.store(s, Ordering::Relaxed); }
    fn render(&self) -> String {
        let strict_skips = self.strict_skips_total.load(Ordering::Relaxed);
        let strict_mism  = self.strict_mismatches_total.load(Ordering::Relaxed);		
        // derived "inflight" estimate = max(0, (node_latest - onchain) / 1)
        let on = self.onchain_height.load(Ordering::Relaxed);
        let nl = self.node_latest.load(Ordering::Relaxed);
        let inflight = nl.saturating_sub(on);
        format!(
            "eezo_relay_submit_total {}\n\
             eezo_relay_store_success_total {}\n\
             eezo_relay_onchain_height {}\n\
             eezo_relay_node_latest_height {}\n\
             eezo_relay_backoff_seconds {}\n\
             eezo_relay_backfill_inflight {}\n\
             eezo_bridge_pi_cv_mismatch_total {}\n\
             eezo_bridge_submit_revert_total {}\n\
             eezo_bridge_suite_mismatch_total {}\n\
             eezo_relay_strict_skips_total {}\n\
             eezo_relay_strict_mismatches_total {}\n\
             eezo_relay_strict_header_mismatch_total {}\n\
             eezo_relay_strict_chainid_mismatch_total {}\n\
             eezo_relay_pi_digest_missing_total {}\n\
             eezo_relay_pi_digest_store_ok_total {}\n\
             eezo_relay_pi_digest_store_err_total {}\n\
             eezo_qc_sidecar_v2_seen_total {}\n\
             eezo_qc_sidecar_v2_valid_total {}\n\
             eezo_qc_sidecar_v2_rejected_total {}\n\
             eezo_qc_sidecar_v2_missing_total {}\n\
             eezo_qc_sidecar_v2_last_anchor_height {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"0\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"1\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"2\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"4\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"8\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"16\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"32\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"64\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"128\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_bucket{{le=\"+Inf\"}} {}\n\
             eezo_qc_sidecar_v2_anchor_lag_sum {}\n\
             eezo_qc_sidecar_v2_anchor_lag_count {}\n",			 
            self.attempts.load(Ordering::Relaxed),
            self.successes.load(Ordering::Relaxed),
            self.onchain_height.load(Ordering::Relaxed),
            self.node_latest.load(Ordering::Relaxed),
            self.backoff_secs.load(Ordering::Relaxed),
            inflight,
            self.pi_cv_mismatch_total.load(Ordering::Relaxed),
            self.submit_revert_total.load(Ordering::Relaxed),
            self.suite_mismatch_total.load(Ordering::Relaxed),
            strict_skips,
            strict_mism,
            self.strict_header_mismatch_total.load(Ordering::Relaxed),
            self.strict_chainid_mismatch_total.load(Ordering::Relaxed),
            self.pi_digest_missing_total.load(Ordering::Relaxed),
            self.pi_digest_store_ok_total.load(Ordering::Relaxed),
            self.pi_digest_store_err_total.load(Ordering::Relaxed),
             self.sc_seen_total.load(Ordering::Relaxed),
             self.sc_valid_total.load(Ordering::Relaxed),
             self.sc_rejected_total.load(Ordering::Relaxed),
             self.sc_missing_total.load(Ordering::Relaxed),
             self.sc_last_anchor_height.load(Ordering::Relaxed),
             self.sc_lag_buckets[0].load(Ordering::Relaxed),
             self.sc_lag_buckets[1].load(Ordering::Relaxed),
             self.sc_lag_buckets[2].load(Ordering::Relaxed),
             self.sc_lag_buckets[3].load(Ordering::Relaxed),
             self.sc_lag_buckets[4].load(Ordering::Relaxed),
             self.sc_lag_buckets[5].load(Ordering::Relaxed),
             self.sc_lag_buckets[6].load(Ordering::Relaxed),
             self.sc_lag_buckets[7].load(Ordering::Relaxed),
             self.sc_lag_buckets[8].load(Ordering::Relaxed),
             self.sc_lag_buckets[9].load(Ordering::Relaxed),
             self.sc_lag_sum.load(Ordering::Relaxed),
             self.sc_lag_count.load(Ordering::Relaxed),			
        )
    }
    // --- sidecar helpers ---
    fn sc_seen(&self) { self.sc_seen_total.fetch_add(1, Ordering::Relaxed); }
    fn sc_valid(&self) { self.sc_valid_total.fetch_add(1, Ordering::Relaxed); }
    fn sc_rejected(&self) { self.sc_rejected_total.fetch_add(1, Ordering::Relaxed); }
    fn sc_missing(&self) { self.sc_missing_total.fetch_add(1, Ordering::Relaxed); }
    fn sc_set_last_anchor(&self, h: u64) { self.sc_last_anchor_height.store(h, Ordering::Relaxed); }
    fn sc_observe_lag(&self, lag: u64) {
        const EDGES: [u64; 10] = [0,1,2,4,8,16,32,64,128,u64::MAX];
        for (i, &le) in EDGES.iter().enumerate() {
            if lag <= le {
                self.sc_lag_buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sc_lag_sum.fetch_add(lag, Ordering::Relaxed);
        self.sc_lag_count.fetch_add(1, Ordering::Relaxed);
    }	
}

async fn serve_metrics(metrics: Arc<RelayMetrics>, bind: String) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(&bind).await
        .with_context(|| format!("bind metrics at {}", bind))?;
    info!("relay metrics listening on http://{}", bind);
    loop {
        let (mut sock, _) = listener.accept().await?;
        let m = metrics.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await; // naive read
            let body = m.render();
            let _ = sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                ).as_bytes()
            ).await;
            let _ = sock.shutdown().await;
        });
    }
}
// ───────────────────────────── T37.1: KEMTLS resume probe ─────────────────────────────
#[cfg(feature = "kemtls-resume")]
static TICKET: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

#[cfg(feature = "kemtls-resume")]
async fn kemtls_probe(cfg: &Config) -> Result<()> {
    let addr = match (&cfg.kemtls_addr, &cfg.kemtls_server_pk) {
        (Some(a), Some(pk_hex)) => (a.as_str(), pk_hex.as_str()),
        _ => return Ok(()), // not configured; noop
    };

    // Parse server public key (accepts `0x…` or raw hex)
    let pk_bytes = <Vec<u8>>::from_hex(strip_0x(addr.1))
        .context("EEZO_KEMTLS_SERVER_PK must be hex bytes")?;
    let server_pk = MlkemPk::from_bytes(pk_bytes.as_slice())
        .map_err(|_| anyhow!("EEZO_KEMTLS_SERVER_PK has wrong size/format"))?;

    // Dial
    let mut stream = TcpStream::connect(addr.0)
        .await
        .with_context(|| format!("connect KEMTLS to {}", addr.0))?;

    // Try resume if we have a cached ticket; otherwise full handshake
    let resumed: bool;
    let mut session: FramedSession;
    if let Some(t) = TICKET.lock().unwrap().take() {
        match client_connect_resume_async::<MlKem768, _>(&server_pk, t, &mut stream).await {
            Ok(fs) => { resumed = true; session = fs; }
            Err(_) => {
                // fall back to full handshake
                session = client_connect_async::<MlKem768, _>(&server_pk, &mut stream).await?;
                resumed = false;
            }
        }
    } else {
        session = client_connect_async::<MlKem768, _>(&server_pk, &mut stream).await?;
        resumed = false;
    }

    // Rotate ticket (if any) and drop the session (we only warm up)
    if let Some(newt) = session.new_ticket().map(|b| b.to_vec()) {
        *TICKET.lock().unwrap() = Some(newt);
    }
    let s = session.into_inner();
    tracing::info!("kemtls probe: resumed={} sid={:?}", s.resumed || resumed, s.session_id);
    Ok(())
}
// ─────────────────────────── end KEMTLS resume probe ─────────────────────────

// --- submit_header function UPDATED with argument order fix and V2 validation ---
async fn submit_header<C: Middleware + 'static>(
    contract: &EezoLightClient<C>,
    hdr: &HeaderResp,
) -> Result<TxHash> {
    let proof_b = hex_to_bytes(&hdr.proof)?;
    let pi_b    = hex_to_bytes(&hdr.public_inputs)?;

    // + NEW: Validate V2 public inputs structure
    if pi_b.len() >= 4 {
        // Read circuit version (first 4 bytes as u32)
        let cv_bytes = &pi_b[0..4];
        let cv = u32::from_be_bytes(cv_bytes.try_into().unwrap());
        
        if cv == 2 {
            // V2 expects 8-tuple ABI encoded bytes
            const MIN_V2_LEN: usize = 4 + 8 + 32 + 32 + 32 + 4 + 20 + 4;
            if pi_b.len() < MIN_V2_LEN {
                return Err(anyhow!("malformed v2 pubInputs (len={}, expected at least {})", 
                    pi_b.len(), MIN_V2_LEN));
            }
        }
    }

    // + FIXED: Correct argument order - proof first, then public_inputs
    let mut call = contract.verify_and_store(proof_b.into(), pi_b.into());

    // Gas override logic (keep as is)
    if let Ok(raw) = env::var("RELAY_GAS") {
        match raw.parse::<u64>() {
            Ok(gas) => {
                tracing::warn!("RELAY_GAS={} set → skipping gas estimation", gas);
                call = call.gas(U256::from(gas));
                if let Ok(gp_raw) = env::var("RELAY_GAS_PRICE") {
                    if let Ok(gwei) = gp_raw.parse::<u64>() {
                        let wei = U256::from(gwei) * U256::exp10(9);
                        call = call.gas_price(wei);
                        tracing::info!("using RELAY_GAS_PRICE={} gwei", gwei);
                    } else {
                        tracing::warn!("RELAY_GAS_PRICE='{}' is not a u64 gwei; ignoring", gp_raw);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("RELAY_GAS='{}' not a u64 ({}); falling back to estimation", raw, e);
            }
        }
    }

    let pending = call
        .send()
        .await
        .context("send verifyAndStore")?;

    let tx_hash = pending.tx_hash();

    // + IMPROVED: Handle idempotent replay errors gracefully
    match pending.await.context("wait receipt")? {
        Some(rcpt) => {
            tracing::info!("verifyAndStore tx sent: tx={:?} status={:?}", rcpt.transaction_hash, rcpt.status);
            if rcpt.status == Some(1.into()) {
                Ok(rcpt.transaction_hash)
            } else {
                Err(anyhow!("transaction {:?} failed with status {:?}", rcpt.transaction_hash, rcpt.status))
            }
        },
        None => {
            tracing::info!("verifyAndStore sent (no receipt yet), tx={:?}", tx_hash);
            Err(anyhow!("transaction dropped or not mined"))
        },
    }
}

// --- hex_preview remains unchanged ---
fn hex_preview(label: &str, s: &str) -> String {
    let h = strip_0x(s);
    let take = h.chars().take(16).collect::<String>();
    let len = h.len() / 2;
    format!("{}: {} bytes (0x{}…)", label, len, take)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Initializing relay...");
    dotenv().ok();
    // Greppable one-liner handshake (T37.7)
    let v = ssz_versions("relay");
    println!("{}", v.to_log_line());	
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    info!("Relay logging initialized.");

    // cheap CLI: eezo-relay inspect-ckpt <path>
    if let Some(cmd) = std::env::args().nth(1) {
        if cmd == "inspect-ckpt" {
            let p = std::env::args().nth(2).expect("usage: eezo-relay inspect-ckpt <path>");
            let f = std::fs::File::open(&p).with_context(|| format!("open {}", p))?;
            let r = std::io::BufReader::new(f);
            let hdr: eezo_ledger::checkpoints::BridgeHeader = serde_json::from_reader(r)
                .with_context(|| format!("parse {}", p))?;
            match eezo_ledger::checkpoints::validate_sidecar_v2_for_header(&hdr) {
                Ok(()) => {
                    if let Some(sc) = &hdr.qc_sidecar_v2 {
                        let lag = hdr.height.saturating_sub(sc.anchor_height);
                        println!(
                            "status: OK | h={} anchor={} suite={} reason={} lag={}",
                            hdr.height, sc.anchor_height, hdr.suite_id, reason_str(&sc.reason), lag
                        );
                    } else {
                        println!("status: OK | no sidecar");
                    }
                    std::process::exit(0);
                }
                Err(code) => {
                    eprintln!("status: FAIL | h={} code={}", hdr.height, code);
                    std::process::exit(1);
                }
            }
        }
    }

    // ── SSZ bridge ↔ ledger version handshake (advertise + assert compatibility)
    log_ssz_versions("relay");
    assert_compat_or_warn();
    let cfg = Config::from_env()?;
	if cfg.strict_pi { info!("strict mode enabled: PI value checks active"); }
    info!("relay starting; env={}, chain_id={}, poll={}s backoff_cap={}s",
        env::var("ENV").unwrap_or_else(|_| "local".into()),
        cfg.evm_chain_id, cfg.poll_secs, cfg.backoff_max_secs);
    if cfg.dry_run {
        warn!("DRY_RUN=1 → transactions will NOT be sent; logging intended verifyAndStore calls");
    }
    if cfg.dev_trusted_store {
        warn!("DEV_TRUSTED_STORE=1 set, but Harness path is not wired yet; falling back to verifyAndStore flow");
    }

    let provider = Provider::<Http>::try_from(cfg.rpc.as_str())
        .context("bad RPC")?;
    let wallet = LocalWallet::from_str(&cfg.pk).context("bad PK")?
        .with_chain_id(cfg.evm_chain_id);
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let addr = Address::from_str(&cfg.lc_addr).context("bad LC_ADDR")?;
    let lc = EezoLightClient::new(addr, client.clone());
    
    // Optional SNARK verifier adapter (if SNARK_VERIFIER_ADDR is provided)
    let snark_client = snark::SnarkClient::try_new( // <<< PATCH 3: Initialize SNARK client
        std::env::var("SNARK_VERIFIER_ADDR").ok(),
        client.clone()
    ).map_err(|e| anyhow!("snark client init: {e}"))?;

    let http = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let metrics = Arc::new(RelayMetrics::default());
    {
        let m = metrics.clone();
        let bind = cfg.metrics_bind.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(m, bind).await {
                warn!("metrics server failed: {}", e);
            }
        });
    }
    // Fetch LC expected chainId20 once at startup (strict-mode uses this)
    let expected_chainid20: H160 = {
        // abigen for `expectedChainId20() returns (bytes20)` generates a method
        // named `expected_chain_id_20()`; it returns a fixed 20-byte value.
        match lc.expected_chain_id_20().call().await {
            Ok(b20) => {
                // handle both FixedBytes<20> and [u8;20] via Into
                let arr: [u8; 20] = b20.into();
                H160::from(arr)
            }
            Err(e) => {
                warn!("failed to read expectedChainId20(): {} — defaulting to 0x00..00", e);
                H160::zero()
            }
        }
    };
    info!("strict: expectedChainId20={:?}", expected_chainid20);

    // initial on-chain height & initial rotation view
    let onchain_latest: u64 = lc
        .latest_height()
        .call()
        .await
        .unwrap_or(0);
    let mut rot = match refresh_rotation_view(&lc).await {
        Ok(v) => v,
        Err(e) => {
            warn!("rotation view fetch failed (using defaults): {}", e);
            RotationView::default()
        }
    };
    info!("rotation view: active={}, next={}, dualUntil={}, allow_cv2={}",
        rot.active_suite, rot.next_suite, rot.dual_accept_until, rot.allow_cv2);		
    let mut target: u64 = if onchain_latest == 0 {
        cfg.checkpoint_every
    } else {
        align_up(onchain_latest + 1, cfg.checkpoint_every)
    };
    info!("starting relay from target height {} (onchain_latest={}, step={})",
          target, onchain_latest, cfg.checkpoint_every);

    let poll = Duration::from_secs(cfg.poll_secs);
    let mut backoff = Duration::from_secs(1);
    let backoff_cap = Duration::from_secs(cfg.backoff_max_secs);
    let mut attempts: u64 = 0;
    let mut successes: u64 = 0;
    // T37.6: dedup — remember last submitted height
    let mut last_submitted_h: u64 = 0;
    // refresh rotation view every N loops (cheap and safe)
    let mut rot_refresh_tick: u32 = 0;
    // T38.7: warn once per height when digest missing; and strict gate toggle
    let mut warned_no_digest: HashSet<u64> = HashSet::new();
    let digest_required = env_bool("EEZO_PI_DIGEST_REQUIRED", false);	
    
    #[cfg(feature = "kemtls-resume")]
    if cfg.kemtls_addr.is_some() && cfg.kemtls_server_pk.is_some() {
        if let Err(e) = kemtls_probe(&cfg).await {
            warn!("kemtls probe failed: {}", e);
        }
    }
    
    loop {
        #[cfg(feature ="kemtls-resume")]
        if cfg.kemtls_addr.is_some() && cfg.kemtls_server_pk.is_some() {
            if let Err(e) = kemtls_probe(&cfg).await {
                debug!("kemtls probe (loop) failed: {}", e);
            }
        }
        
        match lc.latest_height().call().await {
            Ok(onchain) => {
                metrics.set_onchain(onchain);
                // periodic rotation refresh (every ~10 loops)
                rot_refresh_tick = rot_refresh_tick.wrapping_add(1);
                if rot_refresh_tick % 10 == 1 {
                    if let Ok(v) = refresh_rotation_view(&lc).await {
                        if v != rot {
                            info!("rotation view updated: active={} next={} dualUntil={} allow_cv2={}",
                                  v.active_suite, v.next_suite, v.dual_accept_until, v.allow_cv2);
                        }
                        rot = v;
                    }
                }				
                if target <= onchain {
                    target = align_up(onchain + 1, cfg.checkpoint_every);
                    info!("on-chain height {} >= current target; advanced target to {}", onchain, target);
                    backoff = Duration::from_secs(1);
                    metrics.set_backoff(backoff.as_secs());
                    tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                    continue;
                }

                match fetch_summary(&http, &cfg.eezo).await {
                    Ok(sum) => {
                        debug!("onchain={}, node_latest={}", onchain, sum.latest_height);
                        metrics.set_node_latest(sum.latest_height);
                        if sum.latest_height < target {
                            debug!("node latest {} < target {}; sleeping {}s", sum.latest_height, target, cfg.poll_secs);
                            tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                            continue;
                        }

                        {
                            attempts += 1;
                            metrics.inc_attempts();
                            info!("attempting store for height {}", target);

                            match http_header_exists(&http, &cfg.eezo, target).await {
                                Ok(true) => { /* proceed */ }
                                Ok(false) => {
                                    warn!("node summary indicated >= h{}, but header endpoint 404'd; skipping to next +{}", target, cfg.checkpoint_every);
                                    target = target.saturating_add(cfg.checkpoint_every);
                                    tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                    continue;
                                }
                                Err(e) => {
                                    warn!("http presence check failed for h={}: {}", target, e);
                                    backoff = std::cmp::min(backoff * 2, backoff_cap);
                                    metrics.set_backoff(backoff.as_secs());
                                    tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                                    continue;
                                }
                            }

                            let proof_hex: String;
                            let pubin_hex: String;

                            match read_height_scoped_proof(target, &cfg).await {
                                Ok(Some(t)) => {
                                    (proof_hex, pubin_hex) = t;
                                    backoff = Duration::from_secs(1);
                                    metrics.set_backoff(backoff.as_secs());
									
									// T41.5: parse/validate qc_sidecar_v2 and export metrics
									let rot_policy = eezo_ledger::checkpoints::rotation_policy_from_env();
									check_sidecar_for_height(&metrics, &cfg, target, &rot_policy).await;
									
                                }
                                Ok(None) => {
                                    info!(
                                        "waiting for READY + proof files for h={} in {}/h{}/ ...",
                                        target, cfg.proof_dir.display(), target
                                    );
                                    tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                    continue;
                                }
                                Err(e) => {
                                    error!("failed to read proof files for h={}: {}", target, e);
                                    backoff = std::cmp::min(backoff * 2, backoff_cap);
                                    metrics.set_backoff(backoff.as_secs());
                                    tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                                    continue;
                                }
                            }
                            
                            // T37.6: dedup — skip if already submitted
                            if target == last_submitted_h {
                                info!("dedup: already submitted h{}; skipping", target);
                                tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                continue;
                            }

                            let hdr = HeaderResp {
                                proof: proof_hex,
                                public_inputs: pubin_hex,
                                height: target,
                            };
                            // T38.7: optional/strict handling for pi_digest.hex
                            let pi_digest_hex_opt = read_height_scoped_pi_digest(target, &cfg).await?;
                            if digest_required && pi_digest_hex_opt.is_none() {
                                metrics.pi_digest_missing_total.fetch_add(1, Ordering::Relaxed);
                                if warned_no_digest.insert(target) {
                                    warn!("pi_digest.hex missing for h{} — strict mode enabled (EEZO_PI_DIGEST_REQUIRED=1); skipping submission", target);
                                }
                                backoff = std::cmp::min(backoff * 2, backoff_cap);
                                metrics.set_backoff(backoff.as_secs());
                                tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                                continue;
                            }
                            // ── T37.3 submit-gate: parse PI → (cv, suite), then gate by rotation view
                            let (cv, suite, height_opt) = match parse_pi_cv_and_suite(&hdr.public_inputs) {
                                Ok(t) => t,
                                Err(e) => {
                                    warn!("skip h{}: cannot parse public_inputs ({}).", target, e);
                                    metrics.pi_cv_mismatch_total.fetch_add(1, Ordering::Relaxed);
                                    tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                    continue;
                                }
                            };
                            if cv != 2 {
                                warn!("skip h{}: circuit_version {} not accepted (expect 2).", target, cv);
                                metrics.pi_cv_mismatch_total.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                continue;
                            }
                            if !rot.allow_cv2 {
                                warn!("skip h{}: LC says circuit v2 not allowed yet.", target);
                                metrics.suite_mismatch_total.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                continue;
                            }
                            // sanity: if PI encodes height, make sure it matches target (best-effort)
                            if let Some(h_pi) = height_opt {
                                if h_pi != target {
                                    warn!("strict: header mismatch — PI.height={} != header/target={} (skip)", h_pi, target);
                                    metrics.strict_header_mismatch_total.fetch_add(1, Ordering::Relaxed);
                                    metrics.strict_skips_total.fetch_add(1, Ordering::Relaxed);
                                    tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                    continue;
                                }
                            }
                            if !rot.suite_allowed_for_height(target, suite) {
                                warn!("skip h{}: suite {} not accepted (active={}, next={}, dualUntil={}).",
                                    target, suite, rot.active_suite, rot.next_suite, rot.dual_accept_until);
                                metrics.suite_mismatch_total.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                continue;
                            }
                            // ── T37.7: strict mode v1 (value checks only; no SSZ recompute)
                            if cfg.strict_pi {
                                match fetch_header_pi(&http, &cfg.eezo, target).await {
                                    Ok(Some(h_pi_hex)) => {
                                        // Parse both: file PI (prover output) vs header PI (node view)
                                        let (tx_f, st_f, sig_f, bl_f) = match parse_pi_core(&hdr.public_inputs) {
                                            Ok(t) => t,
                                            Err(e) => {
                                                warn!("strict: bad local PI at h{}: {} (skip)", target, e);
                                                metrics.strict_skips_total.fetch_add(1, Ordering::Relaxed);
                                                backoff = std::cmp::min(backoff * 2, backoff_cap);
                                                metrics.set_backoff(backoff.as_secs());
                                                tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                                                continue;
                                            }
                                        };
                                        let (tx_h, st_h, _sig_h, _bl_h) = match parse_pi_core(&h_pi_hex) {
                                            Ok(t) => t,
                                            Err(e) => {
                                                warn!("strict: bad header PI at h{}: {} (skip)", target, e);
                                                metrics.strict_skips_total.fetch_add(1, Ordering::Relaxed);
                                                backoff = std::cmp::min(backoff * 2, backoff_cap);
                                                metrics.set_backoff(backoff.as_secs());
                                                tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                                                continue;
                                            }
                                        };
                                        // zero checks
                                        if tx_f.is_zero() || st_f.is_zero() || sig_f.is_zero() || bl_f == 0 {
                                            warn!("strict: zero field(s) in local PI at h{} (skip)", target);
                                            metrics.strict_skips_total.fetch_add(1, Ordering::Relaxed);
                                            backoff = std::cmp::min(backoff * 2, backoff_cap);
                                            metrics.set_backoff(backoff.as_secs());
                                            tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                                            continue;
                                        }
                                        // equality checks vs header view
                                        if tx_f != tx_h || st_f != st_h {
                                            warn!("strict: header vs PI mismatch at h{} (tx_root or state_root)", target);
                                            metrics.strict_mismatches_total.fetch_add(1, Ordering::Relaxed);
                                            metrics.strict_skips_total.fetch_add(1, Ordering::Relaxed);
                                            backoff = std::cmp::min(backoff * 2, backoff_cap);
                                            metrics.set_backoff(backoff.as_secs());
                                            tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                                            continue;
                                        }
                                        // chainId20 guard against LC expectation
                                        match parse_pi_chainid20(&hdr.public_inputs) {
                                            Ok(ci_local) => {
                                                if ci_local != expected_chainid20 {
                                                    warn!("strict: chainId20 mismatch at h{} — PI={:?} LC.expected={:?} (skip)", target, ci_local, expected_chainid20);
                                                    metrics.strict_chainid_mismatch_total.fetch_add(1, Ordering::Relaxed);
                                                    metrics.strict_skips_total.fetch_add(1, Ordering::Relaxed);
                                                    tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                                    continue;
                                                }
                                            }
                                            Err(e) => {
                                                warn!("strict: failed to parse chainId20 at h{}: {} (skip)", target, e);
                                                metrics.strict_skips_total.fetch_add(1, Ordering::Relaxed);
                                                tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                                continue;
                                            }
                                        }										
                                    }
                                    Ok(None) => {
                                        warn!("strict: header PI missing at h{} (404); skip this height", target);
                                        metrics.strict_skips_total.fetch_add(1, Ordering::Relaxed);
                                        tokio::time::sleep(jittered(poll.as_millis() as u64)).await;
                                        continue;
                                    }
                                    Err(e) => {
                                        warn!("strict: header fetch failed at h{}: {}", target, e);
                                        backoff = std::cmp::min(backoff * 2, backoff_cap);
                                        metrics.set_backoff(backoff.as_secs());
                                        tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                                        continue;
                                    }
                                }
                            } 							
                            if cfg.dry_run {
                                let pi_preview = hex_preview("public_inputs", &hdr.public_inputs);
                                let proof_preview = hex_preview("proof", &hdr.proof);
                                info!(
                                    "DRY_RUN: would call verifyAndStore(height={}) [{}; {}]",
                                    hdr.height, pi_preview, proof_preview
                                );
                                successes += 1;
                                metrics.inc_successes();
                                last_submitted_h = target; // T37.6: dedup
                                backoff = Duration::from_secs(1);
                                metrics.set_backoff(backoff.as_secs());
                            } else {
                                match submit_header(&lc, &hdr).await {
                                    Ok(_tx) => {
                                        successes += 1;
                                        metrics.inc_successes();
                                        last_submitted_h = target; // T37.6: dedup
                                        backoff = Duration::from_secs(1);
                                        metrics.set_backoff(backoff.as_secs());

                                        // ── T39.3: SNARK-on-chain path (optional) → else fallback to storePiDigest ──
                                        let mut snark_attempted = false; // <<< PATCH 4: SNARK-first/fallback logic
                                        
                                        if cfg.snark_onchain {
                                            if let Some(sc) = snark_client.as_ref() {
                                                // need both: proof bytes and a 32-byte digest for this height
                                                match snark::read_snark_proof(&cfg.proof_dir, target).await {
                                                    Ok(Some(proof_bytes)) => {
                                                        match snark::read_pi_digest_32(&cfg.proof_dir, target).await {
                                                            Ok(Some(d32)) => {
                                                                snark_attempted = true;
                                                                match sc.submit(target, d32, proof_bytes.clone()).await {
                                                                    Ok(Some(tx_hash)) => {
                                                                        info!(
                                                                            "SNARK ok: verifyAndStorePiDigest(h={}, len={}) tx={:?}",
                                                                            target,
                                                                            proof_bytes.len(),
                                                                            tx_hash
                                                                        );
                                                                        // note: we DO NOT call storePiDigest after a successful SNARK path
                                                                    }
                                                                    Ok(None) => {
                                                                        // mined but reverted → fallback
                                                                        warn!(
                                                                            "SNARK revert at h{} (len={}): falling back to storePiDigest",
                                                                            target,
                                                                            proof_bytes.len()
                                                                        );
                                                                    }
                                                                    Err(e) => {
                                                                        // send/await failure → fallback
                                                                        warn!(
                                                                            "SNARK submit failed at h{}: {} — falling back to storePiDigest",
                                                                            target, e
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                            Ok(None) => {
                                                                // digest missing or wrong length → fallback
                                                                debug!("SNARK path: pi_digest.hex missing or not 32 bytes at h{}", target);
                                                            }
                                                            Err(e) => {
                                                                warn!("SNARK path: error reading pi_digest for h{}: {}", target, e);
                                                            }
                                                        }
                                                    }
                                                    Ok(None) => {
                                                        // no proof present → fallback
                                                        debug!("SNARK path: no snark_proof.(bin|hex) for h{}", target);
                                                    }
                                                    Err(e) => {
                                                        warn!("SNARK path: error reading snark proof for h{}: {}", target, e);
                                                    }
                                                }
                                            } else {
                                                debug!("SNARK path enabled, but SNARK_VERIFIER_ADDR not set — skipping SNARK call");
                                            }
                                        }

                                        // Fallback (or SNARK disabled / not attempted): store canonical PI digest
                                        if !snark_attempted {
                                            match &pi_digest_hex_opt {
                                                Some(dhex) => {
                                                    match hex_to_bytes(dhex) {
                                                        Ok(bytes) if bytes.len() == 32 => {
                                                            let digest = H256::from_slice(&bytes);
                                                            let d_arr: [u8; 32] = digest.into();
                                                            let call = lc.store_pi_digest(target, d_arr);
                                                            match call.send().await {
                                                                Ok(p) => {
                                                                    let _ = p.await;
                                                                    metrics.pi_digest_store_ok_total.fetch_add(1, Ordering::Relaxed);
                                                                    info!(
                                                                        "storePiDigest ok h={} d=0x{}",
                                                                        target,
                                                                        hex::encode(digest.as_bytes())
                                                                    );
                                                                }
                                                                Err(e) => {
                                                                    metrics.pi_digest_store_err_total.fetch_add(1, Ordering::Relaxed);
                                                                    warn!("storePiDigest failed h{}: {}", target, e);
                                                                }
                                                            };
                                                        }
                                                        Ok(bytes) => {
                                                            warn!(
                                                                "pi_digest.hex for h{} len={} (want 32), skipping",
                                                                target,
                                                                bytes.len()
                                                            );
                                                        }
                                                        Err(e) => warn!("pi_digest.hex parse error h{}: {}", target, e),
                                                    }
                                                }
                                                None => {
                                                    metrics.pi_digest_missing_total.fetch_add(1, Ordering::Relaxed);
                                                    if warned_no_digest.insert(target) {
                                                        warn!(
                                                            "pi_digest.hex missing for h{} (optional mode) — header stored, no digest submitted",
                                                            target
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        // + PATCH START: IMPROVED IDEMPOTENT REVERT HANDLING
                                        let err_msg = e.to_string();
                                        if err_msg.contains("non-monotonic height") || 
                                           err_msg.contains("header mismatch") {
                                            info!("idempotent replay at height={} (LC already accepted or data identical). Treating as success.", target);
                                            successes += 1; // Treat as success
                                            metrics.inc_successes();
                                            last_submitted_h = target; // T37.6: dedup
                                            backoff = Duration::from_secs(1);
                                            metrics.set_backoff(backoff.as_secs());
                                        } else {
                                        // + PATCH END: IMPROVED IDEMPOTENT REVERT HANDLING
                                            error!("store failed at h={}: {}", target, e);
											metrics.submit_revert_total.fetch_add(1, Ordering::Relaxed);
                                            backoff = std::cmp::min(backoff * 2, backoff_cap);
                                            metrics.set_backoff(backoff.as_secs());
                                            tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                                            continue;
                                        }
                                    }
                                }
                            }
                            // T37.6: optional GC
                            let gc_height = target.saturating_sub(cfg.keep_heights);
                            let gc_dir = cfg.proof_dir.join(format!("h{}", gc_height));
                            if gc_height > 0 && gc_dir.exists() {
                                if let Err(e) = tokio::fs::remove_dir_all(&gc_dir).await {
                                    debug!("relay GC failed for {}: {}", gc_dir.display(), e);
                                } else {
                                    info!("relay GC: removed {}", gc_dir.display());
                                }
                            }
                            
                            target = target.saturating_add(cfg.checkpoint_every);
                        }
                    }
                    Err(e) => {
                        warn!("summary fetch failed: {}", e);
                        backoff = std::cmp::min(backoff * 2, backoff_cap);
                        metrics.set_backoff(backoff.as_secs());
                        tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
                    }
                }
            }
            Err(e) => {
                error!("latestHeight() call failed: {}", e);
                backoff = std::cmp::min(backoff * 2, backoff_cap);
                metrics.set_backoff(backoff.as_secs());
                tokio::time::sleep(jittered(backoff.as_millis() as u64)).await;
            }
        }
        if (attempts + successes) % 10 == 1 {
            info!("relay stats: attempts={}, successes={}", attempts, successes);
        }
    }
}