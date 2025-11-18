#[cfg(feature = "state-sync")]
mod state_sync;
// Build the http::state module when either state-sync OR checkpoints are on,
// because the bridge endpoints live there and only require checkpoints.
// Keep http module for the other endpoints you already expose.
// It should build when either state-sync or state-sync-http is on.
#[cfg(any(feature = "state-sync", feature = "state-sync-http"))]
mod http {
    pub mod state;
}

// Bridge endpoints are implemented in crates/node/src/bridge.rs
#[cfg(feature = "checkpoints")]
mod bridge;
#[cfg(feature = "checkpoints")]
use crate::bridge::{
    get_bridge_header as _get_bridge_by_height,
    get_bridge_header_latest as _get_bridge_latest,
	// T36.6: index endpoint
	get_bridge_index as _get_bridge_index,
    // T36.7: summary endpoint
    get_bridge_summary as _get_bridge_summary,
    // T36.8: branch/prove endpoints
    get_bridge_branch as _get_bridge_branch,
    get_bridge_prove  as _get_bridge_prove,
    // NEW (T36.8): POST writer for proof/public_inputs
    post_bridge_prove as _post_bridge_prove,
	
};
#[cfg(feature = "checkpoints")]
use axum::routing::get as _get_bridge_get;

use anyhow::Context;
use axum::http::StatusCode;
use axum::{
    extract::{Path as AxumPath, Query},
    extract::State,
	routing::{get, post},
    Json, Router,
};
use axum::response::{IntoResponse, Response};
#[cfg(feature = "dev-tools")]
use axum::body::Bytes;
// PathBuf is needed even when only `checkpoints` is enabled (e.g., resolve_outbox_dir).
use std::path::PathBuf;
use clap::Parser;
use eezo_ledger::{Block, BlockHeader};
#[cfg(feature = "persistence")]
use eezo_ledger::{Supply, StateSnapshot};
#[cfg(feature = "pq44-runtime")]
use eezo_ledger::consensus::{SingleNode, SingleNodeCfg};
use std::time::{SystemTime, UNIX_EPOCH};
// Persistence (RocksDB) + genesis helpers are only available when the binary
// is built with the `persistence` feature.
#[cfg(feature = "persistence")]
use eezo_ledger::config::PersistenceCfg;
#[cfg(feature = "persistence")]
use eezo_ledger::persistence;
#[cfg(feature = "persistence")]
use eezo_ledger::{ensure_genesis, GenesisConfig};
use tokio::sync::{RwLock, Mutex as AsyncMutex};
use eezo_ledger::bridge::{BridgeState, OutboxEvent};
use std::collections::{HashMap as Map, VecDeque};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
// (removed duplicate PathBuf import)
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::time::interval;

mod metrics;
mod peers;
mod mempool;
mod accounts;
use peers::{parse_peers_from_env, peers_handler, PeerMap, PeerService};
use accounts::{Accounts, AccountView, FaucetReq};
mod addr;
use crate::addr::parse_account_addr;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use axum::serve;

#[cfg(any(feature = "pq44-runtime", feature = "state-sync", feature="consensus-core-adapter"))]
mod consensus_runner;

// T36.6: expose bridge metrics immediately at boot
// metrics registrars used at boot
#[cfg(feature = "metrics")]
use crate::metrics::{
    register_t33_bridge_metrics,
    register_t34_rotation_metrics,
    register_t36_bridge_metrics,
    register_t37_kemtls_metrics,
    register_t40_shadow_sig_metrics,
    register_t40_cutover_metrics,
};

// ─── Helper: build subrouter for bridge endpoints (safe when features off) ─────
#[cfg(feature = "checkpoints")]
fn build_bridge_router() -> axum::Router<AppState> {
    axum::Router::new()
	    // T36.8: inclusion branch + prove helpers
		.route("/bridge/branch", _get_bridge_get(_get_bridge_branch))
        // keep GET /bridge/prove (reader) and ADD POST /bridge/prove (writer)
		.route("/bridge/prove",  _get_bridge_get(_get_bridge_prove))
        .route("/bridge/prove",  post(_post_bridge_prove))
        // T36.7: compact summary for relay/dashboard
        .route("/bridge/summary", _get_bridge_get(_get_bridge_summary))
	    // index of emitted checkpoints (paged)
		.route("/bridge/index", _get_bridge_get(_get_bridge_index))
        // put "latest" first so it doesn't get captured by :height
        .route("/bridge/header/latest", _get_bridge_get(_get_bridge_latest))
        .route("/bridge/header/:height", _get_bridge_get(_get_bridge_by_height))
}

#[cfg(not(feature = "checkpoints"))]
fn build_bridge_router() -> axum::Router<AppState> {
    axum::Router::new()
}


// T36.2: core runner handle (SingleNode path)
#[cfg(feature = "pq44-runtime")]
use crate::consensus_runner::CoreRunnerHandle;
// If you compile the adapter/testing path, make it mutually exclusive with pq44-runtime.
#[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
use crate::consensus_runner::CoreRunnerHandle;

// T36.2: Vote/Qc types only when adapter/testing path is on (and pq44-runtime is off)
#[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
use consensus_core::prelude::{Vote, Qc, ViewId, BlockId, ValidatorId};

use axum::extract::rejection::JsonRejection;

#[cfg(feature = "metrics")]
use prometheus::{register_int_counter, IntCounter};
#[cfg(feature = "metrics")]
static ADMIN_PEERS_UPDATE_TOTAL: once_cell::sync::Lazy<IntCounter> =
    once_cell::sync::Lazy::new(|| {
        register_int_counter!(
            "eezo_node_admin_peers_update_total",
            "Total number of admin peer updates"
        )
        .expect("metric")
    });
// T30 tx metrics
#[cfg(feature = "metrics")]
static TX_ACCEPTED_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_tx_accepted_total", "Txs accepted into a block").expect("metric")
});
#[cfg(feature = "metrics")]
static TX_REJECTED_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
	// renamed to avoid clashing with EEZO_TX_REJECTED_TOTAL (IntCounterVec) in metrics.rs
	register_int_counter!(
	    "eezo_tx_rejected_simple_total",
		"Txs rejected by proposer (simple, unlabelled)"
	).expect("metric")
});
fn check_admin_token(state: &AppState, token: Option<&str>) -> bool {
    matches!((&state.admin_token, token), (Some(expected), Some(provided)) if expected == provided)
}

async fn config_handler(State(state): State<AppState>) -> Json<RuntimeConfigView> {
    let mut rc = state.runtime_config.clone();
    let mut peers: Vec<String> = state.peers.read().await.keys().cloned().collect();
    peers.sort();
    peers.dedup();
    rc.peers = peers;
    // Keep T34 fields in sync with current AppState (if they change later)
	rc.active_suite_id   = state.active_suite_id;
    rc.next_suite_id     = state.next_suite_id;
	rc.dual_accept_until = state.dual_accept_until;
    Json(rc)
}

async fn health_handler() -> &'static str {
    "ok"
}

async fn ready_handler(State(state): State<AppState>) -> (StatusCode, &'static str) {
    let ready_status = state.ready_flag.load(Ordering::SeqCst);
    log::info!("Received /ready ping, responding with {:?}", ready_status);
	println!("🔍 /ready endpoint called - readiness flag = {}", ready_status);
    if ready_status {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "degraded")
    }
}

async fn admin_degrade(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, &'static str) {
    if let Some(expected) = &state.admin_token {
        if q.get("token").map(|s| s.as_str()) == Some(expected.as_str()) {
            state.ready_flag.store(false, Ordering::SeqCst);
            #[cfg(feature = "metrics")]
            {
                crate::metrics::EEZO_NODE_READY.set(0);
                NODE_READY_DEGRADE_TOTAL.inc();
            }
            return (StatusCode::OK, "ready=false");
        }
        return (StatusCode::FORBIDDEN, "forbidden");
    }
    (StatusCode::NOT_FOUND, "disabled")
}

async fn admin_restore(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, &'static str) {
    if let Some(expected) = &state.admin_token {
        if q.get("token").map(|s| s.as_str()) == Some(expected.as_str()) {
            state.ready_flag.store(true, Ordering::SeqCst);
            #[cfg(feature = "metrics")]
            {
                crate::metrics::EEZO_NODE_READY.set(1);
                NODE_READY_RESTORE_TOTAL.inc();
            }
            return (StatusCode::OK, "ready=true");
        }
        return (StatusCode::FORBIDDEN, "forbidden");
    }
    (StatusCode::NOT_FOUND, "disabled")
}

async fn admin_peers_handler(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let token = q.get("token").map(|s| s.as_str());
    if !check_admin_token(&state, token) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        );
    }
    let peers_map = state.peers.read().await;
    let mut peers: Vec<_> = peers_map
        .iter()
        .map(|(k, v)| {
            serde_json::json!({
                "url": k,
                "ready": v.ready,
            })
        })
        .collect();

    peers.sort_by(|a, b| a["url"].as_str().cmp(&b["url"].as_str()));
    (StatusCode::OK, Json(serde_json::json!({ "peers": peers })))
}

#[derive(serde::Deserialize)]
struct AdminReloadPeers(Vec<String>);

async fn admin_peers_update_handler(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    body: Result<Json<AdminReloadPeers>, JsonRejection>,
) -> (StatusCode, &'static str) {
    let token = q.get("token").map(|s| s.as_str());
    if !check_admin_token(&state, token) {
        return (StatusCode::FORBIDDEN, "forbidden");
    }
    let peers_from_body = body
        .ok()
        .map(|Json(AdminReloadPeers(v))| v)
        .unwrap_or_default();
    let new_peers: Vec<String> = peers_from_body
        .into_iter()
        .map(|p| p.trim().trim_end_matches('/').to_string())
        .collect();
    state
        .peer_svc
        .set_peers(dedup_preserve_order(new_peers))
        .await;
    #[cfg(feature = "metrics")]
    ADMIN_PEERS_UPDATE_TOTAL.inc();
    (StatusCode::OK, "ok")
}

async fn admin_runtime_handler(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let token = q.get("token").map(|s| s.as_str());
    if !check_admin_token(&state, token) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        );
    }
    let now = SystemTime::now();
    let uptime = now
        .duration_since(state.started_at)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let ready = state.ready_flag.load(Ordering::SeqCst);
    let peer_count = state.peers.read().await.len();
    let pid = std::process::id();
    let version = state.version;
    let node_id = state.identity.node_id.clone();
    let out = serde_json::json!({
        "pid": pid,
        "uptime_secs": uptime,
        "ready": ready,
        "peers_total": peer_count,
        "version": version,
        "node_id": node_id,
    });
    (StatusCode::OK, Json(out))
}

#[derive(serde::Serialize)]
struct StatusView {
    pid: u32,
    uptime_secs: u64,
    ready: bool,
    listen: String,
    datadir: String,
    version: String,
    git_sha: Option<String>,
    node_id: String,
    first_seen: u64,
}

async fn status_handler(State(state): State<AppState>) -> Json<StatusView> {
    let now = SystemTime::now();
    let uptime = now
        .duration_since(state.started_at)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    Json(StatusView {
        pid: std::process::id(),
        uptime_secs: uptime,
        ready: state.ready_flag.load(Ordering::SeqCst),
        listen: state.runtime_config.node.listen.clone(),
        datadir: state.runtime_config.node.datadir.clone(),
        version: state.version.to_string(),
        git_sha: state.git_sha.map(|s| s.to_string()),
        node_id: state.identity.node_id.clone(),
        first_seen: state.identity.first_seen,
    })
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct NodeIdentity {
    node_id: String,
    first_seen: u64,
}

#[cfg(feature = "metrics")]
use prometheus::{register_gauge_vec, Encoder, GaugeVec, TextEncoder};

#[cfg(feature = "metrics")]
static NODE_STARTS: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_node_starts_total", "Node starts").expect("metric")
});
#[cfg(feature = "metrics")]
static NODE_READY_DEGRADE_TOTAL: once_cell::sync::Lazy<IntCounter> =
    once_cell::sync::Lazy::new(|| {
        register_int_counter!(
            "eezo_node_ready_degrade_total",
            "Times readiness was degraded"
        )
        .expect("metric")
    });
#[cfg(feature = "metrics")]
static NODE_READY_RESTORE_TOTAL: once_cell::sync::Lazy<IntCounter> =
    once_cell::sync::Lazy::new(|| {
        register_int_counter!(
            "eezo_node_ready_restore_total",
            "Times readiness was restored"
        )
        .expect("metric")
    });
#[cfg(feature = "metrics")]
static NODE_INFO: once_cell::sync::Lazy<GaugeVec> = once_cell::sync::Lazy::new(|| {
    register_gauge_vec!(
        "eezo_node_info",
        "Static node identity and build info (value is always 1)",
        &["node_id", "version", "git_sha"]
    )
    .expect("metric")
});
#[cfg(feature = "metrics")]
static NODE_BG_ERROR_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!(
        "eezo_node_bg_error_total",
        "Times background error flipped readiness"
    )
    .expect("metric")
});
#[cfg(feature = "metrics")]
async fn metrics_handler() -> (axum::http::StatusCode, String) {
    let mf = prometheus::gather();
    let mut buf = Vec::new();
    TextEncoder::new().encode(&mf, &mut buf).unwrap();
    (axum::http::StatusCode::OK, String::from_utf8(buf).unwrap())
}
// Always-available shim so /metrics returns 200 even if the binary
// wasn't compiled with the `metrics` feature (tests only check 2xx).
async fn metrics_handler_any() -> (axum::http::StatusCode, String) {
    #[cfg(feature = "metrics")]
    {
        metrics_handler().await
    }
    #[cfg(not(feature = "metrics"))]
    {
        (axum::http::StatusCode::OK, String::from("# metrics feature not built"))
    }
}
// ─────────────────────────── T37: metrics sidecar server (axum 0.7) ───────────────────────────
async fn spawn_metrics_server(bind: String) {
    let app = axum::Router::new().route("/metrics", get(metrics_handler_any));
    match bind.parse::<SocketAddr>() {
        Ok(addr) => {
            log::info!("metrics: binding on http://{}", addr);
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    if let Err(e) = serve(listener, app.into_make_service()).await {
                        log::warn!("metrics server exited: {}", e);
                    }
                }
                Err(e) => log::warn!("metrics bind failed: {}", e),
            }
        }
        Err(e) => log::warn!("invalid EEZO_METRICS_BIND '{}': {}", bind, e),
    }
}
/// Parse an "EEZO_CHAIN_ID" that can be decimal (e.g., "31337")
/// or hex (e.g., "0x01" or full 20-byte "0x001122..."). Returns a 20-byte big-endian array.
fn parse_chain_id20_flexible(s: &str) -> Option<[u8; 20]> {
    let t = s.trim();
    // decimal?
    if !t.starts_with("0x") && t.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(v) = t.parse::<u64>() {
            let mut out = [0u8; 20];
            out[12..20].copy_from_slice(&v.to_be_bytes());
            return Some(out);
        }
        return None;
    }
    // hex: strip 0x and decode
    let h = t.strip_prefix("0x").unwrap_or(t);
    if h.len() % 2 != 0 { return None; }
    let bytes = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i+2], 16))
        .collect::<Result<Vec<u8>, _>>().ok()?;
    if bytes.len() > 20 { return None; }
    let mut out = [0u8; 20];
    // left-pad to 20 bytes
    out[(20 - bytes.len())..].copy_from_slice(&bytes);
    Some(out)
}
#[cfg(feature = "metrics")]
use crate::metrics::EEZO_NODE_READY;
pub fn set_ready(v: bool) {
    #[cfg(feature = "metrics")]
    {
        EEZO_NODE_READY.set(if v { 1 } else { 0 });
    }
	// When the `metrics` feature is off, avoid unused-variable warnings.
	let _ = v;
}

fn parse_chain_id_hex(s: &str) -> Option<[u8; 20]> {
    let t = s.trim().trim_start_matches("0x");
    if t.len() != 40 { return None; }
    let mut out = [0u8; 20];
    let bytes = hex::decode(t).ok()?;
    if bytes.len() != 20 { return None; }
    out.copy_from_slice(&bytes);
    Some(out)
}

fn env_bool(var: &str, default_on: bool) -> bool {
    match env::var(var).ok() {
        Some(raw) => {
            let s = raw.trim().to_ascii_lowercase();
            match s.as_str() {
                "on" | "1" | "true" | "yes" => true,
                "off" | "0" | "false" | "no" => false,
                _ => default_on,
            }
        }
        None => default_on,
    }
}

fn env_usize(var: &str, default_v: usize) -> usize {
    env::var(var)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default_v)
}

fn env_u16(var: &str, default_v: u16) -> u16 {
    env::var(var)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default_v)
}

#[cfg(feature = "pq44-runtime")]
fn env_u64(var: &str, default_v: u64) -> u64 {
    env::var(var)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default_v)
}

#[cfg(target_os = "linux")]
fn pid_alive(pid: u32) -> bool {
    std::fs::metadata(format!("/proc/{}", pid)).is_ok()
}

#[cfg(not(target_os = "linux"))]
fn pid_alive(_pid: u32) -> bool {
    true
}

#[derive(Serialize, Clone)]
struct RuntimeConfigView {
    chain_id_hex: String,
    verify_cache_cap: usize,
    parallel_verify: bool,
    max_block_bytes: usize,
    metrics_on: bool,
    metrics_port: u16,
    node: NodeConfigView,
    node_id: String,
    first_seen: u64,
    peers: Vec<String>,
    treasury: Option<String>,
	// ───── T34: crypto-suite rotation (exposed via /config) ─────
	#[serde(default)]
	active_suite_id: u8,
	#[serde(default)]
	next_suite_id: Option<u8>,
	#[serde(default)]
	dual_accept_until: Option<u64>,
}

#[derive(Serialize, Clone)]
struct NodeConfigView {
    listen: String,
    datadir: String,
    genesis: Option<String>,
    log_level: String,
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
struct NodeCfg {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default = "default_datadir")]
    datadir: String,
    #[serde(default)]
    genesis: Option<String>,
    #[serde(default = "default_log_level")]
    log_level: String,
    #[serde(default)]
    peers: Vec<String>,
}

fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_datadir() -> String {
    "data".into()
}
fn default_log_level() -> String {
    "info".into()
}

impl Default for NodeCfg {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            datadir: default_datadir(),
            genesis: None,
            log_level: default_log_level(),
            peers: Vec::new(),
        }
    }
}

// -----------------------------------------------------------------------------
// T30: Wire types for tx submission/status (JSON)
// -----------------------------------------------------------------------------
#[derive(Deserialize, Serialize, Clone, Debug)]
struct TransferTx {
    from: String,   // "0x.." (devnet)
    to: String,     // "0x.."
    amount: String, // u64 as string for JSON safety
    nonce: String,  // u64 as string
    fee: String,    // u64 as string
    chain_id: String, // "0x..."
    // (20 bytes hex) or short devnet "0x01"
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct SignedTxEnvelope {
    tx: TransferTx,
    sig: String, // base64 or hex — devnet accepts opaque string for now
}

#[derive(Serialize)]
struct SubmitTxResp {
    hash: String, // hex-encoded blake3(tx_envelope_json)
}

// ── T36.2: HTTP DTOs for consensus votes/QCs ───────────────────────────────────
#[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
#[derive(serde::Deserialize)]
struct VoteReq {
    view: u64,             // e.g., 1
    block: String,         // 0x…32-byte hex (32 bytes)
    validator: u32,        // 0..committee_size-1
    sig_hex: Option<String>
}

#[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
#[derive(serde::Serialize, Clone)]
struct QcInfo {
    view: u64,
    block: String,
    voters: Vec<u32>,
}

// -----------------------------------------------------------------------------
// Minimal /head endpoint
// 200 {height} once at least one block was produced, 404 while height is 0.
// -----------------------------------------------------------------------------
#[derive(serde::Serialize)]
struct HeadView {
    height: u64,
}
async fn head_handler(State(state): State<AppState>) -> Response {
    let h = state.block_height.load(Ordering::SeqCst);
    if h == 0 {
        StatusCode::NOT_FOUND.into_response()
    } else {
        (StatusCode::OK, Json(HeadView { height: h })).into_response()
    }
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum TxStatusView {
    Pending,
    Included { block_height: u64 },
    Rejected { error: String },
}

fn hex_to_32(bytes_hex: &str) -> Option<[u8; 32]> {
    let s = bytes_hex.strip_prefix("0x").unwrap_or(bytes_hex);
    let v = hex::decode(s).ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

#[derive(Serialize, Deserialize, Clone)]
struct Receipt {
    hash: String,
    // status is "included" or "rejected"
    status: &'static str,
    block_height: Option<u64>,
    from: String,
    to: String,
    amount: String,
    fee: String,
    nonce: String,
    error: Option<String>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

#[derive(Clone)]
struct AppState {
    runtime_config: RuntimeConfigView,
    ready_flag: Arc<AtomicBool>,
    admin_token: Option<String>,
    started_at: SystemTime,
    version: &'static str,
    git_sha: Option<&'static str>,
    identity: NodeIdentity,
    peers: PeerMap,
    peer_svc: peers::PeerService,
    config_file_path: Option<String>,

    // Dev/PoA height tracker for the T30 proposer
    block_height: Arc<AtomicU64>,
    // Shared in-proc mempool (T30)
    mempool: crate::mempool::SharedMempool,
    accounts: Accounts,
    // Recent blocks (in-memory, dev only): height -> tx hashes (hex)
    // Keep only last N heights to avoid unbounded memory.
    recent_blocks: Arc<RwLock<RecentBlocks>>,
    receipts: Arc<RwLock<HashMap<String, Receipt>>>,
    // Optional treasury address;
    // if present, fees are credited here (otherwise burned)
    treasury_addr: Option<String>,

    // Node-wide persistence (RocksDB)
    #[cfg(feature = "persistence")]
    db: std::sync::Arc<eezo_ledger::persistence::Persistence>,

    // t36: consensus core runner handle (pq44 SingleNode path)
    #[cfg(feature = "pq44-runtime")]
    core_runner: Option<Arc<CoreRunnerHandle>>,
    // adapter/testing path (mutually exclusive with pq44-runtime)
    #[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
    core_runner: std::sync::Arc<CoreRunnerHandle>,
    #[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
    last_qc: std::sync::Arc<tokio::sync::Mutex<Option<Qc>>>,
	// Bridge Alpha
	chain_id: [u8; 20],
	bridge_admin_pubkey: Option<Vec<u8>>,
	bridge: Arc<AsyncMutex<BridgeState>>,
	outbox: Arc<RwLock<Vec<OutboxEvent>>>,
    // Crypto-suite rotation (T34)
    pub active_suite_id: u8,
    pub next_suite_id: Option<u8>,
    pub dual_accept_until: Option<u64>, // block height
    // T36.8: base datadir for runtime artifacts (`<datadir>/proof/...`)
    pub datadir: Option<std::path::PathBuf>,	
}

struct RecentBlocks {
    by_height: Map<u64, Vec<String>>,
    order: VecDeque<u64>,
    cap: usize,
}

fn dedup_preserve_order(mut v: Vec<String>) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    v.retain(|s| seen.insert(s.clone()));
    v
}

fn load_nodecfg_peers_or_empty(path: &Option<String>) -> anyhow::Result<Vec<String>> {
    if let Some(p) = path {
        if p.trim().is_empty() {
            return Ok(Vec::new());
        }
        let txt = std::fs::read_to_string(p)?;
        let nc: NodeCfg = toml::from_str(&txt)?;
        Ok(nc.peers)
    } else {
        Ok(Vec::new())
    }
}

#[derive(serde::Deserialize)]
struct ReloadPeers(Vec<String>);

async fn reload_handler(
    State(state): State<AppState>,
    maybe_json: Result<Json<ReloadPeers>, JsonRejection>,
) -> (StatusCode, &'static str) {
    let peers_from_body = maybe_json
        .ok()
        .map(|Json(ReloadPeers(v))| v)
        .unwrap_or_default();
    let new_peers = if peers_from_body.is_empty() {
        load_nodecfg_peers_or_empty(&state.config_file_path).unwrap_or_default()
    } else {
        peers_from_body
            .into_iter()
            .map(|p| p.trim().trim_end_matches('/').to_string())
            .collect()
    };

    state
        .peer_svc
        .set_peers(dedup_preserve_order(new_peers))
        .await;
    (StatusCode::OK, "ok")
}

async fn reload_from_file_handler(State(state): State<AppState>) -> (StatusCode, &'static str) {
    let v = load_nodecfg_peers_or_empty(&state.config_file_path).unwrap_or_default();
    state.peer_svc.set_peers(dedup_preserve_order(v)).await;
    (StatusCode::OK, "ok")
}

// GET /txpool → basic mempool stats
#[derive(Serialize)]
struct TxpoolStatsView {
    pending: usize,
    included_known: usize,
    rejected_known: usize,
    approx_queue_bytes: usize,
}
async fn txpool_handler(State(state): State<AppState>) -> Json<TxpoolStatsView> {
    // Uses your existing mempool.stats() helper (you already defined it).
    let (pending, included, rejected, approx_bytes) = state.mempool.stats().await;
    Json(TxpoolStatsView {
        pending,
        included_known: included,
        rejected_known: rejected,
        approx_queue_bytes: approx_bytes,
    })
}

// GET /block/:height → list of tx hashes included at height
#[derive(Serialize)]
struct BlockView {
    height: u64,
    tx_hashes: Vec<String>,
}
async fn block_handler(
    State(state): State<AppState>,
    AxumPath(h): AxumPath<u64>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Fallback to in-memory recent cache
    let rb = state.recent_blocks.read().await;
    if let Some(v) = rb.by_height.get(&h) {
        (
            StatusCode::OK,
            Json(serde_json::json!(BlockView {
                height: h,
                tx_hashes: v.clone()
            })),
        )
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"unknown height"})))
    }
}

// T30: POST /tx → accept SignedTxEnvelope JSON, hash it, enqueue to mempool.
async fn post_tx(
    State(state): State<AppState>,
    Json(env): Json<SignedTxEnvelope>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Canonical bytes for hashing + storage: re-encode the parsed JSON.
    let raw = match serde_json::to_vec(&env) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid tx encoding: {e}")})),
            )
        }
    };
    let hash32: [u8; 32] = *blake3::hash(&raw).as_bytes();
    let hash_hex = format!("0x{}", hex::encode(hash32));
    // For now, use loopback IP (we’ll wire real remote IP later if needed).
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    match state.mempool.submit(ip, hash32, raw).await {
        Ok(()) => {
			#[cfg(feature = "metrics")]
			{
				crate::metrics::EEZO_MEMPOOL_LEN.set(state.mempool.len().await as i64);
			}
			(StatusCode::OK, Json(serde_json::json!(SubmitTxResp { hash: hash_hex })))
		}
        Err(crate::mempool::SubmitError::Duplicate) => {
			#[cfg(feature = "metrics")]
			{
				crate::metrics::EEZO_MEMPOOL_LEN.set(state.mempool.len().await as i64);
			}
		(StatusCode::OK, Json(serde_json::json!(SubmitTxResp { hash: hash_hex })))
	    }
        Err(crate::mempool::SubmitError::RateLimited) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "rate limited"})),
        ),
        Err(crate::mempool::SubmitError::QueueFull) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "mempool full"})),
        ),
        Err(crate::mempool::SubmitError::BytesCapReached) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "mempool byte cap reached"})),
        ),
    }
}

// T30: GET /tx/{hash} → report mempool status (pending/included/rejected).
async fn get_tx(
    State(state): State<AppState>,
    AxumPath(hash_hex): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(h) = hex_to_32(&hash_hex) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "hash must be 32 bytes (hex)"})),
        );
    };
    match state.mempool.status(&h).await {
        Some(crate::mempool::TxStatus::Pending) => {
            (StatusCode::OK, Json(serde_json::json!(TxStatusView::Pending)))
        }
        Some(crate::mempool::TxStatus::Included { block_height }) => (
            StatusCode::OK,
            Json(serde_json::json!(TxStatusView::Included { block_height })),
        ),
        Some(crate::mempool::TxStatus::Rejected { error }) => (
            StatusCode::OK,
            Json(serde_json::json!(TxStatusView::Rejected { error })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "unknown tx"})),
        ),
    }
}

async fn get_receipt(
    State(state): State<AppState>,
    AxumPath(hash): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // fallback to memory
    let map = state.receipts.read().await;
    if let Some(r) = map.get(&hash) {
        return (StatusCode::OK, Json(serde_json::json!(r)));
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "unknown tx"})),
    )
}

// Update the get_account handler
async fn get_account(
    State(state): State<AppState>,
    AxumPath(addr): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Parse and normalize the address using the new helper
    let normalized_addr = match parse_account_addr(&addr) {
        Some(addr) => format!("0x{}", hex::encode(addr.as_bytes())),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid address format"})),
            )
        }
    };
    let (bal, nonce) = state.accounts.get(&normalized_addr).await;
    let view = AccountView {
        balance: bal.to_string(),
        nonce: nonce.to_string()
    };
    (StatusCode::OK, Json(serde_json::json!(view)))
}

// Update the post_faucet handler
async fn post_faucet(
    State(state): State<AppState>,
    Json(req): Json<FaucetReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    // DEV ONLY: optional toggle
    if std::env::var("EEZO_DEVNET_FAUCET").ok().as_deref() == Some("off") {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"faucet disabled"})));
    }

    let Ok(amount) = req.amount.parse::<u64>() else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"amount must be u64"})));
    };

    // Parse and normalize the address using the new helper
    let normalized_addr = match parse_account_addr(&req.to) {
        Some(addr) => format!("0x{}", hex::encode(addr.as_bytes())),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid address format"})),
            )
        }
    };

    state.accounts.mint(&normalized_addr, amount).await;
    let (bal, nonce) = state.accounts.get(&normalized_addr).await;
    // Return the original address in the response for user convenience
    (StatusCode::OK, Json(serde_json::json!({
        "to": req.to,
        "balance": bal.to_string(),
        "nonce": nonce.to_string()
    })))
}

// ── T36.2: POST /consensus/vote — submit one vote; returns {ok,true} or {qc:{…}}
#[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
async fn post_vote(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Json(v): axum::Json<VoteReq>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    // parse block hex → [u8;32]
    let hex_str = v.block.trim_start_matches("0x");
    let mut block = [0u8; 32];
    if let Ok(bytes) = hex::decode(hex_str) {
        if bytes.len() == 32 {
            block.copy_from_slice(&bytes);
        } else {
            return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error":"block must be 32 bytes"})));
        }
    } else {
        return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error":"invalid hex"})));
    }

    // signature: if none supplied, derive testing signature deterministically
    let sig: Vec<u8> = if let Some(s) = v.sig_hex.as_ref() {
        match hex::decode(s.trim_start_matches("0x")) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error":"invalid sig_hex"}))),
        }
    } else {
        crate::consensus_runner::testing_sign_bytes(v.view, block, v.validator)
    };

    // Build a Vote and submit to the runner
    let vote = Vote::new(ViewId(v.view), BlockId(block), ValidatorId(v.validator), sig);
    if let Some(qc) = state.core_runner.submit(vote) {
        // store latest QC
        {
            let mut guard = state.last_qc.lock().await;
            *guard = Some(qc.clone());
        }
        // return a compact projection (no reliance on internal accessors)
        return (
            StatusCode::OK,
            axum::Json(serde_json::json!({"ok": true, "qc_debug": format!("{qc:?}")}))
        );
    }
    (StatusCode::OK, axum::Json(serde_json::json!({"ok": true})))
}

// ── T36.2: GET /consensus/qc — read the most recent QC (if any)
#[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
async fn get_qc(
    axum::extract::State(state): axum::extract::State<AppState>
) -> (StatusCode, axum::Json<serde_json::Value>) {
    if let Some(qc) = state.last_qc.lock().await.clone() {
        // keep generic until Qc API is locked: return debug string (safe & stable)
        let qc_dbg = format!("{qc:?}");
        (StatusCode::OK, axum::Json(serde_json::json!({ "qc_debug": qc_dbg })))
    } else {
        (StatusCode::NO_CONTENT, axum::Json(serde_json::json!({})))
    }
}

// -----------------------------------------------------------------------------
// DEV-ONLY: admin raw-ingest endpoint (feature-gated)
// Build with: --features dev-tools
// Call as:    POST /_admin/tx_raw?token=<EEZO_ADMIN_TOKEN>
// Body:       raw bytes (opaque blob used to compute the tx hash)
// NOTE: This is intended for local testing/fuzzing.
// Keep the route disabled in
//       production builds (no dev-tools feature) and *require* the admin token.
// -----------------------------------------------------------------------------
#[cfg(feature = "dev-tools")]
async fn post_tx_raw_admin(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    // Require admin token
    let token = q.get("token").map(|s| s.as_str());
    if !check_admin_token(&state, token) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden"})));
    }

    // Treat body as the canonical raw bytes;
    // tx hash = blake3(raw)
    let raw = body.to_vec();
    let hash32: [u8; 32] = *blake3::hash(&raw).as_bytes();
    let hash_hex = format!("0x{}", hex::encode(hash32));

    // Use loopback as submitter IP for now (keeps rate limit path consistent)
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    match state.mempool.submit(ip, hash32, raw).await {
        Ok(()) => {
            #[cfg(feature = "metrics")]
            { crate::metrics::EEZO_MEMPOOL_LEN.set(state.mempool.len().await as i64);
            }
            (StatusCode::OK, Json(serde_json::json!({ "hash": hash_hex })))
        }
        Err(crate::mempool::SubmitError::Duplicate) => {
            #[cfg(feature = "metrics")]
            { crate::metrics::EEZO_MEMPOOL_LEN.set(state.mempool.len().await as i64);
            }
            (StatusCode::OK, Json(serde_json::json!({ "hash": hash_hex })))
        }
        Err(crate::mempool::SubmitError::RateLimited) =>
            (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":"rate limited"}))),
        Err(crate::mempool::SubmitError::QueueFull) =>
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"mempool full"}))),
        Err(crate::mempool::SubmitError::BytesCapReached) =>
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"mempool byte cap reached"}))),
    }
}
// 
// ----------------------------------------------------------------------------
// DEV ONLY: force-commit an empty block at tip+1 and emit a checkpoint
// Build with: --features "persistence,eth-ssz,checkpoints,dev-tools"
// Call as:    POST /_admin/commit_now?token=<EEZO_ADMIN_TOKEN>
// ----------------------------------------------------------------------------
#[cfg(all(feature = "persistence", feature = "dev-tools"))]
async fn admin_commit_now(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    // token gate via query (?token=…)
    let token = q.get("token").map(|s|
    s.as_str());
    if !check_admin_token(&state, token) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden"})));
    }

    // compute heights
    let cur_h = state.block_height.load(Ordering::SeqCst);
    let next_h = cur_h + 1;
    // minimal header for dev
    let header = BlockHeader {
        prev_hash: [0u8; 32],
        height: next_h,
        tx_root: [0u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 0,
        timestamp_ms: now_ms(),
        tx_count: 0,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    };
    let block = Block { header, txs: Vec::new() };
    // persist header+block
    if let Err(e) = state.db.put_header_and_block(next_h, &block.header, &block) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("persist header+block failed: {e}")
        })));
    }

    // snapshot (dev defaults)
    let snap = StateSnapshot {
        height: next_h,
        accounts: eezo_ledger::Accounts::default(),
        supply: Supply { native_mint_total: 0, bridge_mint_total: 0, burn_total: 0 },
        state_root: [0u8; 32],
        bridge: Some(eezo_ledger::bridge::BridgeState::default()),
        #[cfg(feature = "eth-ssz")]
        codec_version: 2,
        #[cfg(feature = "eth-ssz")]
        state_root_v2: [0u8; 32],
    };
    if let Err(e) = state.db.put_state_snapshot(&snap) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("persist snapshot failed: {e}")
        })));
    }
    if let Err(e) = state.db.set_tip(next_h) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("set_tip failed: {e}")
        })));
    }

    // update in-proc height/metrics
    state.block_height.store(next_h, std::sync::atomic::Ordering::SeqCst);
    #[cfg(feature = "metrics")]
    {
        crate::metrics::EEZO_BLOCK_HEIGHT.set(next_h as i64);
        crate::metrics::EEZO_MEMPOOL_LEN.set(state.mempool.len().await as i64);
    }

    // t36: checkpoint emission via runner removed for now;
    // will be re-added in T36.2+
    #[cfg(all(feature="persistence", feature="eth-ssz", feature="checkpoints"))]
    {
        let _hh = block.header.hash();
        // TODO: emit checkpoint here once the new adapter exposes an emitter hook.
    }

    (StatusCode::OK, Json(serde_json::json!({ "ok": true, "height": next_h })))
}

// ----------------------------------------------------------------------------
// DEV ONLY: force-commit a block with specified tx hashes and compute tx_root_v2
// Build with: --features "persistence,eth-ssz,checkpoints,dev-tools"
// Call as:    POST /_admin/commit_with_hashes?token=<EEZO_ADMIN_TOKEN>
// Body:       {"hashes": ["0x...", "0x..."]}
// ----------------------------------------------------------------------------
#[cfg(all(feature = "persistence", feature = "dev-tools"))]
#[derive(serde::Deserialize)]
struct CommitHashesBody {
    hashes: Vec<String>,
}

#[cfg(all(feature = "persistence", feature = "dev-tools"))]
async fn admin_commit_with_hashes(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
    axum::Json(body): axum::Json<CommitHashesBody>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // token check
    let token = q.get("token").map(|s|
    s.as_str());
    if !check_admin_token(&state, token) {
        return (axum::http::StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error":"forbidden"})));
    }

    // parse 32-byte hex hashes
    let mut hh: Vec<[u8; 32]> = Vec::with_capacity(body.hashes.len());
    for h in &body.hashes {
        let s = h.trim().trim_start_matches("0x");
        let Ok(bytes) = hex::decode(s) else {
            return (axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({"error":"bad hex in hashes"})));
        };
        if bytes.len() != 32 { return (axum::http::StatusCode::BAD_REQUEST,
                                     axum::Json(serde_json::json!({"error":"each hash must be 32 bytes"})));
        }
        let mut a = [0u8; 32]; a.copy_from_slice(&bytes); hh.push(a);
    }

    // tx_root_v2 = blake3(concat(hashes)) (dev-only)
    let mut buf = Vec::with_capacity(hh.len() * 32);
    for h in &hh {
        buf.extend_from_slice(h);
    }
    let root32: [u8;
    32] = *blake3::hash(&buf).as_bytes();
    let tx_count = hh.len() as u32;

    // heights
    let cur_h = state.block_height.load(std::sync::atomic::Ordering::SeqCst);
    let next_h = cur_h + 1;

    // header+block
    let header = BlockHeader {
        prev_hash: [0u8; 32],
        height: next_h,
        tx_root: [0u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: root32,
        fee_total: 0,
        timestamp_ms: now_ms(),
        tx_count,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    };
    let block = Block { header, txs: Vec::new() };
    // persist
    if let Err(e) = state.db.put_header_and_block(next_h, &block.header, &block) {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error":format!("persist header+block: {e}")})));
    }
    let snap = StateSnapshot {
        height: next_h,
        accounts: eezo_ledger::Accounts::default(),
        supply: Supply { native_mint_total: 0, bridge_mint_total: 0, burn_total: 0 },
        state_root: [0u8; 32],
        bridge: Some(eezo_ledger::bridge::BridgeState::default()),
        #[cfg(feature = "eth-ssz")]
        codec_version: 2,
        #[cfg(feature = "eth-ssz")]
        state_root_v2: [0u8; 32],
    };
    if let Err(e) = state.db.put_state_snapshot(&snap) {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error":format!("persist snapshot: {e}")})));
    }
    if let Err(e) = state.db.set_tip(next_h) {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({"error":format!("set_tip: {e}")})));
    }
    state.block_height.store(next_h, std::sync::atomic::Ordering::SeqCst);

    // t36: checkpoint emission temporarily disabled;
    // see note above
    #[cfg(all(feature="persistence", feature="eth-ssz", feature="checkpoints"))]
    {
        let _hh = block.header.hash();
    }

    (axum::http::StatusCode::OK,
     axum::Json(serde_json::json!({
        "ok": true, "height": next_h, "tx_count": tx_count,
        "tx_root_v2": format!("0x{}", hex::encode(root32))
     })))
}

struct LockFileGuard {
    path: std::path::PathBuf,
}

impl Drop for LockFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}


#[derive(Parser, Debug)]
#[command(name = "eezo-node", about = "EEZO node")]
struct Cli {
    #[arg(long = "config-file", env = "EEZO_CONFIG_FILE")]
    config_file: Option<String>,

    #[arg(long)]
    genesis: Option<String>,

    #[arg(long = "datadir", alias = "data-dir", alias = "data_dir")]
    datadir: Option<String>,

    #[arg(long = "listen", alias = "listen-addr")]
    listen: Option<String>,

    #[arg(long = "log-level", alias = "log_level")]
    log_level: Option<String>,

    #[cfg(feature = "state-sync")]
    #[arg(
        long = "enable-state-sync",
   
         env = "EEZO_ENABLE_STATE_SYNC",
        action = clap::ArgAction::SetTrue
    )]
    enable_state_sync: bool,

    #[cfg(feature = "state-sync")]
    #[arg(long = "state-sync-source", env = "EEZO_STATE_SYNC_SOURCE")]
    state_sync_source: Option<String>,

    #[cfg(feature = "state-sync")]
    #[arg(long = "bootstrap-base", env = "EEZO_BOOTSTRAP_BASE_URL")]
    bootstrap_base: Option<String>,

    #[cfg(feature = "state-sync")]
    #[arg(
        long = "bootstrap-page-limit",
        env = "EEZO_BOOTSTRAP_PAGE_LIMIT",
    
         default_value_t = 256
    )]
    bootstrap_page_limit: usize,

    #[cfg(feature = "state-sync")]
    #[arg(
        long = "bootstrap-delta-span",
        env = "EEZO_BOOTSTRAP_DELTA_SPAN",
        default_value_t = 1000
    )]
    bootstrap_delta_span: u64,

    #[cfg(feature = "state-sync")]
    #[arg(
        long = "sync-resume",
        env = "EEZO_SYNC_RESUME",
      
         default_value = "true",  // default on
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    sync_resume: bool,

    #[cfg(feature = "state-sync")]
    #[arg(
        long = "sync-backoff-ms",
        env = "EEZO_SYNC_BACKOFF_MS",
        default_value_t = 200u64
    )]
    sync_backoff_ms: u64,

    #[cfg(feature = "state-sync")]
    #[arg(
        long = "sync-backoff-cap-ms",
    
         env = "EEZO_SYNC_BACKOFF_CAP_MS",
        default_value_t = 5_000u64
    )]
    sync_backoff_cap_ms: u64,

    #[cfg(feature = "state-sync")]
    #[arg(
        long = "sync-max-retries",
        env = "EEZO_SYNC_MAX_RETRIES",
        default_value_t = 20usize
    )]
    sync_max_retries: usize,

    // Optional overall watchdog (0 = disabled)
    #[cfg(feature = "state-sync")]
    #[arg(long = "sync-bootstrap-timeout-ms", env = "EEZO_SYNC_BOOTSTRAP_TIMEOUT_MS",
 
       default_value_t = 0)]
    sync_bootstrap_timeout_ms: u64,

    /// Use TLS for state-sync HTTP client (HTTPS).
    // Optional mTLS if cert+key are provided.
    #[cfg(feature = "state-sync")]
    #[arg(long, env = "EEZO_SYNC_TLS", value_parser = clap::builder::BoolishValueParser::new())]
    pub sync_tls: bool,

    /// Path to CA bundle (PEM) for server cert validation.
    #[cfg(feature = "state-sync")]
    #[arg(long, env = "EEZO_SYNC_TLS_CA")]
    pub sync_tls_ca: Option<PathBuf>,

    /// Client certificate (PEM) for mTLS.
    #[cfg(feature = "state-sync")]
    #[arg(long, env = "EEZO_SYNC_TLS_CERT")]
    pub sync_tls_cert: Option<PathBuf>,

    /// Client private key (PEM, PKCS#8) for mTLS.
    #[cfg(feature = "state-sync")]
    #[arg(long, env = "EEZO_SYNC_TLS_KEY")]
    pub sync_tls_key: Option<PathBuf>,

    /// DEV ONLY: skip TLS certificate verification (hostname/CA).
    // Do NOT use in production.
    #[cfg(feature = "state-sync")]
    #[arg(long, env = "EEZO_SYNC_TLS_INSECURE_SKIP_VERIFY", value_parser = clap::builder::BoolishValueParser::new())]
    pub sync_tls_insecure_skip_verify: bool,

    /// Allow unsigned anchors (legacy interop).
    // Default is to REQUIRE signed anchors.
    #[cfg(feature = "state-sync")]
    #[arg(long, env = "EEZO_SYNC_ALLOW_UNSIGNED_ANCHOR", value_parser = clap::builder::BoolishValueParser::new())]
    pub sync_allow_unsigned_anchor: bool,
}

// --- Helper: Write both NODE_ID and IDENTITY as JSON ---
fn write_identity_files(
    node_id_path: &std::path::Path,
    legacy_path: &std::path::Path,
    ident: &NodeIdentity,
) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(ident)?;
    std::fs::write(node_id_path, &json).context("failed to write NODE_ID")?;
    // Keep legacy mirror for compatibility with tests/tools that still read IDENTITY
    std::fs::write(legacy_path, &json).ok();
    Ok(())
}

// t36: removed legacy demo_propose; HotStuff route is no longer available
// #[cfg(feature = "pq44-runtime")]
// async fn demo_propose(State(state): State<AppState>) -> (StatusCode, &'static str) {
//     // Build a real header timestamp;
// let now_ms = std::time::SystemTime::now()
//         .duration_since(std::time::SystemTime::UNIX_EPOCH)
//         .unwrap_or(std::time::Duration::ZERO)
//         .as_millis() as u64;
// let header = BlockHeader {
//         // required fields (match current ledger struct)
//         prev_hash:    [0u8; 32],
//         height:       0,
//         tx_root:      [0u8; 32],
//         fee_total:    0,
//         timestamp_ms: now_ms,
//         tx_count:     0,
//         // this field is required by your build;
// // set zeroes
//         qc_hash:      [0u8; 32],
//         // feature-gated extras
//         #[cfg(feature = "eth-ssz")]
//         tx_root_v2:   [0u8; 32],
//     };

//     // Go through the runner helper (keeps the propose path uniform).
// // consensus_runner::propose_header(
// //         &state.hs,
// //         header,
// //         eezo_ledger::consensus_msg::ValidatorId(0),
// //     );
// // (StatusCode::OK, "proposed")
// // }

// Add the dev-only anchor seeding handler
#[allow(dead_code)]
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
async fn seed_anchor_dev(State(state): State<AppState>) -> (StatusCode, &'static str) {
    use eezo_ledger::checkpoints::CheckpointAnchor;
    // Minimal dummy anchor
    let anchor = CheckpointAnchor::new(
        1, // Use a non-zero height to be a valid sync target
        [2u8; 32],
        [1u8; 32],
        [3u8; 32],
    );
    // Persist only if nothing exists yet
    match state.db.load_checkpoint_anchor() {
        Ok(Some(_)) => return (StatusCode::OK, "anchor already present"),
        Ok(None) => {}
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "load failed"),
    }

    if state.db.save_checkpoint_anchor(&anchor).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }

    (StatusCode::OK, "anchor seeded")
}
// Helper to resolve the correct bridge checkpoint output directory
#[cfg(feature = "checkpoints")]
#[allow(dead_code)]
fn resolve_outbox_dir(datadir: Option<&std::path::Path>) -> std::path::PathBuf {
    if let Ok(p) = env::var("EEZO_BRIDGE_OUTBOX_DIR") {
        return std::path::PathBuf::from(p);
    }
    match datadir {
        Some(d) => d.join("proof").join("checkpoints"),
        // Fallback if datadir is None (e.g. tests or specific configs)
        None => std::path::PathBuf::from("data").join("proof").join("checkpoints"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("💥 PANIC: {:?}", info);
    }));
    println!("🚀 Node starting up...");
    let args = Cli::parse();

    println!(
        "CLI args - genesis: {:?}, datadir: {:?}, listen: {:?}, log_level: {:?}, config_file: {:?}",
        args.genesis, args.datadir, args.listen, args.log_level, args.config_file
    );
    println!(
        "ENV vars - EEZO_CONFIG_FILE: {:?}, EEZO_LISTEN: {:?}, EEZO_DATADIR: {:?}, EEZO_GENESIS: {:?}, EEZO_LOG_LEVEL: {:?}",
        std::env::var("EEZO_CONFIG_FILE").ok(),
        std::env::var("EEZO_LISTEN").ok(),
        std::env::var("EEZO_DATADIR").ok(),
        std::env::var("EEZO_GENESIS").ok(),
        std::env::var("EEZO_LOG_LEVEL").ok()
    );
    let mut cfg = NodeCfg::default();
    let config_path = args.config_file.clone();
    println!("Resolved config path: {:?}", config_path);
    if let Some(ref path) = config_path {
        println!("Attempting to load config from: {}", path);
        let txt = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path))?;
        let from_file: NodeCfg = toml::from_str(&txt)
            .with_context(|| format!("invalid TOML in config file: {}", path))?;
        if from_file.listen.trim().is_empty() {
            anyhow::bail!("config: 'listen' cannot be empty");
        }
        if let Some(ref g) = from_file.genesis {
            if g.trim().is_empty() {
                anyhow::bail!("config: 'genesis' cannot be empty string");
            }
        }
        if from_file.datadir.trim().is_empty() {
            anyhow::bail!("config: 'datadir' cannot be empty");
        }

        if !from_file.listen.is_empty() {
            cfg.listen = from_file.listen;
        }
        if !from_file.datadir.is_empty() {
            cfg.datadir = from_file.datadir;
        }
        if let Some(g) = from_file.genesis {
            cfg.genesis = Some(g);
        }
        if !from_file.log_level.is_empty() {
            cfg.log_level = from_file.log_level;
        }
        if !from_file.peers.is_empty() {
            cfg.peers = from_file.peers.clone();
        }
    }
    // T37.8: optional metrics sidecar (non-blocking). Starts /metrics if EEZO_METRICS_BIND is set.
    if let Ok(bind) = std::env::var("EEZO_METRICS_BIND") {
        tokio::spawn(spawn_metrics_server(bind.clone()));
        println!("metrics: sidecar bound at {}", bind);
    }	
    if let Ok(s) = env::var("EEZO_LISTEN") {
        cfg.listen = s;
    }
    if let Ok(s) = env::var("EEZO_DATADIR") {
        cfg.datadir = s;
    }
    if let Ok(s) = env::var("EEZO_GENESIS") {
        cfg.genesis = Some(s);
    }
    if let Ok(s) = env::var("EEZO_LOG_LEVEL") {
        cfg.log_level = s;
    }

    if let Some(g) = args.genesis.clone() {
        cfg.genesis = Some(g);
    }
    if let Some(d) = args.datadir.clone() {
        cfg.datadir = d;
    }
    if let Some(l) = args.listen.clone() {
        cfg.listen = l;
    }
    if let Some(ll) = args.log_level.clone() {
        cfg.log_level = ll;
    }

    let mut env_peers = parse_peers_from_env();
    if !env_peers.is_empty() {
        cfg.peers.append(&mut env_peers);
    }
    cfg.peers = dedup_preserve_order(cfg.peers);

    if cfg.datadir.trim().is_empty() {
        anyhow::bail!("datadir cannot be empty");
    }

    println!("✅ Config merged successfully");
    println!("Final listen address: {}", cfg.listen);
    println!("Final datadir: {}", cfg.datadir);
    println!("Final log level: {}", cfg.log_level);
    io::stdout().flush().unwrap();

    cfg.listen
        .parse::<SocketAddr>()
        .context("invalid listen address")?;
    let lock_path = std::path::Path::new(&cfg.datadir).join(".lock");
    std::fs::create_dir_all(&cfg.datadir).context("failed to create datadir")?;

    println!("🔍 About to read .lock file at: {:?}", lock_path);
    if let Ok(existing) = std::fs::read_to_string(&lock_path) {
        println!("🔍 Lock file exists, content: '{}'", existing.trim());
        if let Ok(pid) = existing.trim().parse::<u32>() {
            println!("🔍 Parsed PID from lock: {}", pid);
            let mut in_use = false;

            #[cfg(target_os = "linux")]
            {
                if pid_alive(pid) {
                    println!("🔍 PID {} is alive", pid);
                    let cmdline_path = format!("/proc/{}/cmdline", pid);
                    if let Ok(cmd) = std::fs::read(cmdline_path) {
                        let cmd_str = String::from_utf8_lossy(&cmd);
                        println!("🔍 Process cmdline: {}", cmd_str);
                        if cmd_str.contains("eezo-node") {
                            in_use = true;
                            println!("🔍 Process is eezo-node, lock is valid");
                        } else {
                            println!("🔍 Process is NOT eezo-node, lock is stale");
                        }
                    } else {
                        in_use = true;
                        println!("🔍 Can't read cmdline, assuming lock is valid");
                    }
                } else {
                    println!("🔍 PID {} is NOT alive", pid);
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                in_use = pid_alive(pid);
                println!("🔍 Non-Linux platform, pid_alive returned: {}", in_use);
            }

            if in_use {
                println!(
                    "❌ Bail: datadir already in use by pid {}: {}",
                    pid, cfg.datadir
             
                );
                anyhow::bail!("datadir already in use by pid {}: {}", pid, cfg.datadir);
            } else {
                println!("🔍 Removing stale lock file");
                let _ = std::fs::remove_file(&lock_path);
            }
        } else {
            println!("🔍 Could not parse PID from lock, removing garbled lock");
            let _ = std::fs::remove_file(&lock_path);
        }
    } else {
        println!("🔍 No existing lock file found");
    }

    println!("🔍 Writing new lock file with PID: {}", std::process::id());
    std::fs::write(&lock_path, std::process::id().to_string())
        .context("failed to write datadir lock")?;
    let _lock_guard = LockFileGuard {
        path: lock_path.clone(),
    };
    let node_id_path = std::path::Path::new(&cfg.datadir).join("NODE_ID");
    let legacy_json_identity_path = std::path::Path::new(&cfg.datadir).join("IDENTITY");

    // PATCHED: Robustly migrate legacy NODE_ID plain UUID to JSON
    // Always ensure both NODE_ID and IDENTITY are present and valid JSON mirror
    println!("🔍 Loading node identity from: {:?}", node_id_path);
    let identity: NodeIdentity = match std::fs::read_to_string(&node_id_path) {
        Ok(txt) => {
            println!("🔍 Found existing NODE_ID file, contents: {:?}", txt);
            let trimmed = txt.trim();
            if trimmed.starts_with('{') {
                // Current JSON format
                let ident = serde_json::from_str::<NodeIdentity>(trimmed)
                    .context("invalid NODE_ID json")?;
                write_identity_files(&node_id_path, &legacy_json_identity_path, &ident)?;
                ident
            } else if trimmed.len() == 36
                && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            {
                // Legacy UUID: migrate to JSON
                println!(
         
                    "🔍 NODE_ID is legacy UUID; migrating to JSON: {:?}",
                    trimmed
                );
                let node_id = trimmed.to_string();
                let first_seen = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_secs();
                let ident = NodeIdentity {
                    node_id,
                    first_seen,
                };
                write_identity_files(&node_id_path, &legacy_json_identity_path, &ident)?;
                println!("✅ Migrated legacy NODE_ID to JSON: {:?}", ident);
                ident
            } else {
                // Unrecognized format: fallback (could be legacy file, empty, or something else)
                println!("❌ NODE_ID format unrecognized, creating new identity");
                let node_id = uuid::Uuid::new_v4().to_string();
                let first_seen = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_secs();
                let ident = NodeIdentity {
                    node_id,
                    first_seen,
                };
                write_identity_files(&node_id_path, &legacy_json_identity_path, &ident)?;
                ident
            }
        }
        Err(_) => {
            println!("🔍 No NODE_ID file, checking for legacy IDENTITY");
            let maybe_legacy = std::fs::read_to_string(&legacy_json_identity_path).ok();
            if let Some(txt) = maybe_legacy {
                println!("🔍 Found legacy IDENTITY file");
                if txt.trim_start().starts_with('{') {
                    if let Ok(ident) = serde_json::from_str::<NodeIdentity>(&txt) {
                        println!("🔍 Migrating legacy identity to NODE_ID");
                        write_identity_files(&node_id_path, &legacy_json_identity_path, &ident)?;
                        println!("Migrated legacy JSON IDENTITY to NODE_ID");
                        ident
                    } else {
                        println!("🔍 Legacy identity invalid, creating new identity");
                        let node_id = uuid::Uuid::new_v4().to_string();
                        let first_seen = std::time::SystemTime::now()
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .unwrap_or(std::time::Duration::ZERO)
                            .as_secs();
                        let ident = NodeIdentity {
                            node_id,
                            first_seen,
                        };
                        write_identity_files(&node_id_path, &legacy_json_identity_path, &ident)?;
                        ident
                    }
                } else {
                    println!("🔍 Legacy identity not JSON, creating new identity");
                    let node_id = uuid::Uuid::new_v4().to_string();
                    let first_seen = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or(std::time::Duration::ZERO)
                        .as_secs();
                    let ident = NodeIdentity {
                        node_id,
                        first_seen,
                    };
                    write_identity_files(&node_id_path, &legacy_json_identity_path, &ident)?;
                    ident
                }
            } else {
                println!("🔍 No legacy identity found, creating new identity");
                let node_id = uuid::Uuid::new_v4().to_string();
                let first_seen = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_secs();
                let ident = NodeIdentity {
                    node_id,
                    first_seen,
                };
                write_identity_files(&node_id_path, &legacy_json_identity_path, &ident)?;
                ident
            }
        }
    };
    println!("✅ Node identity loaded: {}", identity.node_id);

    env::set_var("RUST_LOG", &cfg.log_level);
    env_logger::init();
    // T36.6: ensure bridge metrics are registered before serving HTTP
    #[cfg(feature = "metrics")]
    {
	    // existing registrars
        register_t36_bridge_metrics();
        register_t33_bridge_metrics();
        register_t34_rotation_metrics();
        register_t37_kemtls_metrics();

        // T40: make shadow + cutover counters visible at boot
        register_t40_shadow_sig_metrics();
        register_t40_cutover_metrics();
	}	
    // T37: spawn a dedicated /metrics HTTP server on EEZO_METRICS_BIND (or default)
    let metrics_bind = std::env::var("EEZO_METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:9898".into());
    tokio::spawn(spawn_metrics_server(metrics_bind.clone()));
    log::info!("spawned metrics server on {}", metrics_bind);	

    // Parse chain_id once, early — ENV overrides, else use genesis (default).
    // Allows decimal (e.g., "31337") or hex ("0x..."), left-padded to 20 bytes.
    let chain_id: [u8; 20] = match std::env::var("EEZO_CHAIN_ID") {
        Ok(s) => match parse_chain_id20_flexible(&s) {
            Some(id) => id,
            None => {
                #[cfg(feature = "persistence")]
                {
                    log::warn!(
                        "EEZO_CHAIN_ID='{}' invalid; falling back to genesis.chain_id",
                        s
                    );
                    let gpath = cfg.genesis.clone().ok_or_else(|| {
                        anyhow::anyhow!(
                            "EEZO_CHAIN_ID invalid and no --genesis provided (persistence on)"
                        )
                    })?;
                    let gtxt = std::fs::read_to_string(&gpath)
                        .with_context(|| format!("failed to read genesis file: {}", gpath))?;
                    let g: eezo_ledger::GenesisConfig = serde_json::from_str(&gtxt)
                        .with_context(|| format!("invalid genesis JSON: {}", gpath))?;
                    g.chain_id
                }
                #[cfg(not(feature = "persistence"))]
                {
                    eprintln!(
                        "EEZO_CHAIN_ID invalid and persistence is off; \
                         defaulting to devnet chain_id=...0001"
                    );
                    let mut out = [0u8; 20];
                    out[19] = 1; // 0x...0001
                    out
                }
            }
        },
        Err(_) => {
            #[cfg(feature = "persistence")]
            {
                // Fallback: derive chain_id from the supplied genesis file
                let gpath = cfg.genesis.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "EEZO_CHAIN_ID not set and no --genesis provided (persistence on)"
                    )
                })?;
                let gtxt = std::fs::read_to_string(&gpath)
                    .with_context(|| format!("failed to read genesis file: {}", gpath))?;
                let g: eezo_ledger::GenesisConfig = serde_json::from_str(&gtxt)
                    .with_context(|| format!("invalid genesis JSON: {}", gpath))?;
                g.chain_id
            }
            #[cfg(not(feature = "persistence"))]
            {
                eprintln!(
                    "EEZO_CHAIN_ID not set and persistence is off; \
                     defaulting to devnet chain_id=...0001"
                );
                let mut out = [0u8; 20];
                out[19] = 1; // 0x...0001
                out
            }
        }
    };
    println!("🔍 Chain ID (effective): {}", hex::encode(chain_id));
    // Bridge Alpha (optional for T33.1): admin ML-DSA-44 public key (hex)
	// If EEZO_BRIDGE_ALPHA is set (1/true), the key becomes required.
	let bridge_admin_pubkey: Option<Vec<u8>> = match env::var("EEZO_BRIDGE_ADMIN_PK") {
		Ok(s) => {
			let h = s.trim().trim_start_matches("0x");
			Some(hex::decode(h).expect("invalid EEZO_BRIDGE_ADMIN_PK hex"))
		}
		Err(_) => None,
	};
	let bridge_alpha_enabled = matches!(
	    env::var("EEZO_BRIDGE_ALPHA").as_deref(),
		Ok("1") | Ok("true") | Ok("TRUE")
	);
	if bridge_alpha_enabled && bridge_admin_pubkey.is_none() {
		return Err(anyhow::anyhow!(
		    "EEZO_BRIDGE_ADMIN_PK required when EEZO_BRIDGE_ALPHA is set"
		));
	}
	// (Optional) Use this to guard bridge logic/routes until we thread it into AppState.
	let _bridge_enabled = bridge_admin_pubkey.is_some();
    println!("🔍 Opening persistence store at: {}", cfg.datadir);
    // Put RocksDB in a dedicated subdir to avoid lock conflicts with other files
    let db_path = std::path::Path::new(&cfg.datadir).join("db");
    std::fs::create_dir_all(&db_path).context("failed to create db subdir")?;

    #[cfg(feature = "persistence")]
    let persistence = Arc::new({
    // Determine snapshot interval from env (prefer EEZO_SNAPSHOT_INTERVAL),
    // else fall back to EEZO_CHECKPOINT_EVERY, else default to 1000.
    let snap_from_env = std::env::var("EEZO_SNAPSHOT_INTERVAL").ok()
        .and_then(|s| s.parse::<u64>().ok());
    let snap_from_ckpt = std::env::var("EEZO_CHECKPOINT_EVERY").ok()
        .and_then(|s| s.parse::<u64>().ok());
    let snapshot_interval = snap_from_env.or(snap_from_ckpt).unwrap_or(1000);

    tracing::info!(
        "🔍 Using persistence snapshot_interval = {} blocks",
     
        snapshot_interval
    );

    let p_cfg = PersistenceCfg {
        db_path: db_path.clone(),
        snapshot_interval,
        enable_compression: true,
        cache_size_mb: 128,
    };
    persistence::open_db(&p_cfg)
        .with_context(|| format!("failed to open RocksDB at {}", db_path.display()))?
    });
    // If built without `persistence`, bail at runtime with a clear message.
    #[cfg(not(feature = "persistence"))]
    {
        // This is safe to keep since Patch 4 correctly guards the persistence usage
        // but removing it since the original code block was guarded by `#[cfg(feature = "persistence")]`
        // which would include it. Leaving it out as per the instructions is cleaner.
    }


    // Default to ready, and only become unready if bootstrap is initiated.
    let ready_flag = Arc::new(AtomicBool::new(true));
    #[cfg(feature = "metrics")]
    {
        crate::metrics::EEZO_NODE_READY.set(1);
    }

    // --- State Sync Bootstrap ---
    #[cfg(all(feature = "state-sync", feature = "persistence"))]
    {
        // Prefer CLI/Clap (which may be populated from env), but also fall back
        // to raw env reads so tests that only set env still work reliably.
        let bootstrap_url_opt = args.bootstrap_base
            .clone()
            .or_else(|| args.state_sync_source.clone())
            .or_else(|| std::env::var("EEZO_BOOTSTRAP_BASE_URL").ok()) // ← add this
            .or_else(|| std::env::var("EEZO_BOOTSTRAP_URL").ok());
        // legacy

		match &bootstrap_url_opt {
			Some(u) => log::info!("state-sync: bootstrap source = {}", u),
			None => log::warn!("state-sync: no bootstrap source set (EEZO_BOOTSTRAP_BASE_URL/--bootstrap-base, EEZO_STATE_SYNC_SOURCE, or EEZO_BOOTSTRAP_URL). Client will stay ready and NOT sync."),
		}
		eprintln!("BOOTSTRAP_DEBUG env(EEZO_BOOTSTRAP_BASE_URL) = {:?}", std::env::var("EEZO_BOOTSTRAP_BASE_URL").ok());
        eprintln!("BOOTSTRAP_DEBUG resolved bootstrap_url_opt = {:?}", bootstrap_url_opt);

        if let Some(base_url) = bootstrap_url_opt {
            log::info!("state-sync: resolved bootstrap base URL = {}", base_url);
            if base_url.starts_with("http") {
                log::info!("state-sync: starting HTTP client bootstrap from {}", base_url);
                let page_limit     = args.bootstrap_page_limit;
                let delta_span     = args.bootstrap_delta_span;
                let resume         = args.sync_resume;
                let max_retries    = args.sync_max_retries;
                let backoff_ms     = args.sync_backoff_ms;
                let backoff_cap_ms = args.sync_backoff_cap_ms;
                let watchdog_ms    = args.sync_bootstrap_timeout_ms;
                let allow_unsigned_anchor = args.sync_allow_unsigned_anchor;
				if allow_unsigned_anchor {
					log::warn!(
					"state-sync: policy override enabled — allowing UNSIGNED checkpoint anchors. \
					Use only in controlled environments (prefer HTTPS and restrict access)."
					);
				}

                if !resume {
                    log::warn!("state-sync: resume disabled; clearing existing sync progress.");
                    #[cfg(feature = "persistence")]
                    // Use the persistence handle created above instead of the not-yet-constructed AppState.
                    if let Err(e) = crate::state_sync::clear_sync_progress(persistence.as_ref()) {
                        log::error!("state-sync: failed to clear progress: {}", e);
                    }
                }

                // --- NON-BLOCKING / BACKGROUND BOOTSTRAP (fix for T29.8) ---
                let base_url_owned = base_url.clone();
                #[cfg(feature = "persistence")]
                // Clone the persistence handle for use in the background bootstrap task.
                let db_ptr = persistence.clone();
                let ready_flag_bg = ready_flag.clone();

                ready_flag_bg.store(false, Ordering::SeqCst);
                #[cfg(feature = "metrics")]
                { crate::metrics::EEZO_NODE_READY.set(0);
                }

                // move everything into a background task
                tokio::spawn(async move {
                    // run the blocking bootstrap on a blocking thread
                    let run_blocking = tokio::task::spawn_blocking(move || {

       
                          let cfg = crate::state_sync::BootstrapCfg {
                            base_url: &base_url_owned,
                            page_limit,

                     
                       delta_span,
                            max_retries,
                            backoff_ms,
                            backoff_cap_ms,

         
                           chain_id,
                            allow_unsigned_anchor,
                        };
                        crate::state_sync::bootstrap(db_ptr.as_ref(), &cfg)

    
                    });

                    let res = if watchdog_ms > 0 {
                        match tokio::time::timeout(std::time::Duration::from_millis(watchdog_ms), run_blocking).await {
                            Ok(joinres) => 
                            joinres,
                            // joined spawn_blocking
                            Err(_) => {
                                log::error!("state-sync: bootstrap watchdog {}ms expired;
                                leaving node unready", watchdog_ms);
                                #[cfg(feature = "metrics")] { crate::metrics::SS_FAILURES_TOTAL.inc(); }
                                return; // stay unready, keep serving /health

                      
                     }
                        }
                    } else {
                        run_blocking.await
                    };


    
                    match res {
                        Ok(Ok(())) => {
                            log::info!("state-sync: bootstrap successful. Node is now ready.");

                      
                             ready_flag_bg.store(true, Ordering::SeqCst);
                            #[cfg(feature = "metrics")] { crate::metrics::EEZO_NODE_READY.set(1); }
                        }
                        Ok(Err(e)) => {

          
                             match e {
                                crate::state_sync::SyncError::ProofFailed => {
                                    eprintln!("state-sync bootstrap failed due to proof/signature: {e}");
                                    // T29.9 requirement: fail fast on bad signature
                                    std::process::exit(1);
                                }
                                _ => {
                                    log::error!("state-sync: bootstrap failed: {e}. Node stays unready.");
                                    #[cfg(feature = "metrics")] { crate::metrics::SS_FAILURES_TOTAL.inc(); }
                                    // remain unready but keep serving /health
                                }

                     
                         }
                        }
                        Err(join_err) => {
                            log::error!("state-sync: bootstrap task panicked: {join_err}. Node stays unready.");
                            #[cfg(feature = "metrics")] { crate::metrics::SS_FAILURES_TOTAL.inc(); }
                        }
                    }
                });
            }
        }
    }

    // T36.2/5: construct SingleNode and start the deterministic slot runner
    // ── variant A: with persistence → pass DB handle so checkpoints use real roots
    #[cfg(all(feature = "pq44-runtime", feature = "persistence"))]
    let core_runner: Option<Arc<CoreRunnerHandle>> = {
        // Build runtime cfg from env (with safe defaults)
        let mut cfg = SingleNodeCfg {
            chain_id, // already parsed earlier
            block_byte_budget: env_usize("EEZO_MAX_BLOCK_BYTES", 1 << 20),
            header_cache_cap: env_usize("EEZO_HEADER_CACHE_CAP", 10_000),
            ..Default::default()
        };
        #[cfg(feature = "checkpoints")]
        {
            let v: u64 = env::var("EEZO_CHECKPOINT_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(eezo_ledger::consensus::DEFAULT_CHECKPOINT_INTERVAL);
            cfg.checkpoint_interval = v;
        }

        // Load (or create in dev) the node keys via wallet (ML-DSA-44)
        let keydir = std::env::var("EEZO_KEYDIR")
		    .map(std::path::PathBuf::from)
			.unwrap_or_else(|_| {
				let mut p = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
				p.push(".eezo/keys");
				p
			});
        let (pk, sk) = eezo_wallet::node_keys::load_or_create_mldsa44(&keydir, true)
		    .map_err(|e| anyhow::anyhow!("wallet key load failed: {e}"))?;
        let single: SingleNode = SingleNode::new(cfg, sk, pk);

        // tick cadence & error behavior (env-tunable)
        let tick_ms: u64 = env_u64("EEZO_CONSENSUS_TICK_MS", 200);
        let rollback_on_error = true;

        // NEW: pass the DB (Some(persistence.clone())) so T36.5 can read real roots/timestamp
        let runner = CoreRunnerHandle::spawn(single, Some(persistence.clone()), tick_ms, rollback_on_error);
        Some(runner)
    };

    // ── variant B: without persistence → keep the old call signature
    #[cfg(all(feature = "pq44-runtime", not(feature = "persistence")))]
    let core_runner: Option<Arc<CoreRunnerHandle>> = {
        // Build runtime cfg from env (with safe defaults)
    let mut cfg = SingleNodeCfg {
        chain_id, // already parsed earlier
        block_byte_budget: env_usize("EEZO_MAX_BLOCK_BYTES", 1 << 20),
        header_cache_cap: env_usize("EEZO_HEADER_CACHE_CAP", 10_000),
        ..Default::default()
    };
    #[cfg(feature = "checkpoints")]
        {
            let v: u64 = env::var("EEZO_CHECKPOINT_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(eezo_ledger::consensus::DEFAULT_CHECKPOINT_INTERVAL);
            cfg.checkpoint_interval = v;
        }

        let keydir = std::env::var("EEZO_KEYDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                let mut p = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
                p.push(".eezo/keys");
                p
        
            });
        let (pk, sk) = eezo_wallet::node_keys::load_or_create_mldsa44(&keydir, true)
            .map_err(|e| anyhow::anyhow!("wallet key load failed: {e}"))?;
        let single: SingleNode = SingleNode::new(cfg, sk, pk);

        let tick_ms = env_u64("EEZO_CONSENSUS_TICK_MS", 200);
        let rollback_on_error = true;
        let runner = CoreRunnerHandle::spawn(single, tick_ms, rollback_on_error);
        Some(runner)
    };
    // let hs: Arc<Mutex<eezo_ledger::HotStuff<StaticCertStore, consensus_runner::NodeLoopback>>> = {
    //     let certs = Arc::new(StaticCertStore::new());
    // consensus_runner::start_single_node_consensus(chain_id, certs)
    // };

    // ── T36.2: Start the consensus-core runner in testing mode and a QC holder
    #[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
    let core_runner = {
        log::info!("T36: Starting consensus-core runner (testing mode)");
        // Committee size placeholder = 4 (matches reducer/tests); adjust later as needed.
        let runner = crate::consensus_runner::start_core_consensus_for_testing(4);
        std::sync::Arc::new(runner)
    };
    #[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
    let last_qc = std::sync::Arc::new(tokio::sync::Mutex::new(None));
    #[cfg(all(feature = "metrics", feature = "pq44-runtime"))]
    crate::metrics::register_ledger_consensus_metrics();
    let metrics_on = env_bool("EEZO_METRICS", false);
    let metrics_port = env_u16("EEZO_METRICS_PORT", 9090);
    let verify_cache_cap = env_usize("EEZO_VERIFY_CACHE_CAP", 10_000);
    let parallel_verify = env_bool("EEZO_PARALLEL_VERIFY", true);
    let _verify_threshold = env_usize("EEZO_VERIFY_THRESHOLD", 32);
    if !(1..=65535).contains(&metrics_port) {
        anyhow::bail!("EEZO_METRICS_PORT must be in 1..=65535");
    }

    let max_bounds = (1usize << 10, 64usize << 20);
    let max_block_bytes = match env::var("EEZO_MAX_BLOCK_BYTES") {
        Ok(vs) => {
            let v: usize = vs
                .parse()
                .map_err(|e| anyhow::anyhow!("EEZO_MAX_BLOCK_BYTES must be an integer: {}", e))?;
            if v < max_bounds.0 || v > max_bounds.1 {
                anyhow::bail!(
                    "EEZO_MAX_BLOCK_BYTES out of range: must be between 1 KiB and 64 MiB"
                );
            }
            v
        }
        Err(_) => {
            let raw = env_usize("EEZO_MAX_BLOCK_BYTES", 1_000_000);
            raw.clamp(max_bounds.0, max_bounds.1)
        }
    };
    // -- Mempool runtime config (T30) ----------------------------------------
    // Defaults are safe for a devnet / single-node PoA.
    let mp_max_len       = env_usize("EEZO_MEMPOOL_MAX_LEN", 10_000);
    let mp_max_bytes     = env_usize("EEZO_MEMPOOL_MAX_BYTES", 64 * 1024 * 1024);
    // 64 MiB
    let mp_rate_capacity = env_usize("EEZO_MEMPOOL_RATE_CAP", 60) as u32;
    // burst
    let mp_rate_per_min  = env_usize("EEZO_MEMPOOL_RATE_PER_MIN", 600) as u32;
    // steady
    let mempool = crate::mempool::SharedMempool::new(crate::mempool::Mempool::new(
        mp_max_len,
        mp_max_bytes,
        mp_rate_capacity,
        mp_rate_per_min,
    ));
    // -- T34.0: crypto-suite rotation policy (env > genesis > defaults) ---------
    // we support both EEZO_ROTATION_* and EEZO_* env keys (either may be set).
    fn env_u8(keys: &[&str]) -> Option<u8> {
        for k in keys {
            if let Ok(v) = std::env::var(k) {
                if let Ok(x) = v.trim().parse::<u8>() {
                    return Some(x);
                }
            }
        }
        None
    }

    fn env_u64_opt(keys: &[&str]) -> Option<u64> {
        for k in keys {
            if let Ok(v) = std::env::var(k) {
                let t = v.trim();
                if t.is_empty() {
                    continue;
                }
                if let Ok(x) = t.parse::<u64>() {
                    return Some(x);
                }
            }
        }
        None
    }

    // 1) Try to read rotation defaults from genesis (if any)
    #[cfg(feature = "persistence")]
    let (gen_active, gen_next, gen_until) = {
        if let Some(gen_path) = &cfg.genesis {
            if let Ok(text) = std::fs::read_to_string(gen_path) {
                if let Ok(gc) = serde_json::from_str::<eezo_ledger::GenesisConfig>(&text) {
                    (gc.active_suite_id, gc.next_suite_id, gc.dual_accept_until)
                } else { (None, None, None) }
            } else { (None, None, None) }
        } else { (None, None, None) }
    };
    #[cfg(not(feature = "persistence"))]
    let (gen_active, gen_next, gen_until) = (None, None, None);

    // 2) Resolve with precedence: ENV > GENESIS > DEFAULTS
    let active_suite_id: u8 = env_u8(&["EEZO_ROTATION_ACTIVE_SUITE","EEZO_ACTIVE_SUITE"])
        .or(gen_active)
        .unwrap_or(1);

    let next_suite_id: Option<u8> = env_u8(&["EEZO_ROTATION_NEXT_SUITE","EEZO_NEXT_SUITE"])
        .or(gen_next);

    let dual_accept_until: Option<u64> =
        env_u64_opt(&["EEZO_ROTATION_DUAL_UNTIL","EEZO_DUAL_ACCEPT_UNTIL"])
            .or(gen_until);
    // A simple boolean for logs (and later, a metric/gauge in metrics.rs)
    let window_open = matches!((next_suite_id, dual_accept_until), (Some(_), Some(h)) if h > 0);
    // PATCH: Set the Prometheus gauge for crypto-suite rotation window
	#[cfg(feature = "metrics")]
	{
		use crate::metrics::EEZO_SUITE_ACCEPT_WINDOW_OPEN;
		EEZO_SUITE_ACCEPT_WINDOW_OPEN.set(if window_open { 1 } else { 0 });
	}

    log::info!(
        "crypto-rotation policy: active_suite={} next_suite={:?} dual_accept_until={:?} window_open={}",
        active_suite_id, next_suite_id, dual_accept_until, window_open
    );
    #[cfg(feature = "persistence")]
    {
        if let Some(gen) = &cfg.genesis {
            println!("🔍 About to read genesis file: {}", gen);
            let text = std::fs::read_to_string(gen).context("failed to read genesis file")?;
            println!("🔍 Parsing genesis JSON...");
            let genesis_cfg: GenesisConfig =
                serde_json::from_str(&text).context("invalid genesis JSON")?;
            println!("✅ Genesis file read and parsed");

            println!("🔍 Genesis chain ID: {}", hex::encode(genesis_cfg.chain_id));
            println!("🔍 Runtime chain ID: {}", hex::encode(chain_id));
            if genesis_cfg.chain_id != chain_id {
                eprintln!(
                    "❌ startup guard: EEZO_CHAIN_ID != genesis.chain_id\n  env  = {}\n  gen  = {}",
                    hex::encode(chain_id),
                    hex::encode(genesis_cfg.chain_id)
     
                );
                std::process::exit(1);
            } else {
                println!("✅ Genesis chain_id matches runtime");
            }

            println!("🔍 Applying genesis...");
            ensure_genesis(&persistence, &genesis_cfg).context("genesis application failed")?;
            println!("✅ Genesis applied");
        } else {
            println!("🔍 No genesis file specified, skipping genesis application");
        }
    }
    #[cfg(not(feature = "persistence"))]
    {
        // Keep variables used above from becoming “unused” when persistence is off
        let _ = cfg.genesis.as_ref();
    }

    println!("✅ Preparing runtime config");

    // --- normalize optional treasury env to canonical 20-byte hex ---
    let treasury_env = std::env::var("EEZO_TREASURY").ok().filter(|s| !s.trim().is_empty());
    let treasury_canonical: Option<String> = treasury_env
        .as_deref()
        .and_then(|raw| parse_account_addr(raw)
            .map(|a| format!("0x{}", hex::encode(a.as_bytes()))));
    // (optional log)
    if let Some(ref t) = treasury_canonical {
        log::info!("treasury configured at {}", t);
    }

    let runtime_config = RuntimeConfigView {
        chain_id_hex: hex::encode(chain_id),
        verify_cache_cap,
        parallel_verify,
        max_block_bytes,
        metrics_on,
        metrics_port,
        node: NodeConfigView {
            listen: cfg.listen.clone(),
            datadir: cfg.datadir.clone(),
       
             genesis: cfg.genesis.clone(),
            log_level: cfg.log_level.clone(),
        },
        node_id: identity.node_id.clone(),
        first_seen: identity.first_seen,
        peers: cfg.peers.clone(),
        treasury: treasury_canonical.clone(),
		// T34 fields come from the env we parsed earlier
		active_suite_id,
		next_suite_id,
		dual_accept_until,
    };
    println!(
        "✅ Runtime config built: node_id={}, listen={}",
        runtime_config.node_id, runtime_config.node.listen
    );
    #[cfg(feature = "metrics")]
    NODE_STARTS.inc();

    let admin_token = std::env::var("EEZO_ADMIN_TOKEN").ok();
    let started_at = SystemTime::now();
    let version: &'static str = env!("CARGO_PKG_VERSION");
    let git_sha: Option<&'static str> = option_env!("EEZO_BUILD_GIT_SHA");

    let peers_cfg = cfg.peers.clone();
    let zero_peer_mode = peers_cfg.is_empty();
    let hook = {
        let ready_flag = ready_flag.clone();
        move |q_ok: bool|
    {
            println!("🔍 Quorum hook called with q_ok={}, zero_peer_mode={}", q_ok, zero_peer_mode);
            if !zero_peer_mode {
                println!("🔍 Multi-peer mode: setting readiness to {}", q_ok);
                ready_flag.store(q_ok, Ordering::SeqCst);
                #[cfg(feature = "metrics")]
                crate::metrics::EEZO_NODE_READY.set(if q_ok { 1 } else { 0 });
            } else {
                println!("🔍 Zero-peer mode: ignoring quorum change, readiness remains as is");
            }
        }
    };

    let peer_svc = PeerService::new_with_hook(peers_cfg.clone(), hook)?;
    println!("🔍 Configured peers: {:?}", cfg.peers);

    peer_svc.clone().spawn().await;
    println!("✅ Peer service started - current readiness: {}", ready_flag.load(Ordering::SeqCst));
    println!("🔍 Zero-peer mode status: {}", zero_peer_mode);

    // Restore block height from RocksDB (fallback to 0)
    #[cfg(feature = "persistence")]
    let start_h = match persistence.get_tip() {
        Ok(h) => {
            if h > 0 {
                 println!("✅ Restored height: {}", h);
            } else {
                 println!("🔍 No tip found, start at 0");
            }
            h
        }
        Err(e) => {
            eprintln!("⚠️ Failed to load tip: {e}. Starting at 0");
            0
        }
    };

    #[cfg(not(feature = "persistence"))]
    let start_h: u64 = 0;
    
    let block_height = Arc::new(AtomicU64::new(start_h));
    let accounts = Accounts::new();
    accounts.mint("0x01", 1_000_000).await;

    let recent_blocks = Arc::new(RwLock::new(RecentBlocks {
        by_height: Map::new(),
        order: VecDeque::new(),
        cap: 1024, // keep last 1024 heights
    }));
    let receipts = Arc::new(RwLock::new(HashMap::<String, Receipt>::new()));

    let state = AppState {
        runtime_config: runtime_config.clone(),
        ready_flag: ready_flag.clone(),
        admin_token,
        started_at,
        version,
        git_sha,
        identity,
        peers: peer_svc.state(),
        peer_svc: peer_svc.clone(),
        config_file_path: args.config_file.clone(),

      
         block_height: block_height.clone(),
        mempool: mempool.clone(),
        accounts: accounts.clone(),
        recent_blocks: recent_blocks.clone(),
        receipts: receipts.clone(),
        treasury_addr: treasury_canonical.clone(),
        #[cfg(feature = "persistence")]
        db: persistence.clone(),
        // t36: consensus core runner handle (started in T36.2)
        #[cfg(feature = "pq44-runtime")]
        core_runner,
        #[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
        core_runner: core_runner.clone(), // Clashes in name if features overlap
        #[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
        last_qc: last_qc.clone(),
		// Bridge Alpha
		chain_id,
		bridge_admin_pubkey,
		bridge: Arc::new(AsyncMutex::new(BridgeState::default())),
		outbox: Arc::new(RwLock::new(Vec::new())),
        active_suite_id,
        next_suite_id,
        dual_accept_until,
        // T36.8: plumb CLI/env-configured datadir into AppState
        datadir: Some(std::path::PathBuf::from(cfg.datadir.clone())),
    };
    println!(
        "✅ AppState initialized: ready_flag={}, version={}, git_sha={:?}",
        ready_flag.load(Ordering::SeqCst),
        version,
        git_sha
    );
    #[cfg(feature = "metrics")]
    {
        let git = state.git_sha.unwrap_or("");
        NODE_INFO
            .with_label_values(&[&state.identity.node_id, state.version, git])
            .set(1.0);
    }
	
    #[cfg(feature = "persistence")]
    {
        if std::env::var("EEZO_BRIDGE_OUTBOX_ENABLED").ok().as_deref() == Some("1") {
            let state_clone = state.clone();
            tokio::spawn(async move {
                use std::{env, fs, path::PathBuf, time::Duration};
                log::info!("🚀 Bridge checkpoint emitter task starting...");

                // How often to emit (heights): default 32
                let checkpoint_every: u64 = env::var("EEZO_CHECKPOINT_EVERY")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(32);

                // Resolve outbox directory once
                let outbox_dir: PathBuf = env::var("EEZO_BRIDGE_OUTBOX_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        let mut p = state_clone
                            .datadir
                            .clone()
                            .unwrap_or_else(|| PathBuf::from("."));
                        p.push("proof");
                        p.push("checkpoints");
                        p
                    });
                if let Err(e) = fs::create_dir_all(&outbox_dir) {
                    log::error!("❌ bridge: failed to create outbox dir {}: {e}", outbox_dir.display());
                }
                log::info!(
                    "bridge: emitter configured: outbox_dir={}, checkpoint_every={}",
                    outbox_dir.display(),
                    checkpoint_every
                );

                // Track last emitted height
                let mut last_emitted: u64 = 0;
                let mut ticker = tokio::time::interval(Duration::from_secs(5));

                loop {
                    ticker.tick().await;

                    // Discover current tip by probing headers (robust, no special API needed)
                    let mut tip = last_emitted;
                    loop {
                        let next = tip.saturating_add(1);
                        match state_clone.db.get_header(next) {
                            Ok(_) => tip = next,
                            Err(_) => break,
                        }
                    }

                    if checkpoint_every == 0 || tip == 0 {
                        // Nothing to do yet
                        continue;
                    }

                    // Emit for each multiple crossed since last tick
                    let mut h = ((last_emitted / checkpoint_every) + 1) * checkpoint_every;
                    while h <= tip {
                        // Gather data
                        let hdr = match state_clone.db.get_header(h) {
                            Ok(h) => h,
                            Err(e) => { log::warn!("bridge: header {} missing: {e}", h); break; }
                        };
                        let state_root = match state_clone.db.get_state_root_v2(h) {
                            Ok(r) => r,
                            Err(e) => { log::warn!("bridge: state_root {} missing: {e}", h); break; }
                        };
                        let tx_root = match state_clone.db.get_tx_root_v2(h) {
                            Ok(r) => r,
                            Err(e) => { log::warn!("bridge: tx_root {} missing: {e}", h); break; }
                        };
                        let ts_secs = match state_clone.db.get_header_timestamp_secs(h) {
                            Ok(t) => t,
                            Err(e) => { log::warn!("bridge: timestamp {} missing: {e}", h); break; }
                        };

                        // Rotation policy: prefer explicit env override (T41.7/T41.8),
                        // fall back to AppState rotation view if env is not set.
                        let policy = eezo_ledger::checkpoints::rotation_policy_from_env()
                            .unwrap_or_else(|| eezo_ledger::rotation::RotationPolicy {
                                active: eezo_crypto::suite::CryptoSuite::try_from(
                                    state_clone.active_suite_id,
                                )
                                .unwrap_or(eezo_crypto::suite::CryptoSuite::MlDsa44),
                                next: state_clone.next_suite_id.and_then(|id| {
                                    eezo_crypto::suite::CryptoSuite::try_from(id).ok()
                                }),
                                dual_accept_until: state_clone.dual_accept_until,
                                activated_at_height: None,
                            });

                        let header_hash = eezo_ledger::block::header_hash(&hdr);
                        let finality_depth = 2u64;
						
                        // Fix: Use the full 7-argument public constructor
                        let args = eezo_ledger::checkpoints::CheckpointArgs::new(
                            &policy, h, header_hash, state_root, tx_root, ts_secs, finality_depth
                        );

                        match eezo_ledger::checkpoints::emit_bridge_checkpoint_with_path(
                            &outbox_dir,
                            &args,
                        ) {
                            Ok(paths) => {
                                log::info!(
                                    "✅ bridge: wrote {} checkpoint file(s) at height {} (e.g. {})",
                                    paths.len(),
                                    h,
                                    paths.first().map(|p| p.display().to_string()).unwrap_or_default()
                                );
                                #[cfg(feature = "metrics")]
                                {
                                    // EEZO_BRIDGE_OUTBOX_TOTAL is an IntCounter (no labels)
                                    crate::metrics::EEZO_BRIDGE_OUTBOX_TOTAL.inc_by(paths.len() as u64);
                                    crate::metrics::bridge_latest_height_set(h);
                                }
                                last_emitted = h;
                                h += checkpoint_every;
                            }
                            Err(e) => {
                                log::error!("❌ bridge: emit failed at h={}: {}", h, e);
                                // Don't advance last_emitted so we retry next tick
                                break;
                            }
                        }
                    }
                }
            });
            log::info!("✅ bridge checkpoint emitter task started (EEZO_BRIDGE_OUTBOX_ENABLED=1)");
        } else {
            log::info!("🔶 bridge checkpoint emitter disabled (set EEZO_BRIDGE_OUTBOX_ENABLED=1 to enable)");
        }
    }

    #[cfg(not(feature = "persistence"))]
    {
        log::info!("🔶 bridge checkpoint emitter disabled: node built without `persistence` feature");
    }

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/healthz", get(health_handler))
        .route("/ready", get(ready_handler))
        // ── T36.2: consensus endpoints (only when testing the adapter) ──
        .route(
            "/consensus/vote",
            post({
                
                #[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
                { post_vote }
                #[cfg(not(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime"))))]
                { health_handler } // stub to keep router building when feature off
            }),
        )
        .route(
 
            "/consensus/qc",
            get({
                #[cfg(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime")))]
                { get_qc }
                #[cfg(not(all(feature = "consensus-core-adapter", feature = "consensus-core-testing", not(feature = "pq44-runtime"))))]
                { 
                health_handler }
            }),
        )
        .route("/readyz", get(ready_handler))
        .route("/config", get(config_handler))
        .route("/status", get(status_handler))
        .route("/head", get(head_handler))
        // T30 tx endpoints
        .route("/tx", post(post_tx))
        .route("/tx/:hash", get(get_tx))
        .route("/receipt/:hash", get(get_receipt))
     
           .route("/txpool", get(txpool_handler))
        .route("/block/:height", get(block_handler))
        .route("/account/:addr", get(get_account))
        .route("/faucet", post(post_faucet))
		// T33 Bridge Alpha endpoints
		.route("/bridge/mint", post(bridge::post_bridge_mint))
		.route("/bridge/outbox", get(bridge::get_outbox))
		.route("/bridge/outbox/:id", get(bridge::get_outbox_one))
        .route("/_admin/degrade", get(admin_degrade))
        .route("/_admin/restore", get(admin_restore))
        .route("/_admin/peers",get(admin_peers_handler).post(admin_peers_update_handler))
        .route("/_admin/runtime", get(admin_runtime_handler))
        .route("/peers", get(peers_handler))
        .route("/reload",post(reload_handler).get(reload_from_file_handler))
		.route("/metrics", get(metrics_handler_any));

    // --- DEV tools: admin surface (feature-gated) ---
	// --- DEV tools: admin surface (feature-gated) ---
    #[cfg(feature = "dev-tools")]
    let app = app
        // raw opaque-bytes ingest (hash + enqueue into mempool)
        .route("/_admin/tx_raw", post(post_tx_raw_admin))
        // force-commit a minimal empty block at tip+1 and emit checkpoint
        .route("/_admin/commit_now", post(admin_commit_now))
        // commit with explicit tx hashes
        
        .route("/_admin/commit_with_hashes", post(admin_commit_with_hashes));

    // t36: removed legacy demo_propose route
    // #[cfg(feature = "pq44-runtime")]
    // let app = app.route("/demo/propose", post(demo_propose));
    // Mount state-sync endpoints whenever features are enabled
    #[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
    let app = {
        // Handlers live under http::state
        use crate::http::state as ss;
        use axum::routing::get;
        app
           // high-level node+bridge view
           .route("/state",          get(ss::get_node_state))
           // existing state-sync endpoints
           .route("/state/anchor",   get(ss::get_anchor))
           .route("/state/snapshot", get(ss::get_snapshot))
           .route("/state/delta",    get(ss::get_delta))
           // ---- v2 ETH-SSZ endpoints (new) ----
           .route("/state/snapshot/manifest", get(ss::get_snapshot_manifest_v2))
           .route("/state/snapshot/blob",     get(ss::get_snapshot_blob))
           .route("/state/delta/manifest",    get(ss::get_delta_manifest_v2))
    };
    // Mount the DEV write route ONLY in debug or when dev-tools is enabled
    #[cfg(all(
        feature = "state-sync",
        feature = "state-sync-http",
        any(debug_assertions, feature = "dev-tools")
    ))]
    let app = {
        use crate::http::state::dev_put;
        let app = app.route("/_admin/put", get(dev_put));
        app.route("/_admin/seed_anchor", get(seed_anchor_dev))
    };
    // Final app is ready (convert back to immutable if desired)
    let app = app;
    // -------------------------------------------------------------------------

    println!("✅ Router built with /ready, /config, /status, /peers, /_admin endpoints");
    // -------------------------------------------------------------------------
    // T30: Minimal single-node proposer
    // - Every EEZO_PROPOSER_INTERVAL_MS (default 400ms), pop a batch from mempool
    // - DEV STUB: mark each popped tx as included at (height += 1)
    //   (next step: call ledger::apply_signed_tx and mark accepted/rejected accordingly)
    // -------------------------------------------------------------------------
    {
        let state_clone = state.clone();
        let interval_ms = env_usize("EEZO_PROPOSER_INTERVAL_MS", 400) as u64;
        #[cfg(feature = "persistence")]
        let db = state_clone.db.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_millis(interval_ms));
            loop {
                tick.tick().await;
                let target_bytes = state_clone.runtime_config.max_block_bytes;
                let batch = state_clone.mempool.pop_batch(target_bytes).await;

               
                 if batch.is_empty() {
                    continue;
                }
                // Capture current tip and pre-compute the *next* height once.
				let cur_h  = state_clone.block_height.load(Ordering::SeqCst);
				let next_h = cur_h.saturating_add(1);
                let mut any_included = false;

         
               // Build “block” index for the UI/debug (list of tx hashes as 0x…)
                let mut block_hashes: Vec<String> = Vec::with_capacity(batch.len());

                for entry in batch {
                    // Try to parse the submitted envelope

              
                     let env = match serde_json::from_slice::<SignedTxEnvelope>(&entry.bytes) {
                        Ok(v) => v,
                        Err(e) => {
                            let reason = format!("bad envelope: {e}");
                            state_clone
                                .mempool
                                .mark_rejected(&entry.hash, reason.clone(), entry.bytes.len())
                                .await;
                            let hhex = format!("0x{}", hex::encode(entry.hash));
                            let dummy_tx = TransferTx { from: "".into(), to: "".into(), amount: "".into(), nonce: "".into(), fee: "".into(), chain_id: "".into() };
                            let receipt = Receipt{
                                hash: hhex.clone(),
                                status: "rejected",
                               
                                 block_height: None,
                                from: dummy_tx.from.clone(),
                                to: dummy_tx.to.clone(),
                                
                                amount: dummy_tx.amount.clone(),
                                fee: dummy_tx.fee.clone(),
                                nonce: dummy_tx.nonce.clone(),
                                error:
 
                                Some(reason),
                            };
                            state_clone.receipts.write().await.insert(hhex.clone(), receipt.clone());


                            #[cfg(feature = "metrics")] { TX_REJECTED_TOTAL.inc(); }
                            continue;
                        }
                    };
                    // --- Basic validation (devnet) ---

                    // Normalize account strings to canonical 0x… form using the addr helper
                    let from_hex = match parse_account_addr(&env.tx.from) {
                        Some(addr) => format!("0x{}", hex::encode(addr.as_bytes())),
            
                        None => {
                            return (
                                StatusCode::BAD_REQUEST,
                         
                               Json(serde_json::json!({"error":"invalid from address"})),
                            )
                        }
                    };
                    let to_hex = match parse_account_addr(&env.tx.to) {
                        Some(addr) => format!("0x{}", hex::encode(addr.as_bytes())),
                        None => {
                            return (
             
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({"error":"invalid to address"})),
                            )
                   
                     }
                    };
                    // 1) chain id must match runtime
                    let mut ok = true;
                    if let Some(tx_cid) = parse_chain_id_hex(&env.tx.chain_id) {
                        if tx_cid != hex::decode(&state_clone.runtime_config.chain_id_hex)
                            .ok()
                            .and_then(|v| {
                                if v.len() == 20 {
                                    let mut a = [0u8; 20];
                                    a.copy_from_slice(&v);
                                    Some(a)
                                } else { None }
                            })
                            .unwrap_or([0u8; 20])
                        {
                   
                         ok = false;
                        }
                    } else {
                        // allow the short devnet form "0x01" -> map to ...0001
                        let short_ok = env.tx.chain_id.trim().eq_ignore_ascii_case("0x01")
                 
                           && state_clone.runtime_config.chain_id_hex.ends_with("0000000000000000000000000000000000000001");
                        if !short_ok { ok = false;
                        }
                    }
                    if !ok {
                        let reason = "wrong chain_id".to_string();
                        state_clone
                            .mempool
                            .mark_rejected(&entry.hash, reason.clone(), entry.bytes.len())
                            .await;
                        let hhex = format!("0x{}", hex::encode(entry.hash));
                        let receipt = Receipt{
                            hash: hhex.clone(),
                            status: "rejected",
                            block_height: None,
     
                            from: env.tx.from.clone(),
                            to: env.tx.to.clone(),
                            amount: env.tx.amount.clone(),
                  
                             fee: env.tx.fee.clone(),
                            nonce: env.tx.nonce.clone(),
                            error: Some(reason),
                        };
                        state_clone.receipts.write().await.insert(hhex.clone(), receipt.clone());
                        #[cfg(feature = "metrics")] { TX_REJECTED_TOTAL.inc(); }
                        continue;
                    }

                    // 2) parse amounts
                    let amount = match env.tx.amount.parse::<u64>() {
                        Ok(v) => v,
                        Err(_) =>
 
                        {
                            let reason = "amount not u64".to_string();
                            state_clone.mempool
                                .mark_rejected(&entry.hash, reason.clone(), entry.bytes.len())
                                .await;
                            let hhex = format!("0x{}", hex::encode(entry.hash));
                            let receipt = Receipt{
                                hash: hhex.clone(),
                                status: "rejected",
                          
                                 block_height: None,
                                from: env.tx.from.clone(),
                                to: env.tx.to.clone(),
                           
                                 amount: env.tx.amount.clone(),
                                fee: env.tx.fee.clone(),
                                nonce: env.tx.nonce.clone(),
                            
                                 error: Some(reason),
                            };
                            state_clone.receipts.write().await.insert(hhex.clone(), receipt.clone());
                            #[cfg(feature = "metrics")] { TX_REJECTED_TOTAL.inc(); }
                            continue;
                        }
                    };
                    let fee = match env.tx.fee.parse::<u64>() {
                        Ok(v) => v,
                        Err(_) => {
                            let reason = "fee not u64".to_string();
                            state_clone.mempool
                                .mark_rejected(&entry.hash, reason.clone(), entry.bytes.len())
                                .await;
                            let hhex = format!("0x{}", hex::encode(entry.hash));
                            let receipt = Receipt{
                                hash: hhex.clone(),
                                status: "rejected",
                          
                                 block_height: None,
                                from: env.tx.from.clone(),
                                to: env.tx.to.clone(),
                           
                                 amount: env.tx.amount.clone(),
                                fee: env.tx.fee.clone(),
                                nonce: env.tx.nonce.clone(),
                            
                                 error: Some(reason),
                            };
                            state_clone.receipts.write().await.insert(hhex.clone(), receipt.clone());
                            #[cfg(feature = "metrics")] { TX_REJECTED_TOTAL.inc(); }
                            continue;
                        }
                    };
                    let want_nonce = match env.tx.nonce.parse::<u64>() {
                        Ok(v) => v,
                        Err(_) => {
                            let reason = "nonce not u64".to_string();
                            state_clone.mempool
                                .mark_rejected(&entry.hash, reason.clone(), entry.bytes.len())
                                .await;
                            let hhex = format!("0x{}", hex::encode(entry.hash));
                            let receipt = Receipt{
                                hash: hhex.clone(),
                                status: "rejected",
                          
                                 block_height: None,
                                from: env.tx.from.clone(),
                                to: env.tx.to.clone(),
                           
                                 amount: env.tx.amount.clone(),
                                fee: env.tx.fee.clone(),
                                nonce: env.tx.nonce.clone(),
                            
                                 error: Some(reason),
                            };
                            state_clone.receipts.write().await.insert(hhex.clone(), receipt.clone());
                            #[cfg(feature = "metrics")] { TX_REJECTED_TOTAL.inc(); }
                            continue;
                        }
                    };
                    // nonce must equal current sender nonce
                    let (bal, cur_nonce) = state_clone.accounts.get(&from_hex).await;
                    if want_nonce != cur_nonce {
                        let reason = format!("bad nonce: want={}, cur={}", want_nonce, cur_nonce);
                        state_clone.mempool
                            .mark_rejected(&entry.hash, reason.clone(), entry.bytes.len())
                            .await;
                        let hhex = format!("0x{}", hex::encode(entry.hash));
                        let receipt = Receipt{
                            hash: hhex.clone(),
                            status: "rejected",
                            block_height: None,
     
                            from: env.tx.from.clone(),
                            to: env.tx.to.clone(),
                            amount: env.tx.amount.clone(),
                  
                             fee: env.tx.fee.clone(),
                            nonce: env.tx.nonce.clone(),
                            error: Some(reason),
                        };
                        state_clone.receipts.write().await.insert(hhex.clone(), receipt.clone());
                        #[cfg(feature = "metrics")] { TX_REJECTED_TOTAL.inc(); }
                        continue;
                    }

                    // 4) sufficient balance
                    let need = amount.saturating_add(fee);
                    if bal < need {
                        let reason = "insufficient funds".to_string();
                        state_clone.mempool
                            .mark_rejected(&entry.hash, reason.clone(), entry.bytes.len())
                            .await;
                        let hhex = format!("0x{}", hex::encode(entry.hash));
                        let receipt = Receipt{
                            hash: hhex.clone(),
                            status: "rejected",
                            block_height: None,
     
                            from: env.tx.from.clone(),
                            to: env.tx.to.clone(),
                            amount: env.tx.amount.clone(),
                  
                             fee: env.tx.fee.clone(),
                            nonce: env.tx.nonce.clone(),
                            error: Some(reason),
                        };
                        state_clone.receipts.write().await.insert(hhex.clone(), receipt.clone());
                        #[cfg(feature = "metrics")] { TX_REJECTED_TOTAL.inc(); }
                        continue;
                    }

                    // 5) DEV: apply to in-memory accounts (debit sender, inc nonce; credit receiver)
                    let _new_nonce = match state_clone.accounts.consume_nonce_and_debit(&from_hex, need).await {
                        Ok(n) => n,
                
                         Err(e) => {
                            let reason = format!("apply debit failed: {e}");
                            state_clone.mempool
                                .mark_rejected(&entry.hash, reason.clone(), entry.bytes.len())
                                .await;
                            let hhex = format!("0x{}", hex::encode(entry.hash));
                            let receipt = Receipt{
                                hash: hhex.clone(),
                                status: "rejected",
                          
                                 block_height: None,
                                from: env.tx.from.clone(),
                                to: env.tx.to.clone(),
                           
                                 amount: env.tx.amount.clone(),
                                fee: env.tx.fee.clone(),
                                nonce: env.tx.nonce.clone(),
                            
                                 error: Some(reason),
                            };
                            state_clone.receipts.write().await.insert(hhex.clone(), receipt.clone());
                            #[cfg(feature = "metrics")] { TX_REJECTED_TOTAL.inc(); }
                            continue;
                        }
                    };
                    // credit receiver with 'amount'
                    state_clone.accounts.mint(&to_hex, amount).await;
                    // fees: credit treasury if configured; otherwise implicitly burned
                    if let Some(ref t) = state_clone.treasury_addr {
                        if fee > 0 {
                            state_clone.accounts.mint(t, fee).await;
                        }
                    }

                    if !any_included {
                        any_included = true;
                    }

                    // Mark included at the precomputed canonical height
					state_clone
					    .mempool
						.mark_included(&entry.hash, next_h, entry.bytes.len())
						.await;
                    let hhex = format!("0x{}", hex::encode(entry.hash));
                    let receipt = Receipt {
                        hash: hhex.clone(),
                        status: "included",
                        block_height: Some(next_h),
                
                         from: env.tx.from.clone(),
                        to: env.tx.to.clone(),
                        amount: env.tx.amount.clone(),
                        fee: env.tx.fee.clone(),
                
                         nonce: env.tx.nonce.clone(),
                        error: None,
                    };
                    state_clone.receipts.write().await.insert(hhex.clone(), receipt);
                    #[cfg(feature = "metrics")] {
                        TX_ACCEPTED_TOTAL.inc();
                    }
                    block_hashes.push(format!("0x{}", hex::encode(entry.hash)));
                }

                // Record which txs we actually accepted this round (we already pushed each
                // accepted tx hash into `block_hashes` above and flipped `any_included`).
                if any_included {
                    // Use the same (cur_h, next_h) pair everywhere for continuity.
                    let prev_h = cur_h;

                    // --- Build a minimal header (ok to leave merkle roots zero for now) ---
                    // If you don't have a stored prev_hash, you can leave it zero on devnet.
                    let prev_hash = [0u8; 32];
                    let header = BlockHeader {
                        prev_hash,
                        height: next_h,
                        tx_root: [0u8; 32],
                        #[cfg(feature = "eth-ssz")]
                        tx_root_v2: [0u8; 32],
                        fee_total: 0, // (optional) sum fees you credited to treasury if you like
                        timestamp_ms: now_ms(),
                        tx_count: block_hashes.len() as u32,

                        #[cfg(feature = "checkpoints")]
                        qc_hash: [0u8; 32],
                    };
                    // For now we can persist an empty-tx Block. T32 only cares that height
                    // advances and receipts flip to "included".
                    // (You can add real tx bodies later.)
                    let block = Block { header, txs: Vec::new() };

                    // --- optional persistence: write header + snapshot + tip ---
                    #[cfg(feature = "persistence")]
                    {
                        let prev_supply = match db.get_latest_snapshot_at_or_below(prev_h) {
                            Ok(Some(s)) => s.supply.clone(),
                            _ => Supply {
                                native_mint_total: 0,
                                bridge_mint_total: 0,
                                burn_total: 0,
                            },
                        };
                        let state_root = [0u8; 32];

                        if let Err(e) = db.put_header_and_block(next_h, &block.header, &block) {
                            eprintln!("❌ persist header+block failed at h={}: {}", next_h, e);
                        } else {
                            let snap = StateSnapshot {
                                height: next_h,
                                accounts: eezo_ledger::Accounts::default(),
                                supply: prev_supply,
                                state_root,
                                bridge: Some(eezo_ledger::bridge::BridgeState::default()),
                                #[cfg(feature = "eth-ssz")]
                                codec_version: 2,
                                #[cfg(feature = "eth-ssz")]
                                state_root_v2: state_root,
                            };
                            if let Err(e) = db.put_state_snapshot(&snap) {
                                eprintln!("❌ persist snapshot failed at h={}: {}", next_h, e);
                            }
                            if let Err(e) = db.set_tip(next_h) {
                                eprintln!("❌ set_tip({}) failed: {}", next_h, e);
                            }
                        }
                    }

                    // publish height + metrics in all builds (persistence or not)
                    state_clone.block_height.store(next_h, Ordering::SeqCst);
                    #[cfg(feature = "metrics")]
                    {
                        crate::metrics::EEZO_BLOCK_HEIGHT.set(next_h as i64);
                        crate::metrics::EEZO_MEMPOOL_LEN
                            .set(state_clone.mempool.len().await as i64);
                    }

                    // keep the in-memory index for /block/:height
                    let mut rb = state_clone.recent_blocks.write().await;
                    rb.by_height.insert(next_h, block_hashes.clone());
                    rb.order.push_back(next_h);
                    while rb.order.len() > rb.cap {
                        if let Some(old_h) = rb.order.pop_front() {
                            rb.by_height.remove(&old_h);
                        }
                    }

                    log::info!("✅ committed block h={} ({} txs)", next_h, block_hashes.len());
                }

            }
        });
    }

    let addr: SocketAddr = cfg.listen.parse().context("invalid listen address")?;
    println!("🔍 Binding to address: {}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind to {}", cfg.listen))?;
    println!("✅ TCP listener bound on {}", cfg.listen);

    println!("🚀 Server starting with readiness = {}", ready_flag.load(Ordering::SeqCst));
    if std::env::var("EEZO_SIMULATE_BG_IO_ERROR").ok().as_deref() == Some("on") {
        let ready_flag_bg = ready_flag.clone();
        tokio::spawn(async move {
            // Delay increased to 2.5s to give the test plenty of time to see the initial 200 OK
			println!("🔍 BG error simulator: waiting 2500ms before degrading readiness");
            tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
			println!("🔍 BG error simulator: flipping readiness to false");
            ready_flag_bg.store(false, Ordering::SeqCst);
            #[cfg(feature = "metrics")]
            {
   
                 crate::metrics::EEZO_NODE_READY.set(0);
                NODE_BG_ERROR_TOTAL.inc();
            }
            eprintln!("simulated background error: readiness degraded");
        });
        println!("✅ Background error simulation task scheduled (will trigger in 2500ms)");
    }

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let st = state.clone();
        tokio::spawn(async move {
            // Do NOT panic if the OS/TTY doesn't support SIGHUP (e.g., some WSL/Windows shells).
			// If this fails, just run without live peer reloads instead of crashing the node.
			let mut hup = match signal(SignalKind::hangup()) {
				Ok(s) => s,
				Err(e) => {
					eprintln!("signal(SIGHUP) setup failed: {e}; continuing without reload support");
					return;
				}
			};
            while hup.recv().await.is_some() {
                if let Ok(v) = load_nodecfg_peers_or_empty(&st.config_file_path) {

   
                     st.peer_svc.set_peers(dedup_preserve_order(v)).await;
                }
            }
        });
    } // <-- important: close the #[cfg(unix)] block
    println!("🎉 SERVER SUMMARY:");
    println!("   • Node ID: {}", runtime_config.node_id);
    println!("   • Listening on: {}", cfg.listen);
    println!("   • Data directory: {}", cfg.datadir);
    println!("   • Chain ID: {}", runtime_config.chain_id_hex);
    println!("   • Version: {}", version);
    println!("   • Git SHA: {:?}", git_sha);
    println!("   • Ready: {}", ready_flag.load(Ordering::SeqCst));
    println!("   • Configured peers: {}", peers_cfg.len());
    println!("   • Mempool: max_len={}, max_bytes={} (rate: cap={}, per_min={})",
        mp_max_len, mp_max_bytes, mp_rate_capacity, mp_rate_per_min);
    println!("🚀 Node is ready and listening on {}", cfg.listen);

    println!("🔍 Final readiness check before server start: {}", ready_flag.load(Ordering::SeqCst));
    // ── Graceful shutdown: stop consensus runner on Ctrl-C ───────────────────
    // T36.2: only present on the pq44-runtime path where CoreRunnerHandle exists.
    #[cfg(feature = "pq44-runtime")]
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        log::info!("signal: Ctrl-C received; shutting down...");
    };

    #[cfg(not(feature = "pq44-runtime"))]
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        log::info!("signal: Ctrl-C received; shutting down...");
    };

    println!("🚀 Launching Axum server now...");
    axum::serve(listener, app.clone().merge(build_bridge_router()).with_state(state.clone()))
        .with_graceful_shutdown(async move {  // <-- Add `move` here
            shutdown_signal.await;

            // Stop consensus runner if it exists
            #[cfg(feature = "pq44-runtime")]
            if let Some(r) = state.core_runner.clone() {
                log::info!("stopping consensus runner...");
    
                r.stop().await;
                log::info!("consensus runner stopped");
            }

            // Add a small delay to ensure cleanup completes
            tokio::time::sleep(Duration::from_millis(500)).await;
        })
        .await
        .context("server failed")?;
    println!("🛑 Server shutdown gracefully");
    Ok(())
}