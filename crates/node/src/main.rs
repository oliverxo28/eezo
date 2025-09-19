use axum::{
    routing::{get, post},
    Router, Json, extract::State, extract::Query,
};
use axum::http::StatusCode;
use std::net::SocketAddr;
use std::env;
use hex;
use serde::Serialize;
use clap::Parser;
use anyhow::Context;
use eezo_ledger::{GenesisConfig, ensure_genesis};
use eezo_ledger::persistence::Persistence;
use std::io::{self, Write};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::collections::HashMap;
use std::time::{SystemTime, Duration};

// --- Peer management modules ---
mod metrics;
mod peers;
use peers::{PeerService, parse_peers_from_env, peers_handler, PeerMap};

use axum::extract::rejection::JsonRejection;

// --- Handler: /config ---
// Rehydrate peers from running set at request time for current/accurate config
async fn config_handler(State(state): State<AppState>) -> Json<RuntimeConfigView> {
    let mut rc = state.runtime_config.clone();
    // Get current peers from PeerMap (runtime)
    let mut peers: Vec<String> = state.peers.read().await.keys().cloned().collect();
    peers.sort();
    peers.dedup();
    rc.peers = peers;
    Json(rc)
}

async fn health_handler() -> &'static str { "ok" }

async fn ready_handler(State(state): State<AppState>) -> (StatusCode, &'static str) {
    let ready_status = state.ready_flag.load(Ordering::SeqCst);
    log::info!("Received /ready ping, responding with {:?}", ready_status);
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
        if q.get("token").map(String::as_str) == Some(expected.as_str()) {
            state.ready_flag.store(false, Ordering::SeqCst);
            #[cfg(feature = "metrics")]
            {
                NODE_READY.set(0);
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
        if q.get("token").map(String::as_str) == Some(expected.as_str()) {
            state.ready_flag.store(true, Ordering::SeqCst);
            #[cfg(feature = "metrics")]
            {
                NODE_READY.set(1);
                NODE_READY_RESTORE_TOTAL.inc();
            }
            return (StatusCode::OK, "ready=true");
        }
        return (StatusCode::FORBIDDEN, "forbidden");
    }
    (StatusCode::NOT_FOUND, "disabled")
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
    let uptime = now.duration_since(state.started_at).unwrap_or(Duration::ZERO).as_secs();

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

// --- Extended metrics imports for T24.1 ---
#[cfg(feature = "metrics")]
use prometheus::{
    Encoder, TextEncoder, IntCounter, IntGauge, GaugeVec,
    register_int_counter, register_int_gauge, register_gauge_vec,
};

#[cfg(feature = "metrics")]
static NODE_STARTS: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_node_starts_total", "Node starts").expect("metric")
});

#[cfg(feature = "metrics")]
static NODE_READY: once_cell::sync::Lazy<IntGauge> = once_cell::sync::Lazy::new(|| {
    register_int_gauge!("eezo_node_ready", "1 when node is ready, 0 when degraded").expect("metric")
});

#[cfg(feature = "metrics")]
static NODE_READY_DEGRADE_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_node_ready_degrade_total", "Times readiness was degraded").expect("metric")
});

#[cfg(feature = "metrics")]
static NODE_READY_RESTORE_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_node_ready_restore_total", "Times readiness was restored").expect("metric")
});

// --- T24.1 node info metric ---
#[cfg(feature = "metrics")]
static NODE_INFO: once_cell::sync::Lazy<GaugeVec> = once_cell::sync::Lazy::new(|| {
    register_gauge_vec!(
        "eezo_node_info",
        "Static node identity and build info (value is always 1)",
        &["node_id", "version", "git_sha"]
    ).expect("metric")
});

#[cfg(feature = "metrics")]
static NODE_BG_ERROR_TOTAL: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_node_bg_error_total", "Times background error flipped readiness").expect("metric")
});

#[cfg(feature = "metrics")]
async fn metrics_handler() -> (axum::http::StatusCode, String) {
    let mf = prometheus::gather();
    let mut buf = Vec::new();
    TextEncoder::new().encode(&mf, &mut buf).unwrap();
    (axum::http::StatusCode::OK, String::from_utf8(buf).unwrap())
}

// --- T24.8: Quorum-aware readiness setter ---
#[cfg(feature = "metrics")]
use crate::metrics::EEZO_NODE_READY;

use once_cell::sync::Lazy;
static READY: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(true));

pub fn set_ready(v: bool) {
    READY.store(v, Ordering::SeqCst);
    #[cfg(feature = "metrics")]
    {
        EEZO_NODE_READY.set(if v { 1 } else { 0 });
    }
}

fn parse_chain_id_strict(s: &str) -> anyhow::Result<[u8; 20]> {
    let s = s.trim();
    if s.len() != 40 {
        anyhow::bail!("EEZO_CHAIN_ID must be exactly 40 hex chars (20 bytes), got length {}", s.len());
    }
    let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("EEZO_CHAIN_ID is not valid hex: {}", e))?;
    if bytes.len() != 20 {
        anyhow::bail!("EEZO_CHAIN_ID must decode to 20 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn env_bool(var: &str, default_on: bool) -> bool {
    match env::var(var).ok() {
        Some(raw) => {
            let s = raw.trim().to_ascii_lowercase();
            match s.as_str() {
                "on" | "1" | "true" | "yes"  => true,
                "off" | "0" | "false" | "no" => false,
                _ => default_on,
            }
        }
        None => default_on,
    }
}

fn env_usize(var: &str, default_v: usize) -> usize {
    env::var(var).ok().and_then(|s| s.parse().ok()).unwrap_or(default_v)
}

fn env_u16(var: &str, default_v: u16) -> u16 {
    env::var(var).ok().and_then(|s| s.parse().ok()).unwrap_or(default_v)
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
    peers: Vec<String>, // T24.12: expose peers in /config
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

fn default_listen() -> String { "127.0.0.1:8080".into() }
fn default_datadir() -> String { "data".into() }
fn default_log_level() -> String { "info".into() }

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
}

fn dedup_preserve_order(mut v: Vec<String>) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    v.retain(|s| seen.insert(s.clone()));
    v
}

fn load_nodecfg_peers_or_empty(path: &Option<String>) -> anyhow::Result<Vec<String>> {
    if let Some(p) = path {
        if p.trim().is_empty() { return Ok(Vec::new()); }
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
    let peers_from_body = maybe_json.ok().map(|Json(ReloadPeers(v))| v).unwrap_or_default();

    // Normalize peer URLs if provided
    let new_peers = if peers_from_body.is_empty() {
        match load_nodecfg_peers_or_empty(&state.config_file_path) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        }
    } else {
        peers_from_body
            .into_iter()
            .map(|p| p.trim().trim_end_matches('/').to_string())
            .collect()
    };

    state.peer_svc.set_peers(dedup_preserve_order(new_peers)).await;
    (StatusCode::OK, "ok")
}

// T24.12: Add GET /reload to reload from file
async fn reload_from_file_handler(State(state): State<AppState>) -> (StatusCode, &'static str) {
    let v = match load_nodecfg_peers_or_empty(&state.config_file_path) {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };
    state.peer_svc.set_peers(dedup_preserve_order(v)).await;
    (StatusCode::OK, "ok")
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
        let txt = std::fs::read_to_string(&path)
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

    if let Some(g) = args.genesis {
        cfg.genesis = Some(g);
    }
    if let Some(d) = args.datadir {
        cfg.datadir = d;
    }
    if let Some(l) = args.listen {
        cfg.listen = l;
    }
    if let Some(ll) = args.log_level {
        cfg.log_level = ll;
    }

    let mut env_peers = parse_peers_from_env();
    if !env_peers.is_empty() {
        cfg.peers.extend(env_peers.drain(..));
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
                println!("❌ Bail: datadir already in use by pid {}: {}", pid, cfg.datadir);
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

    println!("✅ Lock file written");
    println!("✅ Node startup reached main loop");

    let _lock_guard = LockFileGuard { path: lock_path.clone() };

    let node_id_path = std::path::Path::new(&cfg.datadir).join("NODE_ID");
    let legacy_json_identity_path = std::path::Path::new(&cfg.datadir).join("IDENTITY");

    println!("🔍 Loading node identity from: {:?}", node_id_path);
    let identity: NodeIdentity = match std::fs::read_to_string(&node_id_path) {
        Ok(txt) => {
            println!("🔍 Found existing NODE_ID file");
            serde_json::from_str(&txt).context("invalid NODE_ID json")?
        }
        Err(_) => {
            println!("🔍 No NODE_ID file, checking for legacy IDENTITY");
            let maybe_legacy = std::fs::read_to_string(&legacy_json_identity_path).ok();
            if let Some(txt) = maybe_legacy {
                println!("🔍 Found legacy IDENTITY file");
                if txt.trim_start().starts_with('{') {
                    if let Ok(ident) = serde_json::from_str::<NodeIdentity>(&txt) {
                        println!("🔍 Migrating legacy identity to NODE_ID");
                        std::fs::write(&node_id_path, serde_json::to_string_pretty(&ident)?)
                            .context("failed to write migrated NODE_ID")?;
                        println!("Migrated legacy JSON IDENTITY to NODE_ID");
                        ident
                    } else {
                        println!("🔍 Legacy identity invalid, creating new identity");
                        let node_id = uuid::Uuid::new_v4().to_string();
                        let first_seen = std::time::SystemTime::now()
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .unwrap_or(std::time::Duration::ZERO)
                            .as_secs();
                        let ident = NodeIdentity { node_id, first_seen };
                        std::fs::write(&node_id_path, serde_json::to_string_pretty(&ident)?)
                            .context("failed to write NODE_ID")?;
                        ident
                    }
                } else {
                    println!("🔍 Legacy identity not JSON, creating new identity");
                    let node_id = uuid::Uuid::new_v4().to_string();
                    let first_seen = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or(std::time::Duration::ZERO)
                        .as_secs();
                    let ident = NodeIdentity { node_id, first_seen };
                    std::fs::write(&node_id_path, serde_json::to_string_pretty(&ident)?)
                        .context("failed to write NODE_ID")?;
                    ident
                }
            } else {
                println!("🔍 No legacy identity found, creating new identity");
                let node_id = uuid::Uuid::new_v4().to_string();
                let first_seen = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_secs();
                let ident = NodeIdentity { node_id, first_seen };
                std::fs::write(&node_id_path, serde_json::to_string_pretty(&ident)?)
                    .context("failed to write NODE_ID")?;
                ident
            }
        }
    };

    println!("✅ Node identity loaded: {}", identity.node_id);

    env::set_var("RUST_LOG", &cfg.log_level);
    env_logger::init();

    println!("🔍 Opening persistence store at: {}", cfg.datadir);
    let store = Persistence::open_default(std::path::Path::new(&cfg.datadir))
        .context("failed to open data directory")?;

    let chain_id = match env::var("EEZO_CHAIN_ID") {
        Ok(val) => {
            let parsed = parse_chain_id_strict(&val)?;
            parsed
        }
        Err(_) => [9u8; 20],
    };
    println!("🔍 Chain ID: {}", hex::encode(chain_id));

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
            let v: usize = vs.parse().map_err(|e| {
                anyhow::anyhow!("EEZO_MAX_BLOCK_BYTES must be an integer: {}", e)
            })?;
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
                "⚠️  Warning: genesis chain_id ({:?}) does not match runtime EEZO_CHAIN_ID ({:?}); continuing startup",
                genesis_cfg.chain_id,
                chain_id
            );
        } else {
            println!("✅ Genesis chain_id matches runtime");
        }

        println!("🔍 Applying genesis...");
        ensure_genesis(&store, &genesis_cfg).context("genesis application failed")?;
        println!("✅ Genesis applied");
    } else {
        println!("🔍 No genesis file specified, skipping genesis application");
    }

    println!("✅ Preparing runtime config");

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
        peers: cfg.peers.clone(), // T24.12: expose peers in /config
    };

    println!("✅ Runtime config built: node_id={}, listen={}", runtime_config.node_id, runtime_config.node.listen);

    #[cfg(feature = "metrics")]
    NODE_STARTS.inc();

    let ready_flag = Arc::new(AtomicBool::new(true));
    let admin_token = std::env::var("EEZO_ADMIN_TOKEN").ok();
    let started_at = SystemTime::now();
    let version: &'static str = env!("CARGO_PKG_VERSION");
    let git_sha: Option<&'static str> = option_env!("EEZO_BUILD_GIT_SHA");

    let peers_cfg = cfg.peers.clone();
    let hook = {
        let ready_flag = ready_flag.clone();
        move |q_ok: bool| {
            ready_flag.store(q_ok, Ordering::SeqCst);
            #[cfg(feature = "metrics")]
            {
                EEZO_NODE_READY.set(if q_ok { 1 } else { 0 });
            }
        }
    };
    let peer_svc = PeerService::new_with_hook(peers_cfg, hook)?;
    println!("🔍 Configured peers: {:?}", cfg.peers);

    peer_svc.clone().spawn().await;
    println!("✅ Peer service started");

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
        NODE_INFO.with_label_values(&[&state.identity.node_id, state.version, git]).set(1.0);
    }

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/config", get(config_handler))
        .route("/status", get(status_handler))
        .route("/_admin/degrade", get(admin_degrade))
        .route("/_admin/restore", get(admin_restore))
        .route("/peers", get(peers_handler))
        .route("/reload", post(reload_handler).get(reload_from_file_handler)); // T24.12: GET and POST

    #[cfg(feature = "metrics")]
    let app = app.route("/metrics", get(metrics_handler));

    println!("✅ Router built with /ready, /config, /status, /peers endpoints");

    let addr: SocketAddr = cfg.listen.parse().context("invalid listen address")?;
    println!("🔍 Binding to address: {}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind to {}", cfg.listen))?;

    println!("✅ TCP listener bound on {}", cfg.listen);

    ready_flag.store(true, Ordering::SeqCst);
    println!("Initial readiness set to true");

    if std::env::var("EEZO_SIMULATE_BG_IO_ERROR").ok().as_deref() == Some("on") {
        let ready_flag_bg = ready_flag.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            ready_flag_bg.store(false, Ordering::SeqCst);
            #[cfg(feature = "metrics")]
            {
                NODE_READY.set(0);
                NODE_BG_ERROR_TOTAL.inc();
            }
            eprintln!("simulated background error: readiness degraded");
        });
        println!("✅ Background error simulation task scheduled (will trigger in 1500ms)");
    }

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let st = state.clone();
        tokio::spawn(async move {
            let mut hup = signal(SignalKind::hangup()).expect("signal");
            while hup.recv().await.is_some() {
                if let Ok(v) = load_nodecfg_peers_or_empty(&st.config_file_path) {
                    st.peer_svc.set_peers(dedup_preserve_order(v)).await;
                }
            }
        });
    }

    println!("🎉 SERVER SUMMARY:");
    println!("   • Node ID: {}", runtime_config.node_id);
    println!("   • Listening on: {}", cfg.listen);
    println!("   • Data directory: {}", cfg.datadir);
    println!("   • Chain ID: {}", runtime_config.chain_id_hex);
    println!("   • Version: {}", version);
    println!("   • Git SHA: {:?}", git_sha);
    println!("   • Ready: true");
    println!("   • Configured peers: {}", cfg.peers.len());
    println!("🚀 Node is ready and listening on {}", cfg.listen);

    #[cfg(feature = "metrics")]
    NODE_READY.set(1);

    println!("🚀 Launching Axum server now...");

    match axum::serve(listener, app.with_state(state.clone())).await {
        Ok(_) => {
            println!("🛑 Server shutdown gracefully");
            Ok(())
        }
        Err(e) => {
            eprintln!("💥 Server failed with error: {:?}", e);
            Err(e).context("server failed")
        }
    }
}