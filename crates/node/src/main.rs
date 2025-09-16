use axum::{routing::get, Router, Json, extract::State};

use std::net::SocketAddr;
use std::env;
use hex;
use serde::Serialize;
use clap::Parser;
use anyhow::Context;
use eezo_ledger::{GenesisConfig, ensure_genesis};
use eezo_ledger::persistence::Persistence;
use std::io::{self, Write};

async fn health_handler() -> &'static str { "ok" }

async fn ready_handler() -> &'static str { "ok" }

#[cfg(feature = "metrics")]
use prometheus::{Encoder, TextEncoder, IntCounter, register_int_counter};

#[cfg(feature = "metrics")]
static NODE_STARTS: once_cell::sync::Lazy<IntCounter> = once_cell::sync::Lazy::new(|| {
    register_int_counter!("eezo_node_starts_total", "Node starts").expect("metric")
});

#[cfg(feature = "metrics")]
async fn metrics_handler() -> (axum::http::StatusCode, String) {
    let mf = prometheus::gather();
    let mut buf = Vec::new();
    TextEncoder::new().encode(&mf, &mut buf).unwrap();
    (axum::http::StatusCode::OK, String::from_utf8(buf).unwrap())
}

fn parse_chain_id(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    let bytes = hex::decode(s).unwrap_or_default();
    if bytes.len() == 20 {
        out.copy_from_slice(&bytes);
    } else {
        out = [9u8; 20];
    }
    out
}

fn env_bool(var: &str, default_on: bool) -> bool {
    match env::var(var).ok().as_deref() {
        Some("on") | Some("ON") | Some("1") | Some("true") | Some("TRUE") => true,
        Some("off") | Some("OFF") | Some("0") | Some("false") | Some("FALSE") => false,
        _ => default_on,
    }
}

fn env_usize(var: &str, default_v: usize) -> usize {
    env::var(var).ok().and_then(|s| s.parse().ok()).unwrap_or(default_v)
}

fn env_u16(var: &str, default_v: u16) -> u16 {
    env::var(var).ok().and_then(|s| s.parse().ok()).unwrap_or(default_v)
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
        }
    }
}

#[derive(Clone)]
struct AppState {
    runtime_config: RuntimeConfigView,
}

async fn config_handler(State(state): State<AppState>) -> Json<RuntimeConfigView> {
    Json(state.runtime_config)
}

#[derive(Parser, Debug)]
#[command(name = "eezo-node", about = "EEZO node")]
struct Cli {
    #[arg(long)]
    genesis: Option<String>,
    #[arg(long)]
    datadir: Option<String>,
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    log_level: Option<String>,
    #[arg(long)]
    config_file: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    // 1. Start with defaults
    let mut cfg = NodeCfg::default();

    // 2. Resolve config file path: CLI override > ENV > None
    let config_path = args.config_file.or_else(|| std::env::var("EEZO_CONFIG_FILE").ok());

    // 3. Load and overlay config file if present
    if let Some(path) = config_path {
        let txt = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file: {}", path))?;
        let from_file: NodeCfg = toml::from_str(&txt)
            .with_context(|| format!("invalid TOML in config file: {}", path))?;

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
    }

    // 4. Override with environment variables if set
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

    // 5. Override with CLI arguments if provided (highest precedence)
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

    println!("Final listen address: {}", cfg.listen);
    println!("Final log level: {}", cfg.log_level);
    io::stdout().flush().unwrap();

    // Initialize logging with final config
    env::set_var("RUST_LOG", &cfg.log_level);
    env_logger::init();

    // Open persistence
    let store = Persistence::open_default(std::path::Path::new(&cfg.datadir))
        .context("failed to open data directory")?;

    // Genesis
    if let Some(gen) = &cfg.genesis {
        let text = std::fs::read_to_string(gen).context("failed to read genesis file")?;
        let genesis_cfg: GenesisConfig = serde_json::from_str(&text).context("invalid genesis JSON")?;
        ensure_genesis(&store, &genesis_cfg).context("genesis application failed")?;
    }

    // Runtime config via env variables
    let chain_id = parse_chain_id(&env::var("EEZO_CHAIN_ID").unwrap_or_else(|_| hex::encode([9u8; 20])));
    let metrics_on = env_bool("EEZO_METRICS", false);
    let metrics_port = env_u16("EEZO_METRICS_PORT", 9090);
    let verify_cache_cap = env_usize("EEZO_VERIFY_CACHE_CAP", 10_000);
    let parallel_verify = env_bool("EEZO_PARALLEL_VERIFY", true);
    let _verify_threshold = env_usize("EEZO_VERIFY_THRESHOLD", 32);
    let raw_max = env_usize("EEZO_MAX_BLOCK_BYTES", 1_000_000);
    let max_block_bytes = raw_max.clamp(1 << 10, 64 << 20);

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
    };

    #[cfg(feature = "metrics")]
    NODE_STARTS.inc();

    let state = AppState { runtime_config: runtime_config.clone() };

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/config", get(config_handler))
        .with_state(state);

    #[cfg(feature = "metrics")]
    let app = app.route("/metrics", get(metrics_handler));

    let addr: SocketAddr = cfg.listen.parse().context("invalid listen address")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}
