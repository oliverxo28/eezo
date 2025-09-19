use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};
use axum::{extract::State, Json};
use tokio::sync::{RwLock, Notify};
use serde::{Serialize, Deserialize};
use reqwest::Client;

// --- T24.9: Per-peer SLO metrics imports ---
use crate::metrics::{
    EEZO_NODE_PEERS_TOTAL,
    EEZO_NODE_PEERS_READY,
    EEZO_NODE_CLUSTER_QUORUM_OK,
    EEZO_NODE_QUORUM_DEGRADE_TOTAL,
    EEZO_NODE_PEER_PING_MS,
    EEZO_NODE_PEER_PING_FAIL_TOTAL,
};

#[inline]
fn peer_label(url: &str) -> String {
    // Requires seahash in Cargo.toml
    format!("{:x}", seahash::hash(url.as_bytes()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub url: String,
    pub ready: bool,
    pub last_ok_ms: Option<u128>,
    pub last_check_ms: Option<u128>,
}

pub type PeerMap = Arc<RwLock<HashMap<String, PeerStatus>>>;

/// PeerService supporting dynamic, hot-reloadable peers and immediate refresh.
#[derive(Clone)]
pub struct PeerService {
    peers_cfg: Arc<RwLock<Vec<String>>>,
    map: PeerMap,
    client: Client,
    current_quorum_ok: Arc<tokio::sync::Mutex<bool>>,
    below_since: Arc<tokio::sync::Mutex<Option<Instant>>>,
    loss_window: Duration,
    on_quorum_change: Arc<dyn Fn(bool) + Send + Sync>,
    notify: Arc<Notify>,
}

impl PeerService {
    /// New constructor for quorum-aware readiness
    pub fn new_with_hook<F>(peers_cfg: Vec<String>, on_quorum_change: F) -> anyhow::Result<Self>
    where
        F: Fn(bool) + Send + Sync + 'static,
    {
        let client = Client::builder()
            .timeout(Duration::from_millis(800))
            .build()?;

        let loss_ms: u64 = std::env::var("EEZO_QUORUM_LOSS_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2000);

        Ok(Self {
            peers_cfg: Arc::new(RwLock::new(peers_cfg)),
            map: Arc::new(RwLock::new(HashMap::new())),
            client,
            current_quorum_ok: Arc::new(tokio::sync::Mutex::new(true)),
            below_since: Arc::new(tokio::sync::Mutex::new(None)),
            loss_window: Duration::from_millis(loss_ms),
            on_quorum_change: Arc::new(on_quorum_change),
            notify: Arc::new(Notify::new()),
        })
    }

    #[allow(dead_code)]
    pub fn new(peers_cfg: Vec<String>) -> anyhow::Result<Self> {
        Self::new_with_hook(peers_cfg, |_| {})
    }

    pub fn state(&self) -> PeerMap {
        self.map.clone()
    }

    /// Hot-reload setter for peer config.
    pub async fn set_peers(&self, new_peers: Vec<String>) {
        {
            let mut w = self.peers_cfg.write().await;
            *w = new_peers;
        }
        // Clear peer map so metrics reflect new set quickly
        let mut g = self.map.write().await;
        g.clear();
        // Wake the loop now (don’t wait for the next tick)
        self.notify.notify_one();
    }

    /// Optional helper if you want to force an immediate cycle from handlers/tests
	#[allow(dead_code)]
    pub async fn refresh_now(&self) {
        self.notify.notify_one();
    }

    pub async fn spawn(self) {
        let svc = self.clone();
        tokio::spawn(async move {
            loop {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis();

                // Read current peers every loop (so reload works)
                let peers = { svc.peers_cfg.read().await.clone() };

                // Always set this from the config peer list
                EEZO_NODE_PEERS_TOTAL.set(peers.len() as i64);

                let mut guard = svc.map.write().await;
                // Rebuild the peer map for all peers, so all are present (even if unreachable)
                for url in peers.iter() {
                    let ready_url = format!("{}/ready", url);
                    let mut status = PeerStatus {
                        url: url.clone(),
                        ready: false,
                        last_ok_ms: None,
                        last_check_ms: Some(now),
                    };

                    let label = peer_label(url);
                    let start = Instant::now();
                    let ok = match svc.client.get(&ready_url).send().await {
                        Ok(resp) => resp.status().as_u16() == 200,
                        Err(_) => false,
                    };
                    let dur_ms = start.elapsed().as_secs_f64() * 1e3;
                    EEZO_NODE_PEER_PING_MS
                        .with_label_values(&[&label])
                        .observe(dur_ms);

                    if !ok {
                        EEZO_NODE_PEER_PING_FAIL_TOTAL
                            .with_label_values(&[&label])
                            .inc();
                    }

                    status.ready = ok;
                    if ok { status.last_ok_ms = Some(now); }

                    guard.insert(url.clone(), status);
                }
                // Remove any peers from map that are no longer in config (after reload)
                guard.retain(|k, _| peers.contains(k));

                // Update ready peers count
                EEZO_NODE_PEERS_READY.set(guard.values().filter(|p| p.ready).count() as i64);

                // --- QUORUM LOGIC, now includes self in math ---
                let total = guard.len(); // peers only
                let ready = guard.values().filter(|p| p.ready).count();
                drop(guard); // release write lock before await

                let self_ready = true; // or use your actual readiness flag if available
                let total_with_self = total + 1;
                let ready_with_self = ready + if self_ready { 1 } else { 0 };
                let quorum_ok_now = ready_with_self * 3 >= total_with_self * 2;

                EEZO_NODE_CLUSTER_QUORUM_OK.set(if quorum_ok_now { 1 } else { 0 });

                let mut curr = svc.current_quorum_ok.lock().await;
                let mut since = svc.below_since.lock().await;

                if quorum_ok_now {
                    *since = None;
                    if !*curr {
                        // recovered quorum → flip to ready
                        (svc.on_quorum_change)(true);
                        *curr = true;
                    }
                } else {
                    // below quorum
                    let now_i = Instant::now();
                    if since.is_none() {
                        *since = Some(now_i);
                    } else if now_i.duration_since(since.unwrap()) >= svc.loss_window && *curr {
                        EEZO_NODE_QUORUM_DEGRADE_TOTAL.inc();
                        (svc.on_quorum_change)(false);
                        *curr = false;
                    }
                }

                // Wait for either the normal tick OR a reload
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(1000)) => {},
                    _ = svc.notify.notified() => {},
                }
            }
        });
    }
}

/// Parse comma-separated peers from EEZO_PEERS.
pub fn parse_peers_from_env() -> Vec<String> {
    match std::env::var("EEZO_PEERS") {
        Ok(s) if !s.trim().is_empty() => s
            .split(',')
            .map(|p| p.trim().trim_end_matches('/').to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

pub async fn peers_handler(State(state): State<crate::AppState>) -> Json<Vec<PeerStatus>> {
    let guard = state.peers.read().await;
    Json(guard.values().cloned().collect())
}