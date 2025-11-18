#![cfg(feature = "state-sync-http")]
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose as b64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use eezo_ledger::checkpoints::{AnchorSig, CheckpointAnchor};
#[cfg(feature = "checkpoints")]
use eezo_ledger::checkpoints::BridgeHeader;
use eezo_ledger::persistence::Persistence;

// only available when the state-sync core is compiled in
#[cfg(feature = "state-sync")]
use crate::state_sync as ss;
#[cfg(feature = "state-sync")]
use crate::state_sync::{handle_get_anchor, handle_get_delta, SyncError};

#[derive(Serialize)]
pub(crate) struct ErrorBody<'a> {
    error: &'a str,
    detail: String,
}

// +++ add: coarse node+bridge state view used by /state +++
#[cfg(feature = "checkpoints")]
#[derive(Serialize)]
pub struct NodeState {
    /// Whether the node appears "ready" from a bridge perspective
    /// (we've seen at least one checkpoint).
    pub ready_flag: bool,
    /// Node's latest known height (for now: last checkpoint height; we will
    /// refine this to true block height when we wire metrics in later steps).
    pub latest_height: u64,
    /// Latest checkpoint height as seen from the checkpoint JSON files.
    pub bridge_latest_checkpoint: u64,
    /// Whether the bridge emitter was enabled via EEZO_BRIDGE_OUTBOX_ENABLED=1.
    pub bridge_emitter_enabled: bool,
    /// Highest state-sync height applied by this node (0 if never).
    pub state_sync_latest_height: u64,
    /// Total successful state-sync applications (snapshot + delta).
    pub state_sync_total: u64,
    /// Total state-sync apply failures (after retries exhausted).
    pub state_sync_errors_total: u64,
}


// +++ add: small error alias + helpers + route constants + metrics helper +++
type ApiErr = (StatusCode, Json<ErrorBody<'static>>);

#[inline]
fn bad_request(msg: impl Into<String>) -> ApiErr {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: "invalid_argument",
            detail: msg.into(),
        }),
    )
}
#[inline]
fn not_found(msg: impl Into<String>) -> ApiErr {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: "not_found",
            detail: msg.into(),
        }),
    )
}
#[inline]
fn internal_err(msg: impl Into<String>) -> ApiErr {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "internal",
            detail: msg.into(),
        }),
    )
}

const ROUTE_SNAP: &str = "/state/snapshot";
const ROUTE_ANCHOR: &str = "/state/anchor";
const ROUTE_DELTA: &str = "/state/delta";
// --- bridge view (read-only) ---
#[cfg(feature = "checkpoints")]
const ROUTE_BRIDGE_LATEST: &str = "/bridge/header/latest";
#[cfg(feature = "checkpoints")]
const ROUTE_BRIDGE_BY_HEIGHT: &str = "/bridge/header/{height}";

// +++ add: high-level node state route +++
#[cfg(feature = "checkpoints")]
const ROUTE_STATE: &str = "/state";

#[inline]
fn http_ok(route: &str) {
    #[cfg(feature = "metrics")]
    crate::metrics::http_inc(route, StatusCode::OK.as_u16());
    let _ = route; // Keep variable used even if metrics are off
}
#[inline]
fn http_4xx(route: &str, code: StatusCode) {
    #[cfg(feature = "metrics")]
    crate::metrics::http_inc(route, code.as_u16());
    let _ = (route, code); // Keep variables used
}
#[inline]
fn http_5xx(route: &str) {
    #[cfg(feature = "metrics")]
    crate::metrics::http_inc(route, StatusCode::INTERNAL_SERVER_ERROR.as_u16());
    let _ = route; // Keep variable used
}
// --- end add ---

// === Re-export v2 SSZ endpoints implemented in `state_sync.rs` ===
// These are used by the router in `main.rs` to serve Phase-2 APIs.
// Snapshot manifest (v2, JSON) and SSZ blob:
#[cfg(all(
    feature = "state-sync",
    feature = "state-sync-http",
    feature = "eth-ssz"
))]
pub use crate::state_sync::get_snapshot_manifest_v2;
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
pub use crate::state_sync::get_snapshot_blob;
// Delta manifest (v2, SSZ):
#[cfg(all(
    feature = "state-sync",
    feature = "state-sync-http",
    feature = "eth-ssz"
))]
pub use crate::state_sync::get_delta_manifest_v2;

// ---------- Snapshot (base64-only) ----------

#[derive(Deserialize)]
pub struct SnapQuery {
    /// Base64-encoded binary prefix (opaque). If absent, full keyspace is scanned.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Base64-encoded opaque cursor returned by the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Max items per page (clamped).
    #[serde(default = "default_limit")]
    pub limit: usize,
}
fn default_limit() -> usize {
    1000
}

#[derive(Serialize)]
pub struct SnapshotItem {
    /// Base64-encoded key (opaque).
    pub key_b64: String,
    /// Base66-encoded value (opaque).
    pub val_b64: String,
}

#[derive(Serialize)]
pub struct SnapshotPage {
    pub items: Vec<SnapshotItem>,
    /// Base64-encoded cursor to resume; omitted if no more data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// GET /state/snapshot?prefix=<b64>&cursor=<b64>&limit=<u32>
/// Strict base64-only interface for mainnet.
#[cfg(feature = "state-sync")]
pub async fn get_snapshot(
    State(state): State<crate::AppState>,
    Query(q): Query<SnapQuery>,
) -> Result<Json<SnapshotPage>, ApiErr> {
    let db: &Persistence = state.db.as_ref();

    // Validate inputs
    crate::state_sync::validate_prefix_b64(&q.prefix).map_err(|e| {
        #[cfg(feature = "metrics")]
        crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
        http_4xx(ROUTE_SNAP, StatusCode::BAD_REQUEST);
        bad_request(e.to_string())
    })?;
    let limit = crate::state_sync::validate_limit(q.limit).map_err(|e| {
        #[cfg(feature = "metrics")]
        crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
        http_4xx(ROUTE_SNAP, StatusCode::BAD_REQUEST);
        bad_request(e.to_string())
    })?;

    // Strict base64 decode for prefix (if provided)
    let prefix_buf;
    let prefix_bytes = match q.prefix {
        Some(ref p) => match b64::STANDARD.decode(p.as_bytes()) {
            Ok(bytes) => {
                prefix_buf = bytes;
                Some(prefix_buf.as_slice())
            }
            Err(e) => {
                #[cfg(feature = "metrics")]
                crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
                http_4xx(ROUTE_SNAP, StatusCode::BAD_REQUEST);
                return Err(bad_request(format!("invalid prefix (base64): {e}")));
            }
        },
        None => None,
    };

    // Use validated/capped limit
    let page = ss::page_snapshot(db, prefix_bytes, q.cursor.as_deref(), limit).map_err(|e| {
        #[cfg(feature = "metrics")]
        crate::metrics::STATE_SYNC_HTTP_ERR_5XX.inc();
        http_5xx(ROUTE_SNAP);
        internal_err(e.to_string())
    })?;

    // Convert to outward-facing owned strings
    let items: Vec<SnapshotItem> = page
        .items
        .into_iter()
        .map(|it| SnapshotItem {
            key_b64: it.key_b64,
            val_b64: it.val_b64,
        })
        .collect();

    #[cfg(feature = "metrics")]
    {
        #[cfg(feature = "state-sync")]
        use crate::metrics::{STATE_SYNC_CHUNKS_TOTAL, STATE_SYNC_SNAPSHOT_BYTES_TOTAL};
        let bytes: usize = items
            .iter()
            .map(|item| item.key_b64.len() * 3 / 4 + item.val_b64.len() * 3 / 4)
            .sum();
        #[cfg(feature = "state-sync")]
        {
            STATE_SYNC_SNAPSHOT_BYTES_TOTAL.inc_by(bytes as u64);
            STATE_SYNC_CHUNKS_TOTAL
                .with_label_values(&["snapshot"])
                .inc();
        }
    }

    http_ok(ROUTE_SNAP);
    Ok(Json(SnapshotPage {
        items,
        cursor: page.cursor,
    }))
}

// ---------- Anchor ----------

/// GET /state/anchor
#[cfg(feature = "state-sync")]
pub async fn get_anchor(
    State(state): State<crate::AppState>,
) -> Result<Json<CheckpointAnchor>, ApiErr> {
    let db: &Persistence = state.db.as_ref();

    match handle_get_anchor(db) {
        Ok(mut anchor) => {
            // --- T29.9 test hook ---
            #[cfg(any(test, debug_assertions))]
            {
                if std::env::var("EEZO_SYNC_TEST_BAD_SIG").as_deref() == Ok("1") {
                    let pk = vec![0xAA; 16];
                    let sg = vec![0xBB; 32];
                    anchor.sig = Some(AnchorSig {
                        scheme: "ML-DSA-44".to_string(),
                        pk_b64: b64::STANDARD.encode(&pk),
                        sig_b64: b64::STANDARD.encode(&sg),
                    });
                }
            }
            http_ok(ROUTE_ANCHOR);
            Ok(Json(anchor))
        }
        Err(SyncError::NotFound) => {
            #[cfg(feature = "metrics")]
            #[cfg(feature = "state-sync")]
            crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
            http_4xx(ROUTE_ANCHOR, StatusCode::NOT_FOUND);
            Err(not_found("anchor not found"))
        }
        Err(e) => {
            #[cfg(feature = "metrics")]
            #[cfg(feature = "state-sync")]
            crate::metrics::STATE_SYNC_HTTP_ERR_5XX.inc();
            http_5xx(ROUTE_ANCHOR);
            Err(internal_err(e.to_string()))
        }
    }
}

// ---------- Delta (shape may evolve with proofs) ----------

#[derive(Deserialize)]
pub struct DeltaQ {
    pub from: u64,
    pub to: u64,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[cfg(feature = "state-sync")]
pub async fn get_delta(
    State(state): State<crate::AppState>,
    Query(q): Query<DeltaQ>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    let db: &Persistence = state.db.as_ref();
    let limit = crate::state_sync::validate_limit(q.limit).map_err(|e| {
        #[cfg(feature = "metrics")]
        #[cfg(feature = "state-sync")]
        crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
        http_4xx(ROUTE_DELTA, StatusCode::BAD_REQUEST);
        bad_request(e.to_string())
    })?;
    let (from, to) = crate::state_sync::validate_range(q.from, q.to).map_err(|e| {
        #[cfg(feature = "metrics")]
        #[cfg(feature = "state-sync")]
        crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
        http_4xx(ROUTE_DELTA, StatusCode::BAD_REQUEST);
        bad_request(e.to_string())
    })?;

    match handle_get_delta(db, from, to, limit) {
        Ok(batch) => {
            #[cfg(feature = "metrics")]
            {
                #[cfg(feature = "state-sync")]
                use crate::metrics::{STATE_SYNC_CHUNKS_TOTAL, STATE_SYNC_DELTA_BYTES_TOTAL};

                // Estimate delta bytes (entries count * approximate size per entry)
                let bytes_estimate = batch.entries.len() * 100; // Approximate 100 bytes per delta entry
                #[cfg(feature = "state-sync")]
                {
                    STATE_SYNC_DELTA_BYTES_TOTAL.inc_by(bytes_estimate as u64);
                    STATE_SYNC_CHUNKS_TOTAL.with_label_values(&["delta"]).inc();
                }
            }

            http_ok(ROUTE_DELTA);
            Ok(Json(serde_json::json!({
                "from_height": batch.from_height,
                "to_height": batch.to_height,
                "entries": batch.entries,
            })))
        }
        Err(SyncError::InvalidArg(msg)) => {
            #[cfg(feature = "metrics")]
            #[cfg(feature = "state-sync")]
            crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
            http_4xx(ROUTE_DELTA, StatusCode::BAD_REQUEST);
            Err(bad_request(msg.to_string()))
        }
        Err(SyncError::NotFound) => {
            #[cfg(feature = "metrics")]
            #[cfg(feature = "state-sync")]
            crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
            http_4xx(ROUTE_DELTA, StatusCode::NOT_FOUND);
            Err(not_found("delta not found"))
        }
        Err(e) => {
            #[cfg(feature = "metrics")]
            #[cfg(feature = "state-sync")]
            crate::metrics::STATE_SYNC_HTTP_ERR_5XX.inc();
            http_5xx(ROUTE_DELTA);
            Err(internal_err(e.to_string()))
        }
    }
}

// ---------- High-level /state view (node + bridge) ----------

#[cfg(feature = "checkpoints")]
pub async fn get_node_state(
    State(state): State<crate::AppState>,
) -> Result<Json<NodeState>, ApiErr> {
    use std::cmp::Ordering;

    // use datadir-based checkpoints dir
    let dir = checkpoints_dir(&state);
    let files = match list_checkpoint_files(&dir) {
        Ok(v) => v,
        Err(msg) => {
            // No checkpoint files yet -> treat as "not ready" but still return 200.
            log::debug!("state: no checkpoint files yet: {}", msg);
            let emitter_enabled =
                std::env::var("EEZO_BRIDGE_OUTBOX_ENABLED").as_deref() == Ok("1");

            // Derive simple state-sync status from global metrics.
            // If metrics are disabled, we just return zeros.
            #[cfg(feature = "metrics")]
            let (ss_latest, ss_total, ss_errors) = {
                use crate::metrics::{
                    EEZO_STATE_SYNC_LATEST_HEIGHT,
                    EEZO_STATE_SYNC_TOTAL,
                    EEZO_STATE_SYNC_ERRORS_TOTAL,
                };
                (
                    EEZO_STATE_SYNC_LATEST_HEIGHT.get() as u64,
                    EEZO_STATE_SYNC_TOTAL.get(),
                    EEZO_STATE_SYNC_ERRORS_TOTAL.get(),
                )
            };
            #[cfg(not(feature = "metrics"))]
            let (ss_latest, ss_total, ss_errors) = (0u64, 0u64, 0u64);

            http_ok(ROUTE_STATE);
            return Ok(Json(NodeState {
                ready_flag: false,
                latest_height: 0,
                bridge_latest_checkpoint: 0,
                bridge_emitter_enabled: emitter_enabled,
                state_sync_latest_height: ss_latest,
                state_sync_total: ss_total,
                state_sync_errors_total: ss_errors,
            }));
        }
    };

    // Choose the header with the greatest (height, timestamp),
    // same rule as get_bridge_header_latest.
    let mut best_height: u64 = 0;
    let mut best_ts: u64 = 0;

    for p in files {
        match read_bridge_header(&p) {
            Ok(h) => {
                match h.height.cmp(&best_height) {
                    Ordering::Greater => {
                        best_height = h.height;
                        best_ts = h.timestamp;
                    }
                    Ordering::Equal if h.timestamp > best_ts => {
                        best_height = h.height;
                        best_ts = h.timestamp;
                    }
                    Ordering::Less | Ordering::Equal => {}
                }
            }
            Err(e) => {
                log::debug!("state: skip bad checkpoint {:?}: {}", p, e);
            }
        }
    }

        let emitter_enabled =
        std::env::var("EEZO_BRIDGE_OUTBOX_ENABLED").as_deref() == Ok("1");
    let ready = best_height > 0;

    // Derive simple state-sync status from global metrics.
    // If metrics are disabled, we just return zeros.
    #[cfg(feature = "metrics")]
    let (ss_latest, ss_total, ss_errors) = {
        use crate::metrics::{
            EEZO_STATE_SYNC_LATEST_HEIGHT,
            EEZO_STATE_SYNC_TOTAL,
            EEZO_STATE_SYNC_ERRORS_TOTAL,
        };
        (
            EEZO_STATE_SYNC_LATEST_HEIGHT.get() as u64,
            EEZO_STATE_SYNC_TOTAL.get(),
            EEZO_STATE_SYNC_ERRORS_TOTAL.get(),
        )
    };
    #[cfg(not(feature = "metrics"))]
    let (ss_latest, ss_total, ss_errors) = (0u64, 0u64, 0u64);

    http_ok(ROUTE_STATE);
    Ok(Json(NodeState {
        ready_flag: ready,
        // For now we set latest_height == bridge_latest_checkpoint; later we can
        // wire true block height via node metrics.
        latest_height: best_height,
        bridge_latest_checkpoint: best_height,
        bridge_emitter_enabled: emitter_enabled,
        state_sync_latest_height: ss_latest,
        state_sync_total: ss_total,
        state_sync_errors_total: ss_errors,
    }))
}

// ---------- Bridge: read-only checkpoint headers ----------
// Exposes the newest (by height) checkpoint header, and a specific height.
// Files are read from the standard "proof/checkpoints" directory. If multiple
// files exist for the same height (algorithm rotation), the one with the
// greatest timestamp is returned.

#[cfg(feature = "checkpoints")]
fn checkpoints_dir(state: &crate::AppState) -> std::path::PathBuf {
    // mirror the outbox dir used by the bridge emitter:
    // <datadir>/proof/checkpoints
    let base = std::path::PathBuf::from(&state.runtime_config.node.datadir);
    base.join("proof").join("checkpoints")
}

#[cfg(feature = "checkpoints")]
fn read_bridge_header(path: &std::path::Path) -> Result<BridgeHeader, String> {
    use std::fs;
    let data = fs::read(path).map_err(|e| format!("read {:?}: {e}", path))?;
    serde_json::from_slice::<BridgeHeader>(&data)
        .map_err(|e| format!("parse {:?}: {e}", path))
}

#[cfg(feature = "checkpoints")]
fn list_checkpoint_files(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>, String> {
    use std::fs;
    let mut out = Vec::new();
    let rd = fs::read_dir(dir).map_err(|e| format!("open {:?}: {e}", dir))?;
    for ent in rd {
        let ent = ent.map_err(|e| format!("iter dir {:?}: {e}", dir))?;
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(p);
        }
    }
    if out.is_empty() {
        return Err("no checkpoint files found".to_string());
    }
    Ok(out)
}

/// GET /bridge/header/latest
#[cfg(feature = "checkpoints")]
pub async fn get_bridge_header_latest(
    State(state): State<crate::AppState>,
) -> Result<Json<BridgeHeader>, ApiErr> {
    use std::cmp::Ordering;

    let dir = checkpoints_dir(&state);
    let files = match list_checkpoint_files(&dir) {
        Ok(v) => v,
        Err(msg) => {
            #[cfg(feature = "metrics")]
            #[cfg(feature = "state-sync")]
            crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
            http_4xx(ROUTE_BRIDGE_LATEST, StatusCode::NOT_FOUND);
            return Err(not_found(msg));
        }
    };

    // choose the header with the greatest (height, timestamp)
    let mut best: Option<BridgeHeader> = None;
    for p in files {
        match read_bridge_header(&p) {
            Ok(h) => {
                let better = match &best {
                    None => true,
                    Some(b) => match h.height.cmp(&b.height) {
                        Ordering::Greater => true,
                        Ordering::Equal => h.timestamp > b.timestamp,
                        Ordering::Less => false,
                    },
                };
                if better {
                    best = Some(h);
                }
            }
            Err(e) => {
                // ignore bad files but log; do not fail the entire call
                log::debug!("bridge/latest: skip {:?}: {}", p, e);
            }
        }
    }

    if let Some(hdr) = best {
        http_ok(ROUTE_BRIDGE_LATEST);
        Ok(Json(hdr))
    } else {
        #[cfg(feature ="metrics")]
        #[cfg(feature = "state-sync")]
        crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
        http_4xx(ROUTE_BRIDGE_LATEST, StatusCode::NOT_FOUND);
        Err(not_found("no valid checkpoint headers found"))
    }
}

/// GET /bridge/header/{height}
#[cfg(feature = "checkpoints")]
pub async fn get_bridge_header_by_height(
    Path(height): Path<u64>,
    State(state): State<crate::AppState>,
) -> Result<Json<BridgeHeader>, ApiErr> {
    let dir = checkpoints_dir(&state);
    let files = match list_checkpoint_files(&dir) {
        Ok(v) => v,
        Err(msg) => {
            #[cfg(feature = "metrics")]
            #[cfg(feature = "state-sync")]
            crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
            http_4xx(ROUTE_BRIDGE_BY_HEIGHT, StatusCode::NOT_FOUND);
            return Err(not_found(msg));
        }
    };

    // from all files, pick those whose parsed header has the requested height,
    // then choose the one with the largest timestamp (rotation-friendly).
    let mut cand: Option<BridgeHeader> = None;
    for p in files {
        match read_bridge_header(&p) {
            Ok(h) if h.height == height => {
                if cand.as_ref().is_none_or(|c| h.timestamp > c.timestamp) {
                    cand = Some(h);
                }
            }
            Ok(_) => {}
            Err(e) => log::debug!("bridge/{height}: skip {:?}: {}", p, e),
        }
    }

    if let Some(hdr) = cand {
        http_ok(ROUTE_BRIDGE_BY_HEIGHT);
        Ok(Json(hdr))
    } else {
        #[cfg(feature = "metrics")]
        #[cfg(feature = "state-sync")]
        crate::metrics::STATE_SYNC_HTTP_ERR_4XX.inc();
        http_4xx(ROUTE_BRIDGE_BY_HEIGHT, StatusCode::NOT_FOUND);
        Err(not_found(format!("no checkpoint for height {}", height)))
    }
}


// ---------- Dev-only write endpoint ----------

#[cfg(any(debug_assertions, feature = "dev-tools"))]
pub async fn dev_put(
    State(state): State<crate::AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl axum::response::IntoResponse {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let Some(kb64) = q.get("key") else {
        return (axum::http::StatusCode::BAD_REQUEST, "missing key").into_response();
    };
    let Some(vb64) = q.get("val") else {
        return (axum::http::StatusCode::BAD_REQUEST, "missing val").into_response();
    };

    let key = match STANDARD.decode(kb64) {
        Ok(k) => k,
        Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "bad key b64").into_response(),
    };
    let val = match STANDARD.decode(vb64) {
        Ok(v) => v,
        Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "bad val b64").into_response(),
    };

    // IMPORTANT: this must write to the SAME DB your snapshot iterator reads!
    let db: &Persistence = state.db.as_ref();
    if let Err(e) = db.dev_put_raw(&key, &val) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {e}"),
        )
            .into_response();
    }
    (axum::http::StatusCode::OK, "ok").into_response()
}