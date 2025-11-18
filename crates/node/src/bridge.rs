use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
// +++ Added log import +++
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::Ordering;

use crate::addr::parse_account_addr;
use crate::AppState;

use std::fs;
use std::fs::OpenOptions;              // T36.8
use std::io::{Write, ErrorKind};       // T36.8
use std::path::{Path as FsPath, PathBuf}; // T36.8
use std::time::{SystemTime, UNIX_EPOCH};
use std::str::FromStr;                 // <— NEW: for u64::from_str on filename pieces
use std::env;                          // T37.8: drift guard (read interval)

// T36.6/T36.7 metrics
#[cfg(feature = "metrics")]
use crate::metrics::{
    bridge_index_query_inc, bridge_served_inc,
    // T36.7
    bridge_summary_query_inc, bridge_branch_query_inc, bridge_prove_query_inc,
    // keep the latest-height gauge in sync (T36.8)
    bridge_latest_height_set,
	// T37 BridgeOps: last-served gauge
	bridge_last_served_set,
};

use eezo_crypto::sig::registry::verify as verify_sig;
use eezo_ledger::bridge::{canonical_mint_msg, BridgeMintVoucher, ExtChain};
use eezo_ledger::Address;
#[cfg(feature = "checkpoints")]
use eezo_ledger::checkpoints::{
	checkpoint_filename, checkpoint_filename_tagged, // Removed private parse_height_and_tag
    list_checkpoint_files_in as ledger_list_checkpoints, // Use alias for ledger helper
    BridgeHeader, CHECKPOINTS_DIR, // Removed unused CheckpointFile
};

/// Accept both legacy (`00000000000000002048.json`) and new (`ckpt_000..._active.json`) names.
fn parse_checkpoint_height_from_name(name: &str) -> Option<u64> {
    // 1) legacy: exactly 20 digits and ".json"
    if let Some(stem) = name.strip_suffix(".json") {
        if stem.chars().all(|c| c.is_ascii_digit()) {
            return u64::from_str(stem).ok();
        }
    }
    // 2) new: "ckpt_<20-digits>_*.json"
    if let Some(rest) = name.strip_prefix("ckpt_") {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return u64::from_str(&digits).ok();
        }
    }
    None
}

/// Best-effort tag inference from filename.
fn parse_checkpoint_tag_from_name(name: &str) -> Option<String> {
    if name.contains("_active.json") {
        Some("active".to_string())
    } else if name.contains("_next.json") {
        Some("next".to_string())
    } else {
        None
    }
}

#[cfg(all(feature = "persistence", feature = "state-sync"))]
use eezo_ledger::persistence::StateSnapshot;
#[cfg(feature = "eth-ssz")]
use eezo_ledger::merkle::tx_inclusion_proof;

#[derive(Deserialize)]
pub struct ProveQuery {
    pub height: u64,
    pub batch: Option<u32>,
}

#[derive(Deserialize)]
pub struct MintRequest {
    /// 0x + 64 hex chars (32 bytes)
    pub deposit_id: String,
    /// external chain id (Alpha: 1 = Sepolia stub)
    pub ext_chain: u8,
    /// 0x + 64 hex chars (tx hash on external chain)
    pub source_tx: String,
    /// EEZO recipient (0x.. or eezo1.. → normalized to 20B)
    pub to: String,

/// Decimal string
    pub amount: String,
    /// Admin signature (hex or base64) over canonical message
    pub sig: String,
}

#[derive(Serialize)]
pub struct MintResponse {
    pub status: &'static str,
    pub to: String,
    pub new_balance: String,
}

/// Simple rotation status DTO.
#[derive(Serialize)]
pub struct RotationStatus {
    pub active_suite_id: u8,
    pub next_suite_id: Option<u8>,
    pub dual_accept_until: Option<u64>,
    pub window_open: bool,
    pub current_height: u64,
}

// Defaults used when runtime policy isn't wired:
#[inline]
fn active_suite_id_default() -> u8 { 1 }
#[inline]
fn next_suite_id_default() -> Option<u8> { Some(2) }
#[inline]
fn dual_accept_until_default() -> Option<u64> { Some(10) }


pub async fn post_bridge_mint(
    State(state): State<AppState>,
    Json(req): Json<MintRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // --- Parse inputs --------------------------------------------------------
    let Some(deposit_id) = parse_hex32(&req.deposit_id) else {
        return bad("bad deposit_id");
};
    let Some(source_tx) = parse_hex32(&req.source_tx) else {
        return bad("bad source_tx");
    };
let Some(addr) = parse_account_addr(&req.to) else {
        return bad("bad to addr");
    };
let Ok(amount_u128) = req.amount.parse::<u128>() else {
        return bad("bad amount");
    };
let Some(sig_bytes) = decode_sig(&req.sig) else {
        return bad("bad sig");
    };
// Canonical EEZO hex for Accounts storage
    let to_hex = format!("0x{}", hex::encode(addr.as_bytes()));
// Build voucher
    let voucher = BridgeMintVoucher {
        deposit_id,
        ext_chain: req.ext_chain as ExtChain,
        source_tx,
        to: Address::from_bytes(*addr.as_bytes()),
        amount: amount_u128,
        sig: sig_bytes,
    };
// --- Apply (replay-safe) -------------------------------------------------
    // Lock bridge state for replay check + bookkeeping
    let mut bridge = state.bridge.lock().await;
// 1) Replay guard
    if bridge.processed_deposits.contains(&voucher.deposit_id) {
        #[cfg(feature = "metrics")]
        {
            use crate::metrics::EEZO_BRIDGE_MINT_TOTAL;
EEZO_BRIDGE_MINT_TOTAL.with_label_values(&["replay"]).inc();
        }
        return bad("replay");
}

    // 2) Verify admin signature unless disabled by env (runtime toggle).
if std::env::var("EEZO_SKIP_SIG_VERIFY").ok().as_deref() != Some("1") {
        // bridge key is optional at runtime;
        // if missing, bridge is effectively disabled
        let Some(pk) = state.bridge_admin_pubkey.as_ref() else {
            return (StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"error":"bridge_disabled"})));
};
        let msg = canonical_mint_msg(state.chain_id, &voucher);

        // First try the "active" key.
        let mut ok = verify_sig(pk.as_slice(), &msg, &voucher.sig);
// During the dual-accept window, also accept a "next" key if provided via env:
        //    EEZO_BRIDGE_NEXT_PUBKEY = hex("0x…") or base64 of the next suite's pubkey
        if !ok {
            let height_now = state.block_height.load(Ordering::Relaxed);
let window_open = state
                .dual_accept_until
                .map(|until| height_now <= until)
                .unwrap_or(false);
if window_open {
                if let Ok(next_str) = std::env::var("EEZO_BRIDGE_NEXT_PUBKEY") {
                    if let Some(next_pk) = decode_sig(&next_str) {
                        ok = verify_sig(next_pk.as_slice(), &msg, &voucher.sig);
}
                }
            }
        }

        if !ok {
            #[cfg(feature = "metrics")]
            {
                use crate::metrics::EEZO_BRIDGE_MINT_TOTAL;
EEZO_BRIDGE_MINT_TOTAL.with_label_values(&["bad_sig"]).inc();
            }
            return bad("bad_sig");
}
    }

    // 3) Credit the recipient
    state.accounts.mint(&to_hex, amount_u128 as u64).await;
// 4) Mark processed (replay safety)
    bridge.processed_deposits.insert(voucher.deposit_id);
// 5) Persist a snapshot so state survives restarts (dev / zero-peer mode)
    //    Update the ledger snapshot by CREDITING the same amount on the ledger Accounts,
    //    and carry forward the BridgeState.
    // Avoids needing a HashMap-like insert.
    #[cfg(all(feature = "persistence", feature = "state-sync"))]
    {
        // Height: in your current single-node dev run, this will be 0
        let height = state.block_height.load(Ordering::Relaxed);
// Load previous snapshot at this height (or synthesize an empty one)
        let mut snap = match state.db.load_state_snapshot(height) {
            Ok(Some(s)) => s,
            Ok(None) => StateSnapshot {
                height,
                accounts: Default::default(),

    supply: Default::default(),
                state_root: [0u8;
32],
                bridge: None,
                #[cfg(feature = "eth-ssz")]
                codec_version: 2,
                #[cfg(feature = "eth-ssz")]
                state_root_v2: [0u8;
32],
            },
            Err(e) => {
                #[cfg(feature = "metrics")]
                {
                    use crate::metrics::EEZO_BRIDGE_MINT_TOTAL;
EEZO_BRIDGE_MINT_TOTAL
                        .with_label_values(&["persist_err"])
                        .inc();
}
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("load snapshot failed: {e:?}")

     })),
                );
}
        };

        // CREDIT the same account in the persisted ledger snapshot
        snap.accounts.credit(voucher.to, amount_u128);
// Carry forward the bridge state we mutated
        snap.bridge = Some(bridge.clone());
// Write snapshot and refresh tip
        if let Err(e) = state.db.put_state_snapshot(&snap) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("persist snapshot failed: {e:?}")

    })),
            );
}
        if let Err(e) = state.db.set_tip(height) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("set tip failed: {e:?}")
                })),

           );
}
    }

    // Read back balance for response
    let (bal, _nonce) = state.accounts.get(&to_hex).await;
#[cfg(feature = "metrics")]
    {
        use crate::metrics::EEZO_BRIDGE_MINT_TOTAL;
        EEZO_BRIDGE_MINT_TOTAL.with_label_values(&["ok"]).inc();
}

    let resp = MintResponse {
        status: "ok",
        to: to_hex.clone(),
        new_balance: bal.to_string(),
    };
(StatusCode::OK, Json(serde_json::json!(resp)))
}

pub async fn get_outbox(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    // OutboxEvent doesn't implement Serialize; return Debug strings for each item.
    let list = state.outbox.read().await.clone();
    let outbox_dbg: Vec<String> = list.iter().map(|e| format!("{:?}", e)).collect();
    (StatusCode::OK, Json(serde_json::json!({ "outbox": outbox_dbg })))
}

pub async fn get_outbox_one(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> (StatusCode, Json<serde_json::Value>) {
    let guard = state.outbox.read().await;
    if let Some(x) = guard.iter().find(|e| e.id == id) {
        // Return a serializable wrapper with Debug text
        return (StatusCode::OK, Json(serde_json::json!({ "event": format!("{:?}", x) })));
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    )
}

/// GET /bridge/rotation — surface rotation posture/state for clients
pub async fn get_bridge_rotation(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let height_now = state.block_height.load(Ordering::Relaxed);
let active = state.active_suite_id;
    let next = state.next_suite_id;
    let until = state.dual_accept_until;
    let window_open = until.map(|u| height_now <= u).unwrap_or(false);
let resp = RotationStatus {
        active_suite_id: active,
        next_suite_id: next,
        dual_accept_until: until,
        window_open,
        current_height: height_now,
    };
(StatusCode::OK, Json(serde_json::json!(resp)))
}


// ── Bridge Header (Checkpoint) endpoint ─────────────────────────────────────
// GET /bridge/header/{height}
#[cfg(feature = "checkpoints")]
pub async fn get_bridge_header(
    State(state): State<AppState>,
    Path(height): Path<u64>
) -> (StatusCode, Json<serde_json::Value>) {
    // datadir-aware read from <datadir>/proof/checkpoints
    match read_checkpoint_any_in(&checkpoints_dir(&state), height) {
        Ok((_path, hdr)) => {
            let hdr_height = hdr.height; // Capture height before moving hdr
            // T37.8: drift warning (read path)
            warn_if_drift(hdr_height);			
            // T36.6: served metric (height)
			#[cfg(feature = "metrics")]
            {
                bridge_served_inc("height");
                // +++ Added log +++
                log::info!("get_bridge_header: Setting metric gauge to height={}", hdr_height);
                bridge_latest_height_set(hdr_height);
				log::info!("get_bridge_header: Metric gauge set confirmed for height={}", hdr_height);
				// T37: record that we actually served this height
				bridge_last_served_set(hdr_height);
            }
			(StatusCode::OK, Json(serde_json::to_value(hdr).unwrap()))
        }
        Err(err_msg) => {
			// T36.6: served metric (height)
			#[cfg(feature = "metrics")]
			{ bridge_served_inc("height"); }
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                  "error": err_msg, "height": height
            })))
        }
    }
}

/// Find the highest-height checkpoint file present under the given directory.
/// Uses the ledger's listing function which handles parsing and sorting.
#[cfg(feature = "checkpoints")]
fn find_latest_checkpoint_file_in(dir: &FsPath) -> Option<PathBuf> {
    // +++ Added log +++
    log::info!("find_latest_checkpoint_file_in: Reading directory: {:?}", dir);

    // Use the imported function from the ledger crate
    match ledger_list_checkpoints(dir) {
        Ok(checkpoints) => {
            // +++ Added log +++
            log::info!("find_latest_checkpoint_file_in: Found {} files via ledger_list_checkpoints", checkpoints.len());
            if let Some(latest) = checkpoints.first() { // Ledger function already sorts descending by height
                // +++ Added log +++
                log::info!("find_latest_checkpoint_file_in: Identified latest: height={}, path={:?}, tag={:?}", latest.height, latest.path, latest.tag);
                Some(latest.path.clone())
            } else {
                // Fallback: permissive scan for both naming styles
                log::info!("find_latest_checkpoint_file_in: No valid checkpoints from ledger list; falling back to permissive scan.");
                let mut best: Option<(u64, PathBuf)> = None;
                if let Ok(rd) = std::fs::read_dir(dir) {
                    for ent in rd.flatten() {
                        let p = ent.path();
                        if p.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                            if let Some(h) = parse_checkpoint_height_from_name(name) {
                                match &mut best {
                                    None => best = Some((h, p)),
                                    Some((bh, _)) if h > *bh => best = Some((h, p)),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                if let Some((h, p)) = best {
                    log::info!("find_latest_checkpoint_file_in: Fallback picked height={} at {:?}", h, p);
                    Some(p)
                } else {
                    log::info!("find_latest_checkpoint_file_in: Fallback found 0 files.");
                    None
                }
            }
        },
        Err(e) => {
            // +++ Added log +++
            log::error!("find_latest_checkpoint_file_in: Error listing checkpoints using ledger function: {}", e);
            None
        }
    }
}


/// GET /bridge/header/latest
 #[cfg(feature = "checkpoints")]
pub async fn get_bridge_header_latest(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
     // +++ Added log +++
     log::info!("get_bridge_header_latest: Handler invoked.");
     match find_latest_checkpoint_file_in(&checkpoints_dir(&state)) {
         None => {
             // +++ Added log +++
             log::info!("get_bridge_header_latest: No latest file found.");
             #[cfg(feature="metrics")]{ bridge_served_inc("latest"); } (StatusCode::NOT_FOUND, Json(json!({})))
         }
         Some(path) => {
             // +++ Added log +++
             log::info!("get_bridge_header_latest: Found candidate path: {:?}", path);
             match fs::read(&path).ok().and_then(|b| serde_json::from_slice::<BridgeHeader>(&b).ok()) {
                 None => {
                    // +++ Added log +++
                    log::info!("get_bridge_header_latest: Failed to read or parse header at {:?}", path);
                    #[cfg(feature="metrics")]{ bridge_served_inc("latest"); } (StatusCode::NOT_FOUND, Json(json!({})))
                 }
                Some(h) => {
                    let h_height = h.height; // Capture height before moving h
                    // T37.8: drift warning (read path)
                    warn_if_drift(h_height);					
                    // +++ Added log +++
                    log::info!("get_bridge_header_latest: Successfully read header for height={}. Setting metric gauge.", h_height);
                    #[cfg(feature="metrics")]{
                        bridge_served_inc("latest");
                        bridge_latest_height_set(h_height);
						log::info!("get_bridge_header_latest: Metric gauge set confirmed for height={}", h_height);
						// T37: last-served gauge for latest endpoint, too
						bridge_last_served_set(h_height);
                    }
                     (StatusCode::OK, Json(serde_json::to_value(h).unwrap_or_else(|_| json!({}))))
                 }
             }
         }
     }
 }
// ── Bridge index (T36.6) ────────────────────────────────────────────────────
/// Query params for `/bridge/index`: `?limit=&offset=`
#[cfg(feature = "checkpoints")]
#[derive(Deserialize)]
pub struct BridgeIndexQuery {
    pub limit:  Option<usize>,
    pub offset: Option<usize>,
}

/// One entry in the `/bridge/index` response.
#[cfg(feature = "checkpoints")]
#[derive(Serialize, Clone)] // +++ Added Clone +++
pub struct BridgeIndexEntry {
    pub height: u64,
    pub file:   String,
    /// `modified_unix` is seconds since UNIX_EPOCH, if available.
    pub modified_unix: Option<u64>,
    /// Optional rotation tag: "active" | "next" (if the file was tagged).
    pub tag:    Option<String>,
}

#[cfg(feature = "checkpoints")]
fn to_unix_secs(st: Option<SystemTime>) -> Option<u64> {
    st.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
      .map(|d| d.as_secs())
}
// ── T36.8: datadir-aware helpers ────────────────────────────────────────────
#[cfg(feature = "checkpoints")]
fn proof_root(state: &AppState) -> PathBuf {
    let mut p = state.datadir.clone().unwrap_or_else(|| PathBuf::from("data"));
    p.push("proof");
    p
}

#[cfg(feature = "checkpoints")]
fn checkpoints_dir(state: &AppState) -> PathBuf {
    let mut p = proof_root(state);
    p.push("checkpoints");
    p
}
// ── T37.8: drift guard helpers ──────────────────────────────────────────────
#[inline]
fn checkpoint_every_env() -> u64 {
    env::var("EEZO_CHECKPOINT_EVERY")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(32)
}

#[inline]
fn warn_if_drift(h: u64) {
    let every = checkpoint_every_env();
    if every > 0 && h % every != 0 {
        log::warn!(
            "checkpoint drift: height {} is not a multiple of EEZO_CHECKPOINT_EVERY={} \
             (check writer interval / rotation policy)",
            h, every
        );
    }
}

/// List checkpoint files inside a directory (non-recursive), returning parsed heights,
/// stable paths, and modification times. Uses the ledger crate's function.
#[cfg(feature = "checkpoints")]
fn list_checkpoints_in(dir: &FsPath) -> std::io::Result<Vec<BridgeIndexEntry>> {
    // +++ Added Log +++
    log::info!("list_checkpoints_in: Reading directory: {:?}", dir);

    // Call the ledger function directly
    let ledger_files = ledger_list_checkpoints(dir)?;

    // +++ Added Log +++
    log::info!("list_checkpoints_in: Found {} files via ledger_list_checkpoints", ledger_files.len());

    // Convert CheckpointFile from ledger to BridgeIndexEntry for node response
    let result_entries: Vec<BridgeIndexEntry> = ledger_files.into_iter().map(|cf| BridgeIndexEntry {
        height: cf.height,
        // Use the full path's filename
        file: cf.path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        modified_unix: to_unix_secs(cf.modified),
        tag: cf.tag,
    }).collect();

    // +++ Added Log (Optional: Log top 5 results) +++
    if !result_entries.is_empty() {
        let top_n = result_entries.iter().take(5).map(|e| e.height).collect::<Vec<_>>();
        log::info!("list_checkpoints_in: Top {} sorted heights returned by ledger function: {:?}", top_n.len(), top_n);
        return Ok(result_entries);
    }

    // Fallback: permissive scan for both "numeric.json" and "ckpt_..._active.json"
    log::info!("list_checkpoints_in: No valid checkpoints via ledger function; falling back to permissive scan.");
    let mut rows: Vec<BridgeIndexEntry> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if let Some(h) = parse_checkpoint_height_from_name(&name) {
                let modified_unix = ent.metadata().ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                rows.push(BridgeIndexEntry {
                    height: h,
                    file: name.clone(), // <--- THIS IS THE FIX
                    modified_unix,
                    tag: parse_checkpoint_tag_from_name(&name),
                });
            }
        }
    }
    // Sort by height desc (match ledger helper’s ordering)
    rows.sort_by(|a, b| b.height.cmp(&a.height));
    log::info!("list_checkpoints_in: Permissive scan found {} file(s).", rows.len());
    Ok(rows)
}


#[cfg(feature = "checkpoints")]
fn read_checkpoint_any_in(dir: &FsPath, height: u64) -> Result<(PathBuf, BridgeHeader), &'static str> {
    // legacy (untagged)
    let legacy = dir.join(checkpoint_filename(height));
    if let Ok(bytes) = fs::read(&legacy) {
        if let Ok(h) = serde_json::from_slice::<BridgeHeader>(&bytes) { return Ok((legacy, h)); }
        else { log::warn!("Failed parsing legacy checkpoint {:?} as BridgeHeader", legacy); /* Continue search */ }
    }
    // active tag
    let active = dir.join(checkpoint_filename_tagged(height, "active"));
    if let Ok(bytes) = fs::read(&active) {
        if let Ok(h) = serde_json::from_slice::<BridgeHeader>(&bytes) { return Ok((active, h)); }
        else { log::warn!("Failed parsing active checkpoint {:?} as BridgeHeader", active); /* Continue search */ }
    }
    // next tag
    let next = dir.join(checkpoint_filename_tagged(height, "next"));
     if let Ok(bytes) = fs::read(&next) {
        if let Ok(h) = serde_json::from_slice::<BridgeHeader>(&bytes) { return Ok((next, h)); }
        else { log::warn!("Failed parsing next checkpoint {:?} as BridgeHeader", next); /* Continue search */ }
    }

    // Try suite-specific subdirs ONLY if top-level checks failed (backward compat)
    let ml = dir.join("ml-dsa").join(checkpoint_filename(height));
    if let Ok(bytes) = fs::read(&ml) {
        if let Ok(h) = serde_json::from_slice::<BridgeHeader>(&bytes) { return Ok((ml, h)); }
        else { log::warn!("Failed parsing ml-dsa checkpoint {:?} as BridgeHeader", ml); /* Continue search */ }
    }
    let sp = dir.join("sphincs").join(checkpoint_filename(height));
    if let Ok(bytes) = fs::read(&sp) {
        if let Ok(h) = serde_json::from_slice::<BridgeHeader>(&bytes) { return Ok((sp, h)); }
        else { log::warn!("Failed parsing sphincs checkpoint {:?} as BridgeHeader", sp); /* Continue search */ }
    }

    // +++ Added log for failure +++
    log::debug!("read_checkpoint_any_in: Header not found for height {} in dir {:?}", height, dir);
    Err("header_not_found")
}
/// GET /bridge/index
/// Returns a paged list of emitted checkpoints found under `proof/checkpoints/`.
#[cfg(feature = "checkpoints")]
pub async fn get_bridge_index(
    State(state): State<AppState>,
    Query(q): Query<BridgeIndexQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    // +++ Added Log +++
    log::info!("get_bridge_index: Handler invoked with limit={:?}, offset={:?}", q.limit, q.offset);
    // defaults: show up to 50 items starting at 0
    let limit  = q.limit.unwrap_or(50).min(500);
    let offset = q.offset.unwrap_or(0);

    // T36.8: list under <datadir>/proof/checkpoints
    let all = match list_checkpoints_in(&checkpoints_dir(&state)) {
        Ok(v) => v,
        Err(e) => {
             // +++ Added Log +++
            log::error!("get_bridge_index: Error listing checkpoints: {}", e);
            let payload = json!({
                "total":  0u64,
                "offset": offset,
                "limit":  limit,
                "items":  [],     // empty JSON array (no cast inside `json!`)
            });
            // metrics: count the query + served event even on empty/err dir
            #[cfg(feature = "metrics")]
            {
                bridge_index_query_inc();
                bridge_served_inc("index");
            }
            return (StatusCode::OK, Json(payload));
        }
    };

    let total = all.len() as u64;
    let end = offset.saturating_add(limit).min(all.len());
    let slice = if offset >= all.len() { &all[0..0] } else { &all[offset..end] };

    // +++ Added Log +++
    log::info!("get_bridge_index: Total files={}, Offset={}, Limit={}, Slice len={}", total, offset, limit, slice.len());

    let items: Vec<BridgeIndexEntry> = slice.to_vec(); // Clone the slice items

    let payload = json!({
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "items":  items,
    });
    // metrics: count successful index query + served
    #[cfg(feature ="metrics")]
    {
        bridge_index_query_inc();
        bridge_served_inc("index");
    }
    (StatusCode::OK, Json(payload))
}

// ── Bridge summary (T36.7) ──────────────────────────────────────────────────
/// GET /bridge/summary
/// Compact summary for relay polling & dashboards.
/// Returns:
/// { "latest_height": u64, "total": u64, "last_modified_unix": u64|null,
///   "active_suite": u8, "next_suite": u8|null }
#[cfg(feature = "checkpoints")]
pub async fn get_bridge_summary(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    // +++ Added Log +++
    log::info!("get_bridge_summary: Handler invoked.");
    // defaults from runtime rotation posture
    let active = state.active_suite_id;
    let next   = state.next_suite_id;

    // T36.8: read under <datadir>/proof/checkpoints
    let checkpoints_result = list_checkpoints_in(&checkpoints_dir(&state));

    let resp = match checkpoints_result {
        Ok(list) if !list.is_empty() => {
            let latest = &list[0]; // Already sorted descending
            // T37.8: drift warning (read path)
            warn_if_drift(latest.height);			
             // +++ Added Log +++
            log::info!("get_bridge_summary: Found latest checkpoint height={}, file={:?}. Setting metric gauge.", latest.height, latest.file);
            let r = json!({
                "latest_height":     latest.height,
                "total":             list.len() as u64,
                "last_modified_unix": latest.modified_unix,
                "active_suite":      active,
                "next_suite":        next,
            });
            #[cfg(feature="metrics")] {
                bridge_summary_query_inc();
                bridge_served_inc("summary");
                bridge_latest_height_set(latest.height);
				log::info!("get_bridge_summary: Metric gauge set confirmed for height={}", latest.height);
            }
            r
        }
        Ok(_) => { // Empty list
             // +++ Added Log +++
            log::info!("get_bridge_summary: No checkpoint files found.");
            #[cfg(feature="metrics")] { bridge_summary_query_inc(); bridge_served_inc("summary"); }
            json!({
                "latest_height":      0u64,
                "total":              0u64,
                "last_modified_unix": null,
                "active_suite":       active,
                "next_suite":         next,
            })
        }
        Err(e) => { // Error reading directory
             // +++ Added Log +++
            log::error!("get_bridge_summary: Error listing checkpoints: {}", e);
            #[cfg(feature="metrics")] { bridge_summary_query_inc(); bridge_served_inc("summary"); }
             json!({
                "latest_height":      0u64,
                "total":              0u64,
                "last_modified_unix": null,
                "active_suite":       active,
                "next_suite":         next,
                "error":              "failed to read checkpoints directory" // Optional: Add error hint
            })
        }
    };

    (StatusCode::OK, Json(resp))
}

/// GET /bridge/branch?height=<h>&tx_index=<i>
/// Returns real { height, tx_id, leaf_hex, index, branch_hex[] } from the ledger.
/// Requires building node with: `--features "persistence,eth-ssz"`
pub async fn get_bridge_branch(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    // T36.8: metrics (count query + served)
    #[cfg(feature = "metrics")]
    { bridge_branch_query_inc(); bridge_served_inc("branch"); }
    // 1) Parse inputs
    let height: u64 = params
        .get("height")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
let index: usize = params
        .get("tx_index")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
// 2) Load block from persistence
    #[cfg(feature = "persistence")]
    let block_opt: Option<eezo_ledger::Block> = state.db.get_block(height).ok();
#[cfg(not(feature = "persistence"))]
    // Give None an explicit type so the compiler can infer later uses of `block`
    let block_opt: Option<eezo_ledger::Block> = None; // Use ledger::Block type
let Some(block) = block_opt else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "block_not_found", "height": height })),
        );
};

    // 3) Build tx branch from real txs
    #[cfg(not(feature = "eth-ssz"))]
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "eth-ssz feature disabled at build time" })),
        );
}

    #[cfg(feature = "eth-ssz")]
    {
        if block.txs.is_empty() || index >= block.txs.len() {
            // ── Devnet grace: allow a synthetic proof when there are no txs ─────────
            // Only for convenience while developing on single-node empty blocks.
            // Must be compiled with `--features dev-tools`. Real testnet/mainnet
            // will still get a strict 400.
            #[cfg(feature = "dev-tools")]
            {
                if index == 0 && block.txs.is_empty() {
                    // Synthetic "empty" leaf/root and no branch; clearly marked.
                    let leaf_hex = format!("0x{}", hex::encode([0u8; 32]));
                    let branch_hex: Vec<String> = Vec::new();
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "height": height,
                            "tx_id": "0x",
                            "leaf_hex": leaf_hex,
                            "index": index,
                            "branch_hex": branch_hex,
                            "synthetic": true,
                            "reason": "empty_block"
                        })),
                    );
                }
            }
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "bad_index", "height": height, "index": index })),
            );
        }

        let tx = &block.txs[index];
        // Ensure encode_signed_tx is accessible (might need to qualify if defined elsewhere)
        let tx_id = format!("0x{}", hex::encode(eezo_ledger::block::encode_signed_tx(tx)));
let Some((leaf, branch, root)) = tx_inclusion_proof(&block.txs, index) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "proof_build_failed", "height": height, "index": index })),
            );
};

        if block.header.tx_root_v2 != root {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "root_mismatch",
                    "height": height,

            "expected": format!("0x{}", hex::encode(block.header.tx_root_v2)),
                    "got": format!("0x{}", hex::encode(root))
                })),
            );
}

        let leaf_hex = format!("0x{}", hex::encode(leaf));
        let branch_hex: Vec<String> = branch
            .into_iter()
            .map(|n| format!("0x{}", hex::encode(n)))
            .collect();
        (
            StatusCode::OK,
            Json(json!({
                "height": height,
                "tx_id": tx_id,
                "leaf_hex": leaf_hex,
                "index": index,

         "branch_hex": branch_hex
            })),
        )
}
}

/// GET /bridge/prove?height=<h>&batch=<n>
/// Returns { proof_hex, public_inputs_abi_hex, circuit_version }
pub async fn get_bridge_prove(
    Query(q): Query<ProveQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    // T36.8: metrics (count query + served)
    #[cfg(feature = "metrics")]
    { bridge_prove_query_inc(); bridge_served_inc("prove"); }
    // default batch if not provided
    let batch = q.batch.unwrap_or(4);
// Allow overriding the prover binary path via env; default to `eezo-prover` in PATH
    let prover_bin =
        std::env::var("EEZO_PROVER_BIN").unwrap_or_else(|_| "eezo-prover".to_string());
// Spawn the prover CLI
    let out = match Command::new(&prover_bin)
        .args([
            "prove-checkpoint",
            "--height",
            &q.height.to_string(),
            "--batch-sigs",
            &batch.to_string(),
        ])
        .output()

{
        Ok(o) => o,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "prover_spawn_failed",

          "detail": format!("{e}")
                })),
            )
        }
    };
if !out.status.success() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "prover_failed",
                "stderr": String::from_utf8_lossy(&out.stderr)
            })),
        );
}

    // The prover prints JSON — parse and return only what we need
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error":"prover_json_parse_failed"})),
        );
};

    let proof_hex = val.get("proof_hex").and_then(|v| v.as_str()).unwrap_or("");
    let pubin_hex = val
        .get("public_inputs_abi_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("");
let circuit_version = val
        .get("circuit_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(2) as u32;
(
        StatusCode::OK,
        Json(serde_json::json!({
            "proof_hex": proof_hex,
            "public_inputs_abi_hex": pubin_hex,
            "circuit_version": circuit_version,
            "height": q.height,
            "batch_len": batch,
            // surface rotation metadata to clients tooling (up for the cutover)
            "active_suite_id":   active_suite_id_default(),
            "next_suite_id":     next_suite_id_default(),
            "dual_accept_until": dual_accept_until_default()
        })),
    )
}
// ── T36.8: POST /bridge/prove → write <datadir>/proof/{proof.hex,public_inputs.hex}
#[derive(Deserialize)]
pub struct ProveBody {
    pub proof: String,
    pub public_inputs: String
}

#[cfg(feature = "checkpoints")]
pub async fn post_bridge_prove(
    State(state): State<AppState>,
    Json(body): Json<ProveBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    #[cfg(feature="metrics")] {
        bridge_prove_query_inc();
        bridge_served_inc("prove");
    }
    let root = proof_root(&state);
    let _ = fs::create_dir_all(&root);
    let pf = root.join("proof.hex");
    let pi = root.join("public_inputs.hex");
    let write_one = |p: &FsPath, s: &str| -> std::io::Result<()> {
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(p)
            .or_else(|e| if e.kind() == ErrorKind::NotFound {
                if let Some(parent) = p.parent() {
                    fs::create_dir_all(parent)?;
                }
                OpenOptions::new().create(true).write(true).truncate(true).open(p)
            } else {
                Err(e)
            })?;
        f.write_all(s.trim().as_bytes())
    };
    if let Err(e) = write_one(&pf, &body.proof).and_then(|_| write_one(&pi, &body.public_inputs)) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": e.to_string() })));
    }
    (StatusCode::OK, Json(json!({ "ok": true })))
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn bad(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
}

fn parse_hex32(s: &str) -> Option<[u8;
32]> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() != 64 ||
!h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(h).ok()?;
let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn decode_sig(s: &str) -> Option<Vec<u8>> {
    if let Some(h) = s.strip_prefix("0x") {
        return hex::decode(h).ok();
}
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
B64.decode(s).ok()
}

// ── rotation-aware checkpoint reader (T34.2) ────────────────────────────────
#[cfg(feature = "checkpoints")]
fn read_checkpoint_any(height: u64) -> Result<(PathBuf, BridgeHeader), &'static str> {
    // datadir-aware read needed here; using default path for now
    let default_dir = PathBuf::from(CHECKPOINTS_DIR);
    read_checkpoint_any_in(&default_dir, height)
}