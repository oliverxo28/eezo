// crates/node/src/consensus_runner.rs
#![cfg(feature = "pq44-runtime")]

// minimal, deterministic adapter that periodically runs one consensus slot
// t36.4: restore checkpoint emission on commit
// t36.5: fill checkpoint roots/timestamp from persistence (when available)

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use std::env;
use std::io::ErrorKind; // <--- ADDED IMPORT

use eezo_ledger::consensus::SingleNode;
// --- UPDATED: Make sure consensus_api imports are correct ---
use eezo_ledger::consensus_api::{run_one_slot, SlotOutcome};
// --- END UPDATE ---

// --- FIX: Import Block ---
use eezo_ledger::Block;

// T36.6 metrics hooks
#[cfg(feature = "metrics")]
use crate::metrics::{bridge_emitted_inc, bridge_latest_set, register_t36_bridge_metrics};


// checkpoints light helpers (exist behind `checkpoints`)
#[cfg(feature = "checkpoints")]
use eezo_ledger::checkpoints::{
    is_checkpoint_height, BridgeHeader, write_checkpoint_json_default,
    // T41.2 helpers:
    rotation_policy_from_env, should_emit_qc_sidecar_v2, build_stub_sidecar_v2,
    // T41.3 validator:
    validate_sidecar_v2_for_header,
};
#[cfg(feature = "checkpoints")]
use eezo_ledger::qc_sidecar::ReanchorReason;
#[cfg(feature = "metrics")]
use crate::metrics::{
    qc_sidecar_emitted_inc, qc_sidecar_verify_ok_inc, qc_sidecar_verify_err_inc,
    // T41.4 (new):
    qc_sidecar_enforce_ok_inc, qc_sidecar_enforce_fail_inc,
};
// persistence handle (methods live on &Persistence)
#[cfg(feature = "persistence")]
use eezo_ledger::persistence::Persistence;
#[cfg(feature = "persistence")]
use eezo_ledger::persistence::StateSnapshot;
// --------------------
// T41.4: strict consumption toggle
// Enabled only when the build has `--features qc-sidecar-v2-enforce` AND env EEZO_QC_SIDECAR_ENFORCE=1/true/on/yes
#[cfg(feature = "checkpoints")]
#[inline]
fn qc_sidecar_enforce_on() -> bool {
    #[cfg(feature = "qc-sidecar-v2-enforce")]
    {
        std::env::var("EEZO_QC_SIDECAR_ENFORCE")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "on" | "yes"))
            .unwrap_or(false)
    }
    #[cfg(not(feature = "qc-sidecar-v2-enforce"))]
    { false }
}

/// Drives a `SingleNode` by calling `run_one_slot()` on a fixed cadence.
/// No networking, no HTTP, no persistence here. Pure runner.
pub struct CoreRunnerHandle {
    stop: Arc<AtomicBool>,
    // we keep the node behind a mutex so the loop is async-friendly
    #[allow(dead_code)]
    node: Arc<Mutex<SingleNode>>,
    // optional DB handle, only when persistence is compiled in
    #[cfg(feature = "persistence")]
    #[allow(dead_code)]
    db: Option<Arc<Persistence>>,
    join: tokio::task::JoinHandle<()>,
}

impl CoreRunnerHandle {
    /// Spawn the runner with a given tick interval (milliseconds).
    /// `rollback_on_error` controls whether to roll back on slot errors.
    #[cfg(not(feature = "persistence"))]
    pub fn spawn(node: SingleNode, tick_ms: u64, rollback_on_error: bool) -> Arc<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let node = Arc::new(Mutex::new(node));
        let stop_c = Arc::clone(&stop);
        let node_c = Arc::clone(&node);
        // Note: db_c is not available in this cfg block
        let join = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(tick_ms.max(1)));
			// expose T36.6 bridge metrics on /metrics immediately
			#[cfg(feature = "metrics")]
			register_t36_bridge_metrics();
            // dev/test knobs
            let log_every: u64 = env::var("EEZO_LOG_COMMIT_EVERY")
                .ok()
                .and_then(|s| s.parse().ok())

                .unwrap_or(50);
            let max_h_opt: Option<u64> = env::var("EEZO_MAX_HEIGHT")
                .ok()
                .and_then(|s| s.parse().ok());
            // optional override of checkpoint cadence
            #[cfg(feature = "checkpoints")]
            let cp_every_env: Option<u64> = env::var("EEZO_CHECKPOINT_EVERY")

                .ok()
                .and_then(|s| s.parse().ok());
            // optional finality depth (default 2)
            let finality_depth: u64 = env::var("EEZO_FINALITY_DEPTH")
                .ok()
                .and_then(|s| s.parse().ok())

               .unwrap_or(2);

            loop {
                // Use Relaxed ordering as per teacher's patch suggestion
                if stop_c.load(Ordering::Relaxed) {
                    break;
                }
                ticker.tick().await;
                // run exactly one slot - assuming run_one_slot is sync based on teacher feedback
                let outcome = {
                    let mut guard = node_c.lock().await;
                    run_one_slot(&mut *guard, rollback_on_error)
                };
                // optional: structured logs (kept minimal in T36.0)
                match outcome {
                    // Assuming SlotOutcome::Committed { height } as per teacher's plan to NOT change API
                    Ok(SlotOutcome::Committed { height }) => {
                        // capture the committed header hash once, reuse later for checkpoint
                        let mut last_commit_hash_opt: Option<[u8;32]> = None;
                        // log every Nth commit to avoid console spam
                        if log_every == 0 || height % log_every == 0 {
                            log::info!("consensus: committed height={}", height);
                        }

                        // --- FIX: Persist FULL BLOCK (if persistence enabled) ---
                        // NOTE: This block is inside a function #[cfg(not(feature = "persistence"))]
                        //       so the inner #[cfg(feature = "persistence")] guard will never be true.
                        //       The persistence logic should be in the other `spawn` function.
                        //       Leaving this structure as-is based on user's original file, but it's logically dead code here.
                        #[cfg(feature = "persistence")]
                        if let Some(ref db_handle) = db_c { // db_c is not defined here

                            // --- Start Replacement ---
                            // Lock once to get both header and transactions
                            let (header_opt, txs_opt) = {
                                let node_guard = node_c.lock().await;
                                (
                                    node_guard.last_committed_header(),
                                    // *** TEACHER'S CORRECTION APPLIED HERE ***
                                    node_guard.last_committed_txs()
                                )
                            };

                            if let (Some(hdr), Some(txs)) = (header_opt, txs_opt) {
                                if hdr.height == height { // Sanity check height

                                    // 1. Construct the full block
                                    let block = Block { header: hdr.clone(), txs: txs };

                                    last_commit_hash_opt = Some(block.header.hash());

                                    // 2. Save the full block AND header
                                    if let Err(e) = db_handle.put_header_and_block(height, &block.header, &block) {
                                        log::error!("❌ runner: failed to persist block at h={}: {}", height, e);
                                    } else {
                                        log::debug!("runner: persisted block at h={}", height);
                                    }
                                } else {
                                    log::warn!(

                                        "runner: header height mismatch (commit={}, header={}) at h={}",

                                        height, hdr.height, height
                                    );
                                }
                            } else {
                                log::warn!("runner: last_committed_header() or last_committed_txs() is None at h={} (unexpected)", height);
                            }
                            // --- End Replacement ---

                        }
                        // --- END FIX ---


                        // --- Phase 1 Snapshot Writing Logic (as per teacher patch) ---

                        // ── PHASE 1: Write a state snapshot at the configured interval ───────────
                        // NOTE: This block is also logically dead code here due to outer cfg.
                        #[cfg(feature = "persistence")]
                        if let Some(ref db_handle) = db_c { // Use the cloned db handle

                            let snapshot_interval = std::env::var("EEZO_SNAPSHOT_INTERVAL")
                                .ok()
                                .and_then(|s| s.parse::<u64>().ok())

                                .or_else(|| {
                                    std::env::var("EEZO_CHECKPOINT_EVERY")
                                        .ok()

                                        .and_then(|s| s.parse::<u64>().ok())
                                })
                                .unwrap_or(1000);
                        // Default interval

                            if snapshot_interval > 0 && height % snapshot_interval == 0 {
                                log::debug!("runner: h={} matches snapshot interval {}", height, snapshot_interval);
                                // Lock only to read the committed state; drop lock before I/O.
                                let node_guard = node_c.lock().await;
                                let snap = StateSnapshot {
                                    height: node_guard.height,             // committed height
                                    accounts: node_guard.accounts.clone(), // clone committed state

                                    supply:   node_guard.supply.clone(),
                                    state_root: [0u8; 32],                 // legacy root (Phase 1: zero OK, use prev_hash if needed)
                                    bridge: None,                          // TODO: Clone bridge state if necessary

                                    #[cfg(feature = "eth-ssz")]
                                    codec_version: 1,

                                    #[cfg(feature = "eth-ssz")]
                                    state_root_v2: [0u8; 32],              // Phase 1: zero → reader falls back
                                };
                                drop(node_guard); // Release lock before DB write

                                match db_handle.put_state_snapshot(&snap) {
                                    Ok(_)  => log::info!("✅ runner: wrote state snapshot at h={}", height),

                                    Err(e) => log::error!("❌ runner: snapshot write failed at h={}: {}", height, e),
                                }
                            }

                        }
                        // ──────────────────────────────────────────────────────────────────────────
                        // --- END Phase 1 Snapshot Logic ---


                        // ── T36.4/5:
                        // emit checkpoint header every N heights ───────────────
                        #[cfg(feature = "checkpoints")]
                        {
                            // read live node values under the mutex

                            let interval_from_node = { // We only need interval now
                                let g = node_c.lock().await;
                                let mut iv = g.ckpt_interval();
                                // env can override the node's configured interval
                                if let Some(cp_env) = cp_every_env {
                                    iv = cp_env;
                                }
                                iv // Return just the interval
                            };
                            if is_checkpoint_height(height, interval_from_node) {
                                // T36.5: fill roots/timestamp from persistence when available
                                let (state_root_v2, tx_root_v2, ts_secs) = {

                                    // Default to zeroes if persistence or necessary features are off
                                    let mut sr = [0u8; 32];
                                    let mut tr = [0u8; 32];
                                    let mut ts = 0u64;
                                    // NOTE: Persistence logic is dead code here.
                                    #[cfg(feature = "persistence")]
                                    if let Some(ref db_handle) = db_c { // Use the cloned db handle from spawn
                                        // Methods on &Persistence (by height).
                                        // Be robust to slight visibility lag:
                                        // try a few times at H, then once at H-1 before giving up.
                                        let mut got: Option<([u8;32],[u8;32],u64)> = None;
                                        // small retry loop at current height
                                        // --- DEBUG PATCH APPLIED HERE ---
                                        for attempt in 0..3 {
                                            // --- UPDATED: Separate reads with logging ---
                                            let sr_res =
                                                db_handle.get_state_root_v2(height);
                                            let tr_res = db_handle.get_tx_root_v2(height);
                                            let ts_res = db_handle.get_header_timestamp_secs(height); // Reads header

                                            match (&sr_res, &tr_res, &ts_res) {

                                                (Ok(sr0), Ok(tr0), Ok(ts0)) => {
                                                    log::debug!("checkpoint: reads successful for h={} on attempt {}", height, attempt+1);
                                                    got = Some((*sr0, *tr0, *ts0));
                                                    break; // Success!
                                                }
                                                _ => {

                                                    // Log specific failures only on the first attempt to avoid spam
                                                    if attempt == 0 {

                                                        if let Err(e) = sr_res { log::warn!("checkpoint: read get_state_root_v2 failed at h={}: {}", height, e); }
                                                        if let Err(e) = tr_res { log::warn!("checkpoint: read get_tx_root_v2 failed at h={}: {}", height, e); }
                                                        if let Err(e) = ts_res { log::warn!("checkpoint: read get_header_timestamp_secs failed at h={}: {}", height, e); }
                                                    }

                                                    log::debug!("checkpoint: reads failed for h={} on attempt {}, retrying...", height, attempt+1);
                                                }
                                            }
                                            // --- END UPDATE ---

                                            tokio::time::sleep(Duration::from_millis(10)).await;
                                        }
                                        // --- END DEBUG PATCH ---
                                        // final fallback: previous height (off-by-one safety)

                                        if got.is_none() && height > 0 {
                                            // Read from db using the new header timestamp func

                                            if let (Ok(sr1), Ok(tr1), Ok(ts1)) = (
                                                db_handle.get_state_root_v2(height - 1),

                                                db_handle.get_tx_root_v2(height - 1),
                                                db_handle.get_header_timestamp_secs(height - 1), // Use header func

                                            ) {
                                                got = Some((sr1, tr1, ts1));
                                            }
                                        }
                                        match got {

                                            Some((got_sr, got_tr, got_ts)) => {
                                                sr = got_sr;
                                                tr = got_tr;
                                                ts = got_ts;
                                            }
                                            None => {

                                                // This warning should NOT appear now if header persistence worked
                                                log::warn!(

                                                    "checkpoint: persistence read unexpectedly failed at h={} → emitting zero roots",
                                                    height

                                                );
                                                // sr, tr, ts remain zero
                                            }
                                        }

                                    }
                                     (sr, tr, ts) // Return values (potentially zeroes)

                                };

                                // Prefer in-memory hash from the just-committed header; fall back to DB only if needed
                                let committed_header_hash = if let Some(hh) = last_commit_hash_opt {
                                    hh
                                } else {
                                    // NOTE: Persistence logic is dead code here.
                                    #[cfg(feature = "persistence")]
                                    {
                                        db_c.as_ref()
                                            .and_then(|db| db.get_header(height).ok())
                                            .map(|h| h.hash()).unwrap_or([0u8;32])
                                    }
                                    #[cfg(not(feature = "persistence"))] { [0u8;32] }
                                };


                                let mut hdr = BridgeHeader::new(
                                    height,

                                    committed_header_hash, // Use hash of the header at 'height'
                                    state_root_v2,         // real (or zero from snapshot fallback)

                                    tx_root_v2,            // real (or zero)
                                    ts_secs,               // real (or 0)

                                    finality_depth,        // env or default(2)
                                );
                                // T41.2: optionally attach QC sidecar v2 at cutover+1
                                #[cfg(feature = "checkpoints")]
                                if let Some(rot) = rotation_policy_from_env() {
                                    if should_emit_qc_sidecar_v2(height, &rot) {
                                        let sc = build_stub_sidecar_v2(hdr.suite_id, height, ReanchorReason::RotationCutover);
                                        if sc.is_sane_for_height(height) {
                                            hdr = hdr.with_sidecar_v2(sc);
                                            #[cfg(feature = "metrics")]
                                            { qc_sidecar_emitted_inc(); }
                                        } else {
                                            log::warn!("qc-sidecar: built sidecar not sane at h={}, skipping attach", height);
                                        }
                                    }
                                }
                                // T41.3: validate (reader-only) and bump metrics
                                if hdr.qc_sidecar_v2.is_some() {
                                    match validate_sidecar_v2_for_header(&hdr) {
                                        Ok(()) => { #[cfg(feature = "metrics")] qc_sidecar_verify_ok_inc(); }
                                        Err(e) => {
                                            #[cfg(feature = "metrics")] qc_sidecar_verify_err_inc();
                                            log::warn!("qc-sidecar: validate failed at h={}: {}", height, e);
                                        }
                                    }
                                }
                                // T41.4: strict mode — require sidecar at cutover+1; reject if missing/bad
                                if qc_sidecar_enforce_on() {
                                    if let Some(rot) = rotation_policy_from_env() {
                                        if should_emit_qc_sidecar_v2(height, &rot) {
                                            let present = hdr.qc_sidecar_v2.is_some();
                                            let valid = present && validate_sidecar_v2_for_header(&hdr).is_ok();
                                            if valid {
                                                #[cfg(feature = "metrics")] qc_sidecar_enforce_ok_inc();
                                            } else {
                                                #[cfg(feature = "metrics")] qc_sidecar_enforce_fail_inc();
                                                log::error!("qc-sidecar(enforce): missing or invalid at h={} → refusing to write checkpoint", height);
                                                // Skip writing this checkpoint
                                                continue;
                                            }
                                        }
                                    }
                                }
                                // --- MODIFIED BLOCK: skip default writer when outbox task is enabled ---
                                let outbox_enabled = std::env::var("EEZO_BRIDGE_OUTBOX_ENABLED")
                                    .map(|v| { let v = v.to_lowercase(); v == "1" || v == "true" || v == "yes" })
                                    .unwrap_or(false);
                                if outbox_enabled {
                                    log::debug!(
                                        "runner: skipping write_checkpoint_json_default at h={} (EEZO_BRIDGE_OUTBOX_ENABLED)",
                                        height
                                    );
                                } else {
                                    // Handle "AlreadyExists" gracefully like before
                                    match write_checkpoint_json_default(&hdr) {
                                        Ok(path) => {
                                            log::debug!("checkpoint: wrote {:?}", path);
                                            #[cfg(feature = "metrics")]
                                            {
                                                bridge_emitted_inc();
                                                bridge_latest_set(height);
                                            }
                                        }
                                        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                                            log::debug!("checkpoint: file already exists at h={}, skipping", height);
                                        }
                                        Err(e)   => log::warn!("checkpoint: write failed at h={}: {}", height, e),
                                    }
                                }
                                // --- END MODIFIED BLOCK ---
                            }
                        }
                        // ────────────────────────────────────────────────────────────────


                        // optional stop-at-height for test runs
                        if let Some(max_h) = max_h_opt {
                            if height >= max_h {

                                log::info!(
                                    "consensus: reached EEZO_MAX_HEIGHT={} → stopping runner",
                                    max_h

                                );
                                break;
                            }
                        }
                    }
                    Ok(SlotOutcome::Skipped(_why)) => {
                        // no-op;
                        // keep loop quiet on purpose
                    }
                    Err(e) => {
                        // do not panic;
                        // T36.0 only logs errors
                        log::warn!("consensus: slot error: {}", e);
                    }
                }
            }
            log::info!("consensus: runner stopped");
        });

        Arc::new(Self {
            stop,
            node,
            // db field is not present when persistence is off
            #[cfg(feature = "persistence")] // Ensure db is only included when feature is on
            db: None, // This branch explicitly lacks persistence
            join,
        })
    }

    /// Spawn variant when persistence is available: pass `Some(db)` to enable real roots.
    #[cfg(feature = "persistence")]
    pub fn spawn(node: SingleNode, db: Option<Arc<Persistence>>, tick_ms: u64, rollback_on_error: bool) -> Arc<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let node = Arc::new(Mutex::new(node));
        let stop_c = Arc::clone(&stop);
        let node_c = Arc::clone(&node);
        let db_c = db.clone();
        // Clone Option<Arc<Persistence>> for the loop

        let join = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(tick_ms.max(1)));
			// expose T36.6 bridge metrics on /metrics immediately
			#[cfg(feature = "metrics")]
			register_t36_bridge_metrics();
            // dev/test knobs
            let log_every: u64 = env::var("EEZO_LOG_COMMIT_EVERY").ok().and_then(|s| s.parse().ok()).unwrap_or(50);
            let max_h_opt: Option<u64> = env::var("EEZO_MAX_HEIGHT").ok().and_then(|s| s.parse().ok());
            #[cfg(feature = "checkpoints")]

            let cp_every_env: Option<u64> = env::var("EEZO_CHECKPOINT_EVERY").ok().and_then(|s| s.parse().ok());
            let finality_depth: u64 = env::var("EEZO_FINALITY_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(2);

            loop {
                // Use Relaxed ordering
                if stop_c.load(Ordering::Relaxed) { break; }
                ticker.tick().await;


                // Assuming run_one_slot is sync
                let outcome = {
                    let mut guard = node_c.lock().await;
                    run_one_slot(&mut *guard, rollback_on_error)
                };
                match outcome {
                     // Assuming SlotOutcome::Committed { height }
                    Ok(SlotOutcome::Committed { height }) => {
                        // capture the committed header hash once, reuse later for checkpoint
                        let mut last_commit_hash_opt: Option<[u8;32]> = None;
                        if log_every == 0 || height % log_every == 0 {
                            log::info!("consensus: committed height={}", height);
                        }

                        // --- FIX: Persist FULL BLOCK ---
                        #[cfg(feature = "persistence")] // Already guarded by function cfg
                        if let Some(ref db_handle) = db_c {

                            // --- Start Replacement ---
                            // Lock once to get both header and transactions
                            let (header_opt, txs_opt) = {
                                let node_guard = node_c.lock().await;
                                (
                                    node_guard.last_committed_header(),
                                    // *** TEACHER'S CORRECTION APPLIED HERE ***
                                    node_guard.last_committed_txs()
                                )
                            };

                            if let (Some(hdr), Some(txs)) = (header_opt, txs_opt) {
                                if hdr.height == height { // Sanity check height

                                    // 1. Construct the full block
                                    let block = Block { header: hdr.clone(), txs: txs };

                                    last_commit_hash_opt = Some(block.header.hash());

                                    // 2. Save the full block AND header
                                    if let Err(e) = db_handle.put_header_and_block(height, &block.header, &block) {
                                        log::error!("❌ runner: failed to persist block at h={}: {}", height, e);
                                    } else {
                                        log::debug!("runner: persisted block at h={}", height);
                                    }
                                } else {
                                    log::warn!(

                                        "runner: header height mismatch (commit={}, header={}) at h={}",
                                        height, hdr.height, height
                                    );
                                }
                            } else {
                                log::warn!("runner: last_committed_header() or last_committed_txs() is None at h={} (unexpected)", height);
                            }
                            // --- End Replacement ---
                        }
                        // --- END FIX ---


                        // --- Phase 1 Snapshot Writing Logic (as per teacher patch) ---

                        // ── PHASE 1: Write a state snapshot at the configured interval ───────────
                        #[cfg(feature = "persistence")] // Already guarded by function cfg
                        if let Some(ref db_handle) = db_c { // Use the cloned db handle

                            let snapshot_interval = std::env::var("EEZO_SNAPSHOT_INTERVAL")
                                .ok()
                                .and_then(|s| s.parse::<u64>().ok())

                                .or_else(|| {
                                    std::env::var("EEZO_CHECKPOINT_EVERY")
                                        .ok()

                                        .and_then(|s| s.parse::<u64>().ok())
                                })

                                .unwrap_or(1000); // Default interval

                            if snapshot_interval > 0 && height % snapshot_interval == 0 {
                                log::debug!("runner: h={} matches snapshot interval {}", height, snapshot_interval);
                                // Lock only to read the committed state; drop lock before I/O.
                                let node_guard = node_c.lock().await;
                                let snap = StateSnapshot {
                                    height: node_guard.height,             // committed height
                                    accounts: node_guard.accounts.clone(), // clone committed state

                                    supply:   node_guard.supply.clone(),
                                    state_root: [0u8; 32],                 // Phase 1: zero OK, could use prev_hash if needed later
                                    bridge: None,                          // TODO: Clone bridge state

                                    #[cfg(feature = "eth-ssz")]
                                    codec_version: 1,

                                    #[cfg(feature = "eth-ssz")]
                                    state_root_v2: [0u8; 32],              // Phase 1: zero → reader falls back
                                };
                                drop(node_guard); // Release lock before DB write

                                match db_handle.put_state_snapshot(&snap) {
                                    Ok(_)  => log::info!("✅ runner: wrote state snapshot at h={}", height),

                                    Err(e) => log::error!("❌ runner: snapshot write failed at h={}: {}", height, e),
                                }
                            }

                        }
                        // ──────────────────────────────────────────────────────────────────────────
                        // --- END Phase 1 Snapshot Logic ---


                        #[cfg(feature = "checkpoints")]

                        {
                            let interval_from_node = { // Only need interval
                                let g = node_c.lock().await;
                                let mut iv = g.ckpt_interval();
                                if let Some(cp_env) = cp_every_env { iv = cp_env;
                                }
                                iv // Return interval
                            };
                            if is_checkpoint_height(height, interval_from_node) {
                                // === T36.5 / Teacher Option 2 / Debug Patch: real roots/timestamp via persistence ===
                                // Default to zeroes if db handle is None or reads fail

                                let (sr, tr, ts) = if let Some(ref db_handle) = db_c { // Use db_c (cloned Option<Arc>)
                                    let mut got: Option<([u8;32],[u8;32],u64)> = None;
                                    // Retry loop at current height 'height'
                                    // --- DEBUG PATCH APPLIED HERE ---
                                    for attempt in 0..3 {

                                        // --- UPDATED: Separate reads with logging ---
                                        let sr_res = db_handle.get_state_root_v2(height);
                                        // Will now read snapshot (and fallback if v2 is 0)
                                        let tr_res = db_handle.get_tx_root_v2(height);
                                        // Will now read header
                                        let ts_res = db_handle.get_header_timestamp_secs(height);
                                        // Reads header

                                        match (&sr_res, &tr_res, &ts_res) {
                                            (Ok(sr0), Ok(tr0), Ok(ts0)) => {

                                                log::debug!("checkpoint: reads successful for h={} on attempt {}", height, attempt+1);
                                                got = Some((*sr0, *tr0, *ts0));
                                                break; // Success!
                                            }
                                            _ => {

                                                // Log specific failures only on the first attempt to avoid spam
                                                if attempt == 0 {

                                                    if let Err(e) = sr_res { log::warn!("checkpoint: read get_state_root_v2 failed at h={}: {}", height, e); }
                                                    if let Err(e) = tr_res { log::warn!("checkpoint: read get_tx_root_v2 failed at h={}: {}", height, e); }
                                                    if let Err(e) = ts_res { log::warn!("checkpoint: read get_header_timestamp_secs failed at h={}: {}", height, e); }
                                                }
                                                 log::debug!("checkpoint: reads failed
                                                    for h={} on attempt {}, retrying...", height, attempt+1);
                                            }
                                        }
                                        // --- END UPDATE ---

                                        tokio::time::sleep(Duration::from_millis(10)).await;
                                    }
                                     // --- END DEBUG PATCH ---
                                    // Fallback to previous height 'height - 1'

                                    if got.is_none() && height > 0 {
                                        // Use db_handle directly

                                        if let (Ok(sr1), Ok(tr1), Ok(ts1)) = (
                                            db_handle.get_state_root_v2(height - 1),

                                            db_handle.get_tx_root_v2(height - 1),
                                            db_handle.get_header_timestamp_secs(height - 1), // Use header func
                                        ) {

                                            got = Some((sr1, tr1, ts1));
                                        }
                                    }
                                    match got {

                                        Some(v) => v,
                                        None => {

                                            // This warning should NOT appear now
                                            log::warn!(

                                                "checkpoint: persistence read unexpectedly failed at h={} → emitting zero roots",
                                                height

                                            );
                                            ([0u8;32], [0u8;32], 0u64) // Fallback zeroes
                                        }
                                    }

                                } else {
                                    // No DB passed to spawn -> use placeholders
                                    log::warn!("checkpoint: no
                                        persistence handle available at h={} -> emitting zero roots", height);
                                    ([0u8;32], [0u8;32], 0u64)
                                };
                                // Prefer in-memory hash from the just-committed header; fall back to DB only if needed
                                let committed_header_hash = if let Some(hh) = last_commit_hash_opt {
                                    hh
                                } else {
                                    db_c.as_ref()
                                        .and_then(|db| db.get_header(height).ok())
                                        .map(|h| h.hash())
                                        .unwrap_or([0u8;32])
                                };

                                let mut hdr = BridgeHeader::new(height, committed_header_hash, sr, tr, ts, finality_depth);
                                // T41.2: optionally attach QC sidecar v2 at cutover+1
                                #[cfg(feature = "checkpoints")]
                                if let Some(rot) = rotation_policy_from_env() {
                                    if should_emit_qc_sidecar_v2(height, &rot) {
                                        let sc = build_stub_sidecar_v2(hdr.suite_id, height, ReanchorReason::RotationCutover);
                                        if sc.is_sane_for_height(height) {
                                            hdr = hdr.with_sidecar_v2(sc);
                                            #[cfg(feature = "metrics")]
                                            { qc_sidecar_emitted_inc(); }
                                        } else {
                                            log::warn!("qc-sidecar: built sidecar not sane at h={}, skipping attach", height);
                                        }
                                    }
                                }
                                // T41.3: validate (reader-only) and bump metrics
                                if hdr.qc_sidecar_v2.is_some() {
                                    match validate_sidecar_v2_for_header(&hdr) {
                                        Ok(()) => { #[cfg(feature = "metrics")] qc_sidecar_verify_ok_inc(); }
                                        Err(e) => {
                                            #[cfg(feature = "metrics")] qc_sidecar_verify_err_inc();
                                            log::warn!("qc-sidecar: validate failed at h={}: {}", height, e);
                                        }
                                    }
                                }
                                // --- MODIFIED BLOCK: skip default writer when outbox task is enabled ---
                                let outbox_enabled = std::env::var("EEZO_BRIDGE_OUTBOX_ENABLED")
                                    .map(|v| { let v = v.to_lowercase(); v == "1" || v == "true" || v == "yes" })
                                    .unwrap_or(false);
                                if outbox_enabled {
                                    log::debug!(
                                        "runner: skipping write_checkpoint_json_default at h={} (EEZO_BRIDGE_OUTBOX_ENABLED)",
                                        height
                                    );
                                } else {
                                    // Handle "AlreadyExists" gracefully like before
                                    match write_checkpoint_json_default(&hdr) {
                                        Ok(path) => {
                                            log::debug!("checkpoint: wrote {:?}", path);
                                            #[cfg(feature = "metrics")]
                                            {
                                                bridge_emitted_inc();
                                                bridge_latest_set(height);
                                            }
                                        }
                                        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                                            log::debug!("checkpoint: file already exists at h={}, skipping", height);
                                        }
                                        Err(e)   => log::warn!("checkpoint: write failed at h={}: {}", height, e),
                                    }
                                }
                                // --- END MODIFIED BLOCK ---
                            }
                        }
                        if let
                        Some(max_h) = max_h_opt { if height >= max_h { log::info!("consensus: reached EEZO_MAX_HEIGHT={} → stopping runner", max_h); break;
                        } }
                    }
                    Ok(SlotOutcome::Skipped(_)) => {}
                    Err(e) => log::warn!("consensus: slot error: {}", e),
                }
            }

            log::info!("consensus: runner stopped");
        });
        Arc::new(Self { stop, node, db, join }) // db field included here
    }


    /// Request stop and wait for the loop to finish.
    pub async fn stop(self: &Arc<Self>) {
        // Use Relaxed ordering
        self.stop.store(true, Ordering::Relaxed);
        // Abort the task cooperatively
        self.join.abort();
    }

    /// Access to the inner node for tests / future wiring (use sparingly).
    pub async fn with_node<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut SingleNode) -> R,
    {
        let mut g = self.node.lock().await;
        f(&mut *g)
    }
}

// (T36.5 removed local stub emitter; runner emits directly.)

