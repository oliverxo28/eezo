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
use std::io::ErrorKind; 
use std::mem; 

use eezo_ledger::consensus::SingleNode;
// --- UPDATED: Make sure consensus_api imports are correct ---
use eezo_ledger::consensus_api::{SlotOutcome, NoOpReason};
// --- END UPDATE ---\
// --- FIX: Import Block ---\
use eezo_ledger::Block; // Keep this import, as we'll need it to reconstruct the Block
use eezo_ledger::SignedTx; // T66.0: used by collect_block_txs_from_mempool()

/// T60.0 — helper: log a compact summary of block tx hashes.
/// This does **not** change behaviour; it only logs.
fn log_block_shadow_debug(prefix: &str, height: u64, blk_opt: &Option<Block>) {
    if let Some(blk) = blk_opt {
        let tx_count = blk.txs.len();
        if tx_count == 0 {
            log::debug!("{}: height={} txs=0", prefix, height);
            return;
        }

        // Sample up to first 8 tx hashes; log 4-byte prefixes to keep logs short.
        let sample: Vec<[u8; 4]> = blk
            .txs
            .iter()
            .take(8)
            .map(|tx| {
                let h = tx.hash();
                [h[0], h[1], h[2], h[3]]
            })
            .collect();

        log::debug!(
            "{}: height={} txs={} sample_tx_hash_prefixes={:?}",
            prefix,
            height,
            tx_count,
            sample,
        );
    } else {
        log::debug!(
            "{}: height={} blk_opt=None (no last_committed_header/txs yet)",
            prefix,
            height
        );
    }
}

/// T71.0 — Compute a GPU-accelerated block body hash (optional, for comparison).
///
/// This function:
///   1. Serializes all tx bytes from the block into a single buffer
///   2. Runs the GPU hash engine on the buffer (if GPU mode is enabled)
///   3. Returns the canonical CPU digest (GPU is only for comparison/metrics)
///
/// The returned hash is always the CPU digest. GPU can only match or mismatch.
/// This does **not** change consensus behaviour; it only exercises the GPU path.
fn compute_block_body_hash_with_gpu(blk_opt: &Option<Block>, height: u64) -> Option<[u8; 32]> {
    use crate::gpu_hash::{NodeHashEngine, NodeHashBackend};

    let blk = blk_opt.as_ref()?;
    if blk.txs.is_empty() {
        return None;
    }

    // Build the GPU hash engine (reads EEZO_NODE_GPU_HASH from env)
    let engine = NodeHashEngine::from_env();

    // Only run the GPU path if not in CpuOnly mode
    if engine.backend() == NodeHashBackend::CpuOnly {
        // Skip GPU comparison when disabled
        return None;
    }

    // Serialize all tx bytes into a single buffer (concatenated tx hashes)
    let mut block_body_bytes = Vec::new();
    for tx in &blk.txs {
        // Use tx.hash() bytes as a compact representation of each tx.
        // This provides a stable, well-defined input format for GPU hashing
        // without depending on the variable-length tx serialization format.
        block_body_bytes.extend_from_slice(&tx.hash());
    }

    // Run the GPU hash engine (will log + count metrics internally)
    let digest = engine.hash_block_body(&block_body_bytes);

    log::debug!(
        "node_gpu_hash: computed block body hash at height={} (mode={:?}, bytes={}, digest=0x{})",
        height,
        engine.backend(),
        block_body_bytes.len(),
        hex::encode(&digest[..4])
    );

    Some(digest)
}

// --- T54 executor wiring ---
use crate::executor::{Executor, ExecInput};
use crate::executor::{SingleExecutor};
use crate::executor::ParallelExecutor;
// T73.3: STM executor (feature-gated)
// When stm-exec feature is enabled, StmExecutor becomes available.
// If EEZO_EXECUTOR_MODE=stm is set but stm-exec is not compiled,
// build_executor() falls back to ParallelExecutor with a warning.
#[cfg(feature = "stm-exec")]
use crate::executor::StmExecutor;

// T67.0: DAG runner handle for future DAG-aware block building
use crate::dag_runner::DagRunnerHandle;
// T69.0: DAG template policy gate
use crate::dag_runner::{DagTemplatePolicy, evaluate_template_policy};

// ============================================================================
// T73.3: Executor Mode Selection
// ============================================================================

/// Executor mode enum for runtime selection.
///
/// Selected via `EEZO_EXECUTOR_MODE` environment variable:
/// - `"single"` or `"s"` → SingleExecutor
/// - `"parallel"` or `"p"` → ParallelExecutor  
/// - `"stm"` or `"block-stm"` → StmExecutor (requires `stm-exec` feature)
/// - Unset/unknown → default to Parallel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorMode {
    Single,
    Parallel,
    Stm,
}

impl ExecutorMode {
    /// Parse executor mode from environment variable `EEZO_EXECUTOR_MODE`.
    ///
    /// Returns the parsed mode or `None` if unset/unknown (caller decides default).
    pub fn from_env() -> Option<Self> {
        std::env::var("EEZO_EXECUTOR_MODE").ok().and_then(|v| {
            match v.to_ascii_lowercase().as_str() {
                "single" | "s" => Some(ExecutorMode::Single),
                "parallel" | "p" => Some(ExecutorMode::Parallel),
                "stm" | "block-stm" => Some(ExecutorMode::Stm),
                _ => None,
            }
        })
    }

    /// Get the default executor mode (Parallel).
    pub fn default_mode() -> Self {
        ExecutorMode::Parallel
    }
}

/// Build the executor based on the mode and thread count.
///
/// - If STM mode is requested but `stm-exec` feature is not enabled,
///   logs a warning and falls back to Parallel.
/// - Logs the selected mode at startup.
fn build_executor(threads: usize) -> Box<dyn Executor> {
    let env_val = std::env::var("EEZO_EXECUTOR_MODE").ok();
    let mode = match &env_val {
        Some(v) => {
            match ExecutorMode::from_env() {
                Some(m) => m,
                None => {
                    log::warn!(
                        "executor: EEZO_EXECUTOR_MODE='{}' is not recognized, using default: parallel",
                        v
                    );
                    ExecutorMode::default_mode()
                }
            }
        }
        None => {
            log::info!("executor: EEZO_EXECUTOR_MODE not set, using default: parallel");
            ExecutorMode::default_mode()
        }
    };

    match mode {
        ExecutorMode::Single => {
            log::info!("executor: mode=single");
            Box::new(SingleExecutor::new())
        }
        ExecutorMode::Parallel => {
            log::info!("executor: mode=parallel threads={}", threads);
            Box::new(ParallelExecutor::new(threads))
        }
        ExecutorMode::Stm => {
            #[cfg(feature = "stm-exec")]
            {
                let exec = StmExecutor::from_env(threads);
                log::info!(
                    "executor: mode=stm threads={} max_retries={} wave_timeout_ms={}",
                    exec.threads(),
                    exec.config().max_retries,
                    exec.config().wave_timeout_ms
                );
                Box::new(exec)
            }
            #[cfg(not(feature = "stm-exec"))]
            {
                log::warn!(
                    "executor: STM mode requested but stm-exec feature is not enabled; \
                     falling back to parallel"
                );
                log::info!("executor: mode=parallel threads={} (fallback from stm)", threads);
                Box::new(ParallelExecutor::new(threads))
            }
        }
    }
}

// T36.6 metrics hooks
#[cfg(feature = "metrics")]
use crate::metrics::{bridge_emitted_inc, bridge_latest_set, register_t36_bridge_metrics};

// 1) Add the imports (top of file, with other use lines) - PATCH A
#[cfg(feature = "metrics")]
use eezo_ledger::metrics::{
    observe_block_applied as ledger_observe_block_applied,
    observe_block_proposed as ledger_observe_block_proposed,
    observe_supply as ledger_observe_supply,
};

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
#[derive(Copy, Clone, Debug)]
enum BlockTxSource {
    /// Current behaviour: collect txs directly from mempool.
    Mempool,
    /// New mode (T68.0): conceptually "DAG candidate", but currently implemented
    /// as a thin wrapper that falls back to mempool. Real DAG usage will land
    /// in T68.1+.
    DagCandidate,
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
    // T67.0: optional DAG runner handle for future DAG-aware block building
    // Stored behind a Mutex so we can attach it after construction.
    #[allow(dead_code)]
    dag: Arc<Mutex<Option<Arc<DagRunnerHandle>>>>,
    join: tokio::task::JoinHandle<()>,
}
impl CoreRunnerHandle {
    /// Spawn the runner with a given tick interval (milliseconds).
    /// `rollback_on_error` controls whether to roll back on slot errors.
    #[cfg(not(feature = "persistence"))]
    #[cfg(not(feature = "persistence"))]
    pub fn spawn(node: SingleNode, tick_ms: u64, rollback_on_error: bool) -> Arc<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let node = Arc::new(Mutex::new(node));
        let stop_c = Arc::clone(&stop);
        let node_c = Arc::clone(&node);
        // T67.0: start with no DAG handle; it can be attached later
        let dag = Arc::new(Mutex::new(None));
        // Note: db_c is not available in this cfg block

        // 1️⃣ Add MAX_TX reading at struct init (persistence disabled path)
        let block_max_tx = std::env::var("EEZO_BLOCK_MAX_TX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(usize::MAX);
		// T68.0: select block tx source from env (default: mempool).
        let block_tx_source = match std::env::var("EEZO_BLOCK_TX_SOURCE")
            .unwrap_or_else(|_| "mempool".to_string())
            .to_lowercase()
            .as_str()
        {
            "dag" | "dagcandidate" => {
                log::info!("consensus: block tx source = DAG candidate (with mempool fallback)");
                BlockTxSource::DagCandidate
            }
            _ => {
                log::info!("consensus: block tx source = mempool (default)");
                BlockTxSource::Mempool
            }
        };

        // T69.0: Parse DAG template policy from env
        let dag_template_policy = DagTemplatePolicy::from_env();
        log::info!("consensus: dag template policy = {:?}", dag_template_policy);

        // T54/T73.3: choose executor mode/threads from env
        let exec_threads = std::env::var("EEZO_EXECUTOR_THREADS")
            .ok().and_then(|v| v.parse::<usize>().ok())
            .unwrap_or_else(num_cpus::get);
        let exec: Box<dyn Executor> = build_executor(exec_threads);

        // T68.1: Clone the DAG handle for use inside the spawned task
        let dag_c = Arc::clone(&dag);

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
                #[cfg(feature = "metrics")]
                let slot_start = std::time::Instant::now();

                // T70.0: Track DAG prepare time when DAG source is enabled
                #[cfg(feature = "metrics")]
                let dag_prepare_start = std::time::Instant::now();

                // T68.1 + T69.0: If DAG source is selected, try to fetch txs from DAG first.
                // T69.0: Also evaluate the template quality gate if policy is not "off".
                let dag_txs: Option<Vec<SignedTx>> = if matches!(block_tx_source, BlockTxSource::DagCandidate) {
                    // Try to get DAG handle
                    let dag_opt: Option<Arc<DagRunnerHandle>> = dag_c.lock().await.clone();
                    if let Some(dag_handle) = dag_opt {
                        // Read block_byte_budget and snapshot state for dry-run
                        let (block_byte_budget, real_state) = {
                            let guard = node_c.lock().await;
                            let state = (guard.accounts.clone(), guard.supply.clone());
                            (guard.cfg.block_byte_budget, state)
                        };

                        // T69.0: Evaluate template gate before collecting txs
                        let gate_decision = dag_handle.evaluate_template_gate(
                            dag_template_policy,
                            Some(real_state),
                        ).await;

                        match gate_decision {
                            Some(decision) if decision.accept => {
                                // Template passed the gate, collect txs from DAG
                                log::debug!(
                                    "dag_tx_source: template gate accepted (reason={})",
                                    decision.reason
                                );
                                dag_handle.collect_block_txs_from_dag(block_byte_budget).await
                            }
                            Some(decision) => {
                                // Template rejected by gate
                                log::info!(
                                    "dag_tx_source: template gate rejected (reason={})",
                                    decision.reason
                                );
                                #[cfg(feature = "metrics")]
                                crate::metrics::dag_template_gate_rejected_inc();
                                None // Fall back to mempool
                            }
                            None => {
                                // No template available (no DAG candidate)
                                log::debug!("dag_tx_source: no template available for gate evaluation");
                                None // Fall back to mempool
                            }
                        }
                    } else {
                        log::debug!("dag_tx_source: DagCandidate selected but no DAG handle attached");
                        None
                    }
                } else {
                    None
                };

                // T70.0: Record DAG prepare time (only when DAG source is enabled)
                #[cfg(feature = "metrics")]
                if matches!(block_tx_source, BlockTxSource::DagCandidate) {
                    let dag_prepare_elapsed = dag_prepare_start.elapsed().as_secs_f64();
                    crate::metrics::observe_block_dag_prepare_seconds(dag_prepare_elapsed);
                }

                // T70.0: Track executor time
                #[cfg(feature = "metrics")]
                let exec_start = std::time::Instant::now();

                // T54 Step 9: Use the executor instead of run_one_slot
                let outcome: Result<SlotOutcome, eezo_ledger::ConsensusError> = {
                    let mut guard = node_c.lock().await;
                    
                    // Save snapshot for potential rollback
                    let snapshot = if rollback_on_error {
                        Some((
                            guard.accounts.clone(),
                            guard.supply.clone(),
                            guard.height,
                            guard.prev_hash,
                        ))
                    } else {
                        None
                    };
                    
                    // 1–2. Collect transactions for this block from the chosen source.
                    // T68.1: If DAG source is selected and returned txs, use those;
                    // otherwise fall back to mempool.
                    let txs = Self::collect_block_txs_with_dag_fallback(
                        block_tx_source,
                        dag_txs,
                        &mut guard,
                        block_max_tx,
                    );

                    let next_height = guard.height + 1;

                    // 3. Create executor input
                    let exec_input = ExecInput::new(txs, next_height);
                    
                    // 4. Execute block using the executor
                    let exec_outcome = exec.execute_block(&mut guard, exec_input);

                    // T70.0: Record executor time
                    #[cfg(feature = "metrics")]
                    {
                        let exec_elapsed = exec_start.elapsed().as_secs_f64();
                        crate::metrics::observe_block_exec_seconds(exec_elapsed);
                    }

                    // 5. Process outcome
                    match exec_outcome.result {
                        Ok(blk) => {
                            // Apply the block to update node state
                            use eezo_ledger::block::apply_block;
                            let chain_id = guard.cfg.chain_id;

                            // take ownership of the state fields (avoid double &mut borrows through the guard)
                            let mut accounts = mem::take(&mut guard.accounts);
                            let mut supply   = mem::take(&mut guard.supply);

                            // apply to the owned values
                            let res = apply_block(chain_id, &mut accounts, &mut supply, &blk);

                            match res {
                                Ok(()) => {
                                    // put the fields back on success
                                    guard.accounts = accounts;
                                    guard.supply   = supply;

                                    // 2) After successful apply — bump ledger metrics - PATCH B
                                    #[cfg(feature = "metrics")]
                                    {
                                        // Emit block proposal metrics (tx count, fees, etc.)
                                        // This increments eezo_txs_included_total and other legacy counters
                                        // Note: fee_total is u128 but cast to u64 for Prometheus (matches consensus.rs behavior)
                                        ledger_observe_block_proposed(
                                            blk.header.tx_count,
                                            blk.header.fee_total as u64
                                        );
                                        // Emit block applied and supply metrics
                                        ledger_observe_block_applied();
                                        ledger_observe_supply(&guard.supply);
                                    }

                                    // Update node pointers
                                    let curr_hash = blk.header.hash();
                                    guard.height = blk.header.height;
                                    guard.prev_hash = curr_hash;
                                    guard.last_header = Some(blk.header.clone());
                                    guard.last_txs = Some(blk.txs.clone());

                                    Ok(SlotOutcome::Committed { height: blk.header.height })
                                }
                                Err(e) => {
                                    // rollback if needed
                                    if let Some((acc, sup, h, ph)) = snapshot {
                                        guard.accounts = acc;
                                        guard.supply = sup;
                                        guard.height = h;
                                        guard.prev_hash = ph;
                                    } else {
                                        // even without snapshot, restore moved-out fields (no state change applied)
                                        guard.accounts = accounts;
                                        guard.supply   = supply;
                                    }
                                    log::warn!("executor: block apply failed: {:?}", e);
                                    Ok(SlotOutcome::Skipped(NoOpReason::Unknown))
                                }
                            }
                        }
                        Err(e) => {
                            // Rollback if needed
                            if let Some((acc, sup, h, ph)) = snapshot {
                                guard.accounts = acc;
                                guard.supply = sup;
                                guard.height = h;
                                guard.prev_hash = ph;
                            }
                            // Convert the executor's internal String error to a ConsensusError
                            log::warn!("executor: block execution failed: {}", e);
                            Ok(SlotOutcome::Skipped(NoOpReason::Unknown))
                        }
                    }
                };
                
                #[cfg(feature = "metrics")]
                // FIX: Revert pattern match for time metric to match only height or ignore all fields
                if let Ok(SlotOutcome::Committed { height: _ }) = outcome {
                    let sec = slot_start.elapsed().as_secs_f64();
                    crate::metrics::EEZO_BLOCK_E2E_LATENCY_SECONDS
                        .with_label_values(&["commit"])
                        .observe(sec);
                    // T70.0: Also record total block latency for perf harness
                    crate::metrics::observe_block_total_latency_seconds(sec);
                }
                // optional: structured logs (kept minimal in T36.0)
                match outcome {
                    // FIX: Revert pattern match to only use 'height'
                    Ok(SlotOutcome::Committed { height }) => {

                        // 🚨 NEW LOGIC: Lock the node again to retrieve the recently committed block data
                        // This is necessary because blk/summary are not returned by run_one_slot
                        let blk_opt = {
                            let node_guard = node_c.lock().await;
                            node_guard.last_committed_header()
                                .zip(node_guard.last_committed_txs())
                                .map(|(header, txs)| Block { header, txs })
                        };
                        
                        // --- T51.5a/T51.5c block batching + inclusion metrics ---
                        // NOTE: eezo_txs_included_total and eezo_block_tx_count are updated
                        // automatically by the ledger via observe_block_proposed() during block assembly.
                        // We only need to update the node-specific fullness metrics here.
                        #[cfg(feature = "metrics")]
                        {
                            use crate::metrics::{
                                EEZO_BLOCK_FULL_TOTAL,
                                EEZO_BLOCK_UNDERFILLED_TOTAL,
                            };

                            if let Some(ref blk) = blk_opt {
                                let tx_count = blk.txs.len();

                                // Use pre-read block_max_tx for fullness stats.
                                if tx_count == block_max_tx {
                                    EEZO_BLOCK_FULL_TOTAL.inc();
                                } else if tx_count > 0 {
                                    EEZO_BLOCK_UNDERFILLED_TOTAL.inc();
                                }
                            }
                        }
                        // --- END METRICS ---

                        // T60.0: block-only shadow tx hash summary (prep for DAG compare)
                        log_block_shadow_debug("dag_shadow_block", height, &blk_opt);

                        // T71.0: GPU hash comparison (optional, controlled by EEZO_NODE_GPU_HASH)
                        // This exercises the GPU hashing path without changing consensus behaviour.
                        let _ = compute_block_body_hash_with_gpu(&blk_opt, height);

                        // update committed height gauge and mempool metrics
                        #[cfg(feature = "metrics")]
                        {
                            crate::metrics::EEZO_BLOCK_HEIGHT.set(height as i64);
                            
                            // Update ledger mempool metrics after block commit
                            let node_guard = node_c.lock().await;
                            let mempool_len = node_guard.mempool.len();
                            let mempool_bytes = node_guard.mempool.bytes_used();
                            drop(node_guard);
                            
                            crate::metrics::EEZO_MEMPOOL_LEN.set(mempool_len as i64);
                            crate::metrics::EEZO_MEMPOOL_BYTES.set(mempool_bytes as i64);
                        }

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
                                    let block = Block { header: hdr.clone(), txs };

                                    _last_commit_hash_opt = Some(block.header.hash());

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
                                let committed_header_hash = blk_opt.as_ref().map(|b| b.header.hash()).unwrap_or([0u8;32]);

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
            dag,
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
        // T67.0: start with no DAG handle; it can be attached later
        let dag = Arc::new(Mutex::new(None));
        // Clone Option<Arc<Persistence>> for the loop

        // 1️⃣ Add MAX_TX reading at struct init (persistence enabled path)
        let block_max_tx = std::env::var("EEZO_BLOCK_MAX_TX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(usize::MAX);
		// T68.0: select block tx source from env (default: mempool).
        let block_tx_source = match std::env::var("EEZO_BLOCK_TX_SOURCE")
            .unwrap_or_else(|_| "mempool".to_string())
            .to_lowercase()
            .as_str()
        {
            "dag" | "dagcandidate" => {
                log::info!("consensus: block tx source = DAG candidate (with mempool fallback)");
                BlockTxSource::DagCandidate
            }
            _ => {
                log::info!("consensus: block tx source = mempool (default)");
                BlockTxSource::Mempool
            }
        };

        // T69.0: Parse DAG template policy from env
        let dag_template_policy = DagTemplatePolicy::from_env();
        log::info!("consensus: dag template policy = {:?}", dag_template_policy);

        // T54/T73.3: choose executor mode/threads from env
        let exec_threads = std::env::var("EEZO_EXECUTOR_THREADS")
            .ok().and_then(|v| v.parse::<usize>().ok())
            .unwrap_or_else(num_cpus::get);
        let exec: Box<dyn Executor> = build_executor(exec_threads);

        // T68.1: Clone the DAG handle for use inside the spawned task
        let dag_c = Arc::clone(&dag);

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
                #[cfg(feature = "metrics")]
                let slot_start = std::time::Instant::now();

                // T70.0: Track DAG prepare time when DAG source is enabled
                #[cfg(feature = "metrics")]
                let dag_prepare_start = std::time::Instant::now();

                // T68.1 + T69.0: If DAG source is selected, try to fetch txs from DAG first.
                // T69.0: Also evaluate the template quality gate if policy is not "off".
                let dag_txs: Option<Vec<SignedTx>> = if matches!(block_tx_source, BlockTxSource::DagCandidate) {
                    // Try to get DAG handle
                    let dag_opt: Option<Arc<DagRunnerHandle>> = dag_c.lock().await.clone();
                    if let Some(dag_handle) = dag_opt {
                        // Read block_byte_budget and snapshot state for dry-run
                        let (block_byte_budget, real_state) = {
                            let guard = node_c.lock().await;
                            let state = (guard.accounts.clone(), guard.supply.clone());
                            (guard.cfg.block_byte_budget, state)
                        };

                        // T69.0: Evaluate template gate before collecting txs
                        let gate_decision = dag_handle.evaluate_template_gate(
                            dag_template_policy,
                            Some(real_state),
                        ).await;

                        match gate_decision {
                            Some(decision) if decision.accept => {
                                // Template passed the gate, collect txs from DAG
                                log::debug!(
                                    "dag_tx_source: template gate accepted (reason={})",
                                    decision.reason
                                );
                                dag_handle.collect_block_txs_from_dag(block_byte_budget).await
                            }
                            Some(decision) => {
                                // Template rejected by gate
                                log::info!(
                                    "dag_tx_source: template gate rejected (reason={})",
                                    decision.reason
                                );
                                #[cfg(feature = "metrics")]
                                crate::metrics::dag_template_gate_rejected_inc();
                                None // Fall back to mempool
                            }
                            None => {
                                // No template available (no DAG candidate)
                                log::debug!("dag_tx_source: no template available for gate evaluation");
                                None // Fall back to mempool
                            }
                        }
                    } else {
                        log::debug!("dag_tx_source: DagCandidate selected but no DAG handle attached");
                        None
                    }
                } else {
                    None
                };

                // T70.0: Record DAG prepare time (only when DAG source is enabled)
                #[cfg(feature = "metrics")]
                if matches!(block_tx_source, BlockTxSource::DagCandidate) {
                    let dag_prepare_elapsed = dag_prepare_start.elapsed().as_secs_f64();
                    crate::metrics::observe_block_dag_prepare_seconds(dag_prepare_elapsed);
                }

                // T70.0: Track executor time
                #[cfg(feature = "metrics")]
                let exec_start = std::time::Instant::now();

                // T54 Step 9: Use the executor instead of run_one_slot
                let outcome: Result<SlotOutcome, eezo_ledger::ConsensusError> = {
                    let mut guard = node_c.lock().await;
                    
                    // Save snapshot for potential rollback
                    let snapshot = if rollback_on_error {
                        Some((
                            guard.accounts.clone(),
                            guard.supply.clone(),
                            guard.height,
                            guard.prev_hash,
                        ))
                    } else {
                        None
                    };
                    
                    // 1–2. Collect transactions for this block from the chosen source.
                    // T68.1: If DAG source is selected and returned txs, use those;
                    // otherwise fall back to mempool.
                    let txs = Self::collect_block_txs_with_dag_fallback(
                        block_tx_source,
                        dag_txs,
                        &mut guard,
                        block_max_tx,
                    );

                    let next_height = guard.height + 1;

                    // 3. Create executor input
                    let exec_input = ExecInput::new(txs, next_height);
                    
                    // 4. Execute block using the executor
                    let exec_outcome = exec.execute_block(&mut guard, exec_input);

                    // T70.0: Record executor time
                    #[cfg(feature = "metrics")]
                    {
                        let exec_elapsed = exec_start.elapsed().as_secs_f64();
                        crate::metrics::observe_block_exec_seconds(exec_elapsed);
                    }

                    // 5. Process outcome
                    match exec_outcome.result {
                        Ok(blk) => {
                            // Apply the block to update node state
                            use eezo_ledger::block::apply_block;
                            let chain_id = guard.cfg.chain_id;

                            // take ownership first (prevents double &mut borrows through guard)
                            let mut accounts = mem::take(&mut guard.accounts);
                            let mut supply   = mem::take(&mut guard.supply);

                            let apply_result = apply_block(chain_id, &mut accounts, &mut supply, &blk);

                            match apply_result {
                                Ok(()) => {
                                    // put the fields back on success
                                    guard.accounts = accounts;
                                    guard.supply   = supply;
                                    
                                    // 2) After successful apply — bump ledger metrics - PATCH C
                                    #[cfg(feature = "metrics")]
                                    {
                                        // Emit block proposal metrics (tx count, fees, etc.)
                                        // This increments eezo_txs_included_total and other legacy counters
                                        // Note: fee_total is u128 but cast to u64 for Prometheus (matches consensus.rs behavior)
                                        ledger_observe_block_proposed(
                                            blk.header.tx_count,
                                            blk.header.fee_total as u64
                                        );
                                        // Emit block applied and supply metrics
                                        ledger_observe_block_applied();
                                        ledger_observe_supply(&guard.supply);
                                    }

                                    // Update node pointers
                                    let curr_hash = blk.header.hash();
                                    guard.height = blk.header.height;
                                    guard.prev_hash = curr_hash;
                                    guard.last_header = Some(blk.header.clone());
                                    guard.last_txs = Some(blk.txs.clone());

                                    Ok(SlotOutcome::Committed { height: blk.header.height })
                                }
                                Err(e) => {
                                    // rollback if needed
                                    if let Some((acc, sup, h, ph)) = snapshot {
                                        guard.accounts = acc;
                                        guard.supply = sup;
                                        guard.height = h;
                                        guard.prev_hash = ph;
                                    } else {
                                        // restore moved-out fields even if no snapshot (no state change applied)
                                        guard.accounts = accounts;
                                        guard.supply   = supply;
                                    }
                                    log::warn!("executor: block apply failed: {:?}", e);
                                    Ok(SlotOutcome::Skipped(NoOpReason::Unknown))
                                }
                            }
                        }
                        Err(e) => {
                            // Rollback if needed
                            if let Some((acc, sup, h, ph)) = snapshot {
                                guard.accounts = acc;
                                guard.supply = sup;
                                guard.height = h;
                                guard.prev_hash = ph;
                            }
                            // Convert the executor's internal String error to a ConsensusError
                            log::warn!("executor: block execution failed: {}", e);
                            Ok(SlotOutcome::Skipped(NoOpReason::Unknown))
                        }
                    }
                };

                #[cfg(feature = "metrics")]
                // FIX: Revert pattern match for time metric to match only height or ignore all fields
                if let Ok(SlotOutcome::Committed { height: _ }) = outcome {
                    let sec = slot_start.elapsed().as_secs_f64();
                    crate::metrics::EEZO_BLOCK_E2E_LATENCY_SECONDS
                        .with_label_values(&["commit"])
                        .observe(sec);
                    // T70.0: Also record total block latency for perf harness
                    crate::metrics::observe_block_total_latency_seconds(sec);
                }				
                match outcome {
                     // FIX: Revert pattern match to only use 'height'
                    Ok(SlotOutcome::Committed { height }) => {
                        
                        // 🚨 NEW LOGIC: Lock the node again to retrieve the recently committed block data
                        // This is necessary because blk/summary are not returned by run_one_slot
                        let blk_opt = {
                            let node_guard = node_c.lock().await;
                            node_guard.last_committed_header()
                                .zip(node_guard.last_committed_txs())
                                .map(|(header, txs)| Block { header, txs })
                        };
                        
                        // --- T51.5a block batching metrics (MOVED HERE) ---
                        // NOTE: eezo_block_tx_count is updated by ledger via observe_block_proposed()
                        #[cfg(feature = "metrics")]
                        {
                            use crate::metrics::{
                                EEZO_BLOCK_FULL_TOTAL,
                                EEZO_BLOCK_UNDERFILLED_TOTAL,
                            };

                            if let Some(ref blk) = blk_opt {
                                let tx_count = blk.txs.len();

                                // Use pre-read block_max_tx
                                if tx_count == block_max_tx {
                                    EEZO_BLOCK_FULL_TOTAL.inc();
                                } else if tx_count > 0 {
                                    EEZO_BLOCK_UNDERFILLED_TOTAL.inc();
                                }
                            }
                        }
                        // --- END METRICS ---

                        // T60.0: block-only shadow tx hash summary (prep for DAG compare)
                        log_block_shadow_debug("dag_shadow_block", height, &blk_opt);

                        // T71.0: GPU hash comparison (optional, controlled by EEZO_NODE_GPU_HASH)
                        // This exercises the GPU hashing path without changing consensus behaviour.
                        let _ = compute_block_body_hash_with_gpu(&blk_opt, height);

                        // update committed height gauge
                        #[cfg(feature = "metrics")]
                        {
                            crate::metrics::EEZO_BLOCK_HEIGHT.set(height as i64);
                        }

                        // capture the committed header hash once, reuse later for checkpoint
                        let mut last_commit_hash_opt: Option<[u8;32]> = None;
                        if log_every == 0 || height % log_every == 0 {
                            log::info!("consensus: committed height={}", height);
                        }
                        // --- FIX: Persist FULL BLOCK ---
                        #[cfg(feature = "persistence")] // Already guarded by function cfg
                        if let Some(ref db_handle) = db_c {

                            // --- Start Replacement ---
                            // Use blk_opt derived above
                            if let Some(ref blk) = blk_opt {
                                // We need hdr and txs for matching the original logic's calls
                                let hdr = &blk.header;

                                if hdr.height == height { // Sanity check height

                                    // 1. Block is already constructed as blk

                                    last_commit_hash_opt = Some(hdr.hash());

                                    // 2. Save the full block AND header (passing blk as the block data)
                                    if let Err(e) = db_handle.put_header_and_block(height, hdr, blk) {
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
                                let committed_header_hash = blk_opt.as_ref().map(|b| b.header.hash()).unwrap_or([0u8;32]);

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
        Arc::new(Self {
            stop,
            node,
            db,
            dag,
            join,
        })
    }
	/// T67.0: attach or clear the DAG runner handle (no behaviour change yet).
    ///
    /// This is called from main.rs once both CoreRunnerHandle and DagRunnerHandle
    /// (if any) have been constructed. For now we only store the handle and log;
    /// the proposer logic does not read it yet.
    pub async fn set_dag_runner(self: &Arc<Self>, dag: Option<Arc<DagRunnerHandle>>) {
        {
            let mut guard = self.dag.lock().await;
            *guard = dag.clone();
        }

        match dag {
            Some(_) => {
                log::info!("consensus: core_runner: dag handle attached");
            }
            None => {
                log::info!("consensus: core_runner: dag handle absent");
            }
        }
    }
    /// Request stop and wait for the loop to finish.
    pub async fn stop(self: &Arc<Self>) {
        // Use Relaxed ordering
        self.stop.store(true, Ordering::Relaxed);
        // Abort the task cooperatively
        self.join.abort();
    }

    /// Access to the inner node for tests / future wiring (use sparingly).
	#[allow(dead_code)]
    pub async fn with_node<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut SingleNode) -> R,
    {
        let mut g = self.node.lock().await;
        f(&mut g)
    }

    /// T66.1: helper to collect block txs for the next block from a given source.
    ///
    /// Today this only supports `BlockTxSource::Mempool` (current behaviour).
    /// Later tasks can extend this to support DAG candidates.
    fn collect_block_txs(
        source: BlockTxSource,
        guard: &mut SingleNode,
        block_max_tx: usize,
    ) -> Vec<SignedTx> {
        match source {
            BlockTxSource::Mempool => {
                Self::collect_from_mempool(guard, block_max_tx)
            }

            BlockTxSource::DagCandidate => {
                // T68.0: For now, DagCandidate is just a thin wrapper over the mempool
                // behaviour. Real DAG-driven tx selection will arrive in T68.1+.
                // NOTE: This path is only used by the non-persistence spawn variant.
                // The persistence-enabled spawn uses collect_block_txs_with_dag_fallback.
                log::debug!("dag_tx_source: DagCandidate mode selected → using mempool (T68.0 stub)");
                Self::collect_from_mempool(guard, block_max_tx)
            }
        }
    }

    /// T68.1: Collect block txs with proper DAG fallback logic.
    ///
    /// If `dag_txs` is Some and non-empty, use those txs (sourced from DAG candidate).
    /// Otherwise, fall back to draining from mempool (same as BlockTxSource::Mempool).
    ///
    /// This function is called from the persistence-enabled spawn path where we can
    /// fetch DAG txs before acquiring the node lock.
    fn collect_block_txs_with_dag_fallback(
        source: BlockTxSource,
        dag_txs: Option<Vec<SignedTx>>,
        guard: &mut SingleNode,
        block_max_tx: usize,
    ) -> Vec<SignedTx> {
        match source {
            BlockTxSource::Mempool => {
                // Pure mempool mode - no DAG involvement
                Self::collect_from_mempool(guard, block_max_tx)
            }

            BlockTxSource::DagCandidate => {
                // T68.1: Check if we got txs from DAG
                if let Some(mut txs) = dag_txs {
                    if !txs.is_empty() {
                        // Apply max_tx cap if configured.
                        // NOTE: Unlike the mempool path, we do NOT need to re-enqueue
                        // overflow txs because the DAG's collect_block_txs_from_dag()
                        // uses get_bytes_for_hashes() which is read-only. The txs are
                        // still in the mempool and will be included in future blocks.
                        if block_max_tx < usize::MAX && txs.len() > block_max_tx {
                            log::debug!(
                                "dag_tx_source: truncating from {} to {} txs (overflow stays in mempool)",
                                txs.len(),
                                block_max_tx
                            );
                            txs.truncate(block_max_tx);
                        }

                        log::info!(
                            "dag_tx_source: using {} tx(s) from DAG candidate",
                            txs.len()
                        );

                        // T68.1: Update metrics - DAG source used
                        #[cfg(feature = "metrics")]
                        crate::metrics::dag_block_source_used_inc();

                        return txs;
                    }
                }

                // T68.1: DAG returned None or empty - fall back to mempool
                log::info!("dag_tx_source: DAG candidate empty/unavailable, falling back to mempool");

                // T68.1: Update metrics - fallback to mempool
                #[cfg(feature = "metrics")]
                crate::metrics::dag_block_source_fallback_inc();

                Self::collect_from_mempool(guard, block_max_tx)
            }
        }
    }

    /// Helper: Drain transactions from mempool with byte budget and max_tx cap.
    fn collect_from_mempool(guard: &mut SingleNode, block_max_tx: usize) -> Vec<SignedTx> {
        let block_byte_budget = guard.cfg.block_byte_budget;
        let mut txs = guard.mempool.drain_for_block(block_byte_budget);

        // Apply max_tx cap if configured, re-enqueue overflow
        if block_max_tx < usize::MAX && txs.len() > block_max_tx {
            let dropped = txs.split_off(block_max_tx);
            for tx in dropped {
                guard.mempool.enqueue_tx(tx);
            }
        }

        txs
    }

    /// T63.1: Get a snapshot of the current accounts and supply for dry-run execution.
    ///
    /// This clones the live ledger state so that dry-run can execute transactions
    /// against the real chain state without modifying it.
    pub async fn snapshot_accounts_supply(&self) -> (eezo_ledger::Accounts, eezo_ledger::Supply) {
        let g = self.node.lock().await;
        (g.accounts.clone(), g.supply.clone())
    }
}

// ============================================================================
// T73.3: Unit Tests for Executor Mode Selection
// ============================================================================

#[cfg(test)]
mod executor_mode_tests {
    use super::ExecutorMode;
    use std::sync::Mutex;
    
    // Mutex to serialize env var access across tests
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_executor_mode_default() {
        assert_eq!(ExecutorMode::default_mode(), ExecutorMode::Parallel);
    }

    #[test]
    fn test_executor_mode_parsing() {
        // Serialize all env var tests to avoid race conditions
        let _guard = ENV_LOCK.lock().unwrap();
        
        // Test single mode
        std::env::set_var("EEZO_EXECUTOR_MODE", "single");
        assert_eq!(ExecutorMode::from_env(), Some(ExecutorMode::Single));
        
        std::env::set_var("EEZO_EXECUTOR_MODE", "s");
        assert_eq!(ExecutorMode::from_env(), Some(ExecutorMode::Single));
        
        std::env::set_var("EEZO_EXECUTOR_MODE", "SINGLE");
        assert_eq!(ExecutorMode::from_env(), Some(ExecutorMode::Single));
        
        // Test parallel mode
        std::env::set_var("EEZO_EXECUTOR_MODE", "parallel");
        assert_eq!(ExecutorMode::from_env(), Some(ExecutorMode::Parallel));
        
        std::env::set_var("EEZO_EXECUTOR_MODE", "p");
        assert_eq!(ExecutorMode::from_env(), Some(ExecutorMode::Parallel));
        
        std::env::set_var("EEZO_EXECUTOR_MODE", "PARALLEL");
        assert_eq!(ExecutorMode::from_env(), Some(ExecutorMode::Parallel));
        
        // Test STM mode
        std::env::set_var("EEZO_EXECUTOR_MODE", "stm");
        assert_eq!(ExecutorMode::from_env(), Some(ExecutorMode::Stm));
        
        std::env::set_var("EEZO_EXECUTOR_MODE", "block-stm");
        assert_eq!(ExecutorMode::from_env(), Some(ExecutorMode::Stm));
        
        std::env::set_var("EEZO_EXECUTOR_MODE", "STM");
        assert_eq!(ExecutorMode::from_env(), Some(ExecutorMode::Stm));
        
        // Test unknown values
        std::env::set_var("EEZO_EXECUTOR_MODE", "unknown");
        assert_eq!(ExecutorMode::from_env(), None);
        
        std::env::set_var("EEZO_EXECUTOR_MODE", "");
        assert_eq!(ExecutorMode::from_env(), None);
        
        // Test unset
        std::env::remove_var("EEZO_EXECUTOR_MODE");
        assert_eq!(ExecutorMode::from_env(), None);
    }
}