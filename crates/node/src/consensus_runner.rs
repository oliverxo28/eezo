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

// T75.0: Import shadow DAG types when dag-consensus feature is enabled
#[cfg(feature = "dag-consensus")]
use crate::dag_consensus_runner::ShadowBlockSummary;

// T76.1: Import HybridDagHandle for hybrid mode
#[cfg(feature = "dag-consensus")]
use crate::dag_consensus_runner::HybridDagHandle;

// T76.5: HybridBatchStats — statistics for structured logging per batch
#[cfg(feature = "dag-consensus")]
#[derive(Debug, Clone, Default)]
pub struct HybridBatchStats {
    /// Total number of tx hashes in the original batch
    pub n: usize,
    /// Number of hashes filtered by de-dup (already committed)
    pub filtered_seen: usize,
    /// Number of candidate hashes after de-dup filtering
    pub candidate: usize,
    /// Number of transactions with bytes successfully used (decoded)
    pub used: usize,
    /// Number of transactions dropped by nonce prefilter
    pub bad_nonce_pref: usize,
    /// Number of tx hashes with missing bytes
    pub missing: usize,
    /// Number of decode errors
    pub decode_err: usize,
    /// Total size in bytes of decoded transactions
    pub size_bytes: usize,
    /// T76.7: Number of batches aggregated for this block
    pub agg_batches: usize,
    /// T76.7: Total candidate count before dedup/nonce filtering (across all aggregated batches)
    pub agg_candidates: usize,
}

#[cfg(feature = "dag-consensus")]
impl HybridBatchStats {
    /// Format the stats as the required structured log line per T76.5 spec.
    /// T76.7: Now includes agg_batches and agg_candidates.
    pub fn to_log_string(&self, apply_ok: usize, apply_fail: usize) -> String {
        format!(
            "hybrid: n={} filtered_seen={} candidate={} used={} bad_nonce_pref={} missing={} decode_err={} apply_ok={} apply_fail={} size_bytes={} agg_batches={} agg_candidates={}",
            self.n,
            self.filtered_seen,
            self.candidate,
            self.used,
            self.bad_nonce_pref,
            self.missing,
            self.decode_err,
            apply_ok,
            apply_fail,
            self.size_bytes,
            self.agg_batches,
            self.agg_candidates
        )
    }
}

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

/// T76.9 — Helper: decode tx bytes using fast decode pool if enabled.
/// 
/// When `EEZO_FAST_DECODE_ENABLED=true`, uses the global decode pool with caching.
/// Otherwise, falls back to direct parsing.
/// 
/// Note: Returns a cloned SignedTx for backward compatibility with existing code
/// that expects owned values. For true zero-copy, use the decode pool directly
/// and work with Arc<DecodedTx>.
#[cfg(all(feature = "dag-consensus", feature = "pq44-runtime"))]
fn decode_tx_from_envelope_bytes(bytes: &[u8]) -> Option<SignedTx> {
    if crate::tx_decode_pool::is_fast_decode_enabled() {
        crate::tx_decode_pool::decode_tx_global(bytes)
            .map(|arc_decoded| arc_decoded.tx.clone())
    } else {
        crate::dag_runner::parse_signed_tx_from_envelope(bytes)
    }
}

/// T76.9 — Fallback for when pq44-runtime is not enabled but dag-consensus is.
/// This just uses the direct parsing without the decode pool.
#[cfg(all(feature = "dag-consensus", not(feature = "pq44-runtime")))]
fn decode_tx_from_envelope_bytes(bytes: &[u8]) -> Option<SignedTx> {
    crate::dag_runner::parse_signed_tx_from_envelope(bytes)
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
/// - T82.4b: When `stm-exec` feature is enabled and EEZO_EXECUTOR_MODE is not set,
///   defaults to STM executor to ensure STM metrics are recorded.
/// - Logs the selected mode at startup.
fn build_executor(threads: usize) -> Box<dyn Executor> {
    let env_val = std::env::var("EEZO_EXECUTOR_MODE").ok();
    let mode = match &env_val {
        Some(v) => {
            match ExecutorMode::from_env() {
                Some(m) => m,
                None => {
                    // When unrecognized, fall back to default_mode (Parallel)
                    log::warn!(
                        "executor: EEZO_EXECUTOR_MODE='{}' is not recognized, using default: parallel",
                        v
                    );
                    ExecutorMode::default_mode()
                }
            }
        }
        None => {
            // T82.4b: When stm-exec feature is enabled, default to STM executor
            // This ensures the STM code path (with T82.0/T82.4 metrics) is used
            #[cfg(feature = "stm-exec")]
            {
                log::info!("executor: EEZO_EXECUTOR_MODE not set, defaulting to STM (stm-exec feature enabled)");
                ExecutorMode::Stm
            }
            #[cfg(not(feature = "stm-exec"))]
            {
                log::info!("executor: EEZO_EXECUTOR_MODE not set, using default: parallel");
                ExecutorMode::default_mode()
            }
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

// T90.0: GPU hash diagnostic (non-consensus)
use crate::gpu_hash::{is_gpu_hash_enabled, hash_batch_with_gpu_check};

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

// T83.2: Async persistence imports
#[cfg(feature = "persistence")]
use crate::persistence_worker::{
    is_async_persist_enabled, log_async_persist_status,
    BlockWriteSet, CommittedMemHead, PersistenceWorker, PersistenceWorkerHandle,
};

// T83.3: Block execution pipelining imports
use crate::block_pipeline::{
    is_pipeline_enabled, log_pipeline_status,
    BlockPipeline, PreparedBlock,
};

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

/// T82.2d: Helper to increment mempool actor metrics on block commit.
///
/// Increments `eezo_mempool_batches_served_total` when:
/// 1. The mempool actor is enabled (EEZO_MEMPOOL_ACTOR_ENABLED=1)
/// 2. The committed block contains at least one transaction
///
/// In this context, a "batch" represents the set of transactions included in a
/// single committed block. The metric counts committed blocks with transactions,
/// which correlates with the number of times the mempool served transactions
/// for block building.
#[cfg(feature = "metrics")]
#[inline]
fn record_mempool_batch_served_if_enabled(tx_count: u32) {
    if crate::mempool_actor::is_mempool_actor_enabled() && tx_count > 0 {
        crate::metrics::mempool_batches_served_inc();
    }
}

/// T76.1/T78.3: Consensus mode enum for determining tx source behavior.
/// This is separate from the top-level ConsensusMode in main.rs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum HybridModeConfig {
    /// Standard mode: use mempool or DAG candidate as tx source
    Standard,
    /// Hybrid mode with DAG ordering enabled: try DAG batches first
    HybridEnabled,
    /// T78.3: DAG-primary mode: DAG is the only source, no mempool fallback
    DagPrimary,
}

/// T78.7: Helper to check if DAG ordering is enabled from environment.
/// Respects the devnet-safe feature for default value.
/// This is used for logging purposes in consensus_runner.
#[inline]
fn dag_ordering_enabled_from_env() -> bool {
    // T78.7: Default depends on build profile
    #[cfg(feature = "devnet-safe")]
    let default_enabled = true;
    #[cfg(not(feature = "devnet-safe"))]
    let default_enabled = false;

    match std::env::var("EEZO_DAG_ORDERING_ENABLED") {
        Ok(v) => {
            let s = v.trim().to_ascii_lowercase();
            match s.as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => default_enabled,
            }
        }
        Err(_) => default_enabled,
    }
}

impl HybridModeConfig {
    /// Parse hybrid mode configuration from environment.
    fn from_env() -> Self {
        // Check consensus mode
        let mode = std::env::var("EEZO_CONSENSUS_MODE")
            .unwrap_or_default()
            .to_ascii_lowercase();
        
        // T78.3: Check for dag-primary mode first
        if mode == "dag-primary" || mode == "dag_primary" {
            return HybridModeConfig::DagPrimary;
        }
        
        // T78.7: In devnet-safe builds with empty/unset mode, default to DagPrimary
        #[cfg(feature = "devnet-safe")]
        if mode.is_empty() {
            return HybridModeConfig::DagPrimary;
        }
        
        let is_dag_hybrid = mode == "dag-hybrid" || mode == "dag_hybrid";
        
        let ordering_enabled = dag_ordering_enabled_from_env();
        
        if is_dag_hybrid && ordering_enabled {
            HybridModeConfig::HybridEnabled
        } else {
            HybridModeConfig::Standard
        }
    }
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
    // T83.2: Async persistence - CommittedMemHead for read-after-write consistency
    #[cfg(feature = "persistence")]
    #[allow(dead_code)]
    mem_head: Arc<CommittedMemHead>,
    // T83.2: Async persistence - worker handle for background RocksDB writes
    #[cfg(feature = "persistence")]
    #[allow(dead_code)]
    persist_worker: Option<PersistenceWorkerHandle>,
    // T67.0: optional DAG runner handle for future DAG-aware block building
    // Stored behind a Mutex so we can attach it after construction.
    #[allow(dead_code)]
    dag: Arc<Mutex<Option<Arc<DagRunnerHandle>>>>,
    // T75.0: optional shadow DAG sender for feeding committed blocks to shadow consensus
    // Stored behind a Mutex so we can attach it after construction.
    #[cfg(feature = "dag-consensus")]
    shadow_dag_sender: Arc<Mutex<Option<tokio::sync::mpsc::Sender<ShadowBlockSummary>>>>,
    // T76.1: optional hybrid DAG handle for consuming ordered batches.
    // TODO(T76.2): Wire this into the main consensus loop to try consuming
    // ordered batches from DAG before falling back to mempool. Currently
    // the handle is stored but not used until the full hybrid integration.
    #[cfg(feature = "dag-consensus")]
    #[allow(dead_code)]
    hybrid_dag: Arc<Mutex<Option<Arc<HybridDagHandle>>>>,
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
        // T75.0: start with no shadow DAG sender; it can be attached later
        #[cfg(feature = "dag-consensus")]
        let shadow_dag_sender = Arc::new(Mutex::new(None));
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
        // T75.0: Clone shadow DAG sender for use inside the spawned task
        #[cfg(feature = "dag-consensus")]
        let shadow_dag_c = Arc::clone(&shadow_dag_sender);
        
        // T76.1/T78.3: Parse hybrid mode configuration (non-persistence variant)
        let hybrid_mode_cfg = HybridModeConfig::from_env();
        match hybrid_mode_cfg {
            HybridModeConfig::HybridEnabled => {
                log::info!("consensus: hybrid mode enabled with DAG ordering (non-persistence variant)");
            }
            HybridModeConfig::DagPrimary => {
                log::info!("consensus: dag-primary mode enabled (DAG-only, no mempool fallback)");
            }
            HybridModeConfig::Standard => {
                // No special logging for standard mode
            }
        }

        let join = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(tick_ms.max(1)));
			// expose T36.6 bridge metrics on /metrics immediately
			#[cfg(feature = "metrics")]
			register_t36_bridge_metrics();
            
            // T81.1: Log consensus mode at startup (non-persistence variant)
            #[cfg(feature = "dag-consensus")]
            {
                let dag_ordering_enabled = dag_ordering_enabled_from_env();
                log::info!(
                    "consensus: mode={:?}, dag_ordering_enabled={} (non-persistence)",
                    hybrid_mode_cfg, dag_ordering_enabled
                );
            }
            // Suppress unused variable warning when dag-consensus feature is off
            #[cfg(not(feature = "dag-consensus"))]
            let _ = hybrid_mode_cfg;
            
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
                
                // T76.1: Hybrid mode is parsed but not wired in non-persistence variant.
                // This variant is primarily for testing without DB. In production,
                // the persistence-enabled variant handles hybrid consumption.

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
                                        
                                        // T82.2d: Increment mempool batch metric on block commit
                                        record_mempool_batch_served_if_enabled(blk.header.tx_count);
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
                            
                            // T82.2c: Reset in-flight count after block is committed.
                            // This reflects that txs are no longer in-flight (they've been included).
                            if crate::mempool_actor::is_mempool_actor_enabled() {
                                crate::metrics::mempool_inflight_len_set(0);
                            }
                        }
                        // --- END METRICS ---

                        // T60.0: block-only shadow tx hash summary (prep for DAG compare)
                        log_block_shadow_debug("dag_shadow_block", height, &blk_opt);

                        // T71.0: GPU hash comparison (optional, controlled by EEZO_NODE_GPU_HASH)
                        // This exercises the GPU hashing path without changing consensus behaviour.
                        let _ = compute_block_body_hash_with_gpu(&blk_opt, height);

                        // T90.0b: GPU hash diagnostic (non-consensus, feature-gated)
                        // Runs regardless of persistence feature to exercise GPU path in
                        // DagPrimary + STM mode without persistence.
                        // Uses EEZO_GPU_HASH_ENABLED=1 to enable.
                        if is_gpu_hash_enabled() {
                            if let Some(ref blk) = blk_opt {
                                if !blk.txs.is_empty() {
                                    let tx_bytes: Vec<Vec<u8>> = blk.txs.iter()
                                        .map(|tx| tx.to_bytes())
                                        .collect();
                                    // hash_batch_with_gpu_check computes CPU hashes,
                                    // compares with GPU if available, and logs mismatches.
                                    // Result is discarded: this is diagnostic only.
                                    let _ = hash_batch_with_gpu_check(&tx_bytes);
                                    log::debug!(
                                        "T90.0b: GPU hash diagnostic ran for block h={} ({} txs)",
                                        height, tx_bytes.len()
                                    );
                                }
                            }
                        }

                        // T75.0: Send committed block to shadow DAG (if enabled)
                        // This must not block or affect the main consensus path.
                        #[cfg(feature = "dag-consensus")]
                        {
                            if let Some(ref blk) = blk_opt {
                                // Try to get the shadow DAG sender
                                let sender_opt: Option<tokio::sync::mpsc::Sender<ShadowBlockSummary>> = 
                                    shadow_dag_c.lock().await.clone();
                                if let Some(sender) = sender_opt {
                                    // Build the summary
                                    let block_hash = blk.header.hash();
                                    let tx_hashes: Vec<[u8; 32]> = blk.txs.iter().map(|tx| tx.hash()).collect();
                                    let summary = ShadowBlockSummary {
                                        height,
                                        block_hash,
                                        tx_hashes,
                                        tx_bytes: None, // T76.3: Will be populated when available
                                        round: None,
                                        timestamp_ms: Some(blk.header.timestamp_ms),
                                    };

                                    // Send non-blocking; log warning if channel is full/closed
                                    if let Err(e) = sender.try_send(summary) {
                                        log::warn!(
                                            "dag-consensus: shadow send failed at height={}: {}",
                                            height, e
                                        );
                                    }
                                }
                            }
                        }

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
                                        // T90.0b: GPU hash diagnostic moved outside persistence guard.
                                        // See T90.0b block above (runs regardless of persistence feature).
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
            // T83.2: Create empty CommittedMemHead (disabled for non-persistence variant)
            #[cfg(feature = "persistence")]
            mem_head: Arc::new(CommittedMemHead::new()),
            #[cfg(feature = "persistence")]
            persist_worker: None,
            dag,
            #[cfg(feature = "dag-consensus")]
            shadow_dag_sender,
            #[cfg(feature = "dag-consensus")]
            hybrid_dag: Arc::new(Mutex::new(None)),
            join,
        })
    }

    /// Spawn variant when persistence is available: pass `Some(db)` to enable real roots.
    #[cfg(feature = "persistence")]
    pub fn spawn(node: SingleNode, db: Option<Arc<Persistence>>, tick_ms: u64, rollback_on_error: bool) -> Arc<Self> {
        // T76.6: Capture the initial committed height before the node is wrapped in Arc<Mutex<_>>.
        // This is used to set node_start_round for stale batch detection.
        #[cfg(feature = "dag-consensus")]
        let initial_committed_height = node.height;
        
        let stop = Arc::new(AtomicBool::new(false));
        let node = Arc::new(Mutex::new(node));
        let stop_c = Arc::clone(&stop);
        let node_c = Arc::clone(&node);
        let db_c = db.clone();
        // T67.0: start with no DAG handle; it can be attached later
        let dag = Arc::new(Mutex::new(None));
        // T75.0: start with no shadow DAG sender; it can be attached later
        #[cfg(feature = "dag-consensus")]
        let shadow_dag_sender = Arc::new(Mutex::new(None));
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
        // T75.0: Clone shadow DAG sender for use inside the spawned task
        #[cfg(feature = "dag-consensus")]
        let shadow_dag_c = Arc::clone(&shadow_dag_sender);
        
        // T76.1/T78.3: Parse hybrid mode configuration and create hybrid_dag handle container
        let hybrid_mode_cfg = HybridModeConfig::from_env();
        #[cfg(feature = "dag-consensus")]
        let hybrid_dag_store: Arc<Mutex<Option<Arc<HybridDagHandle>>>> = Arc::new(Mutex::new(None));
        #[cfg(feature = "dag-consensus")]
        let hybrid_dag_c = Arc::clone(&hybrid_dag_store);
        match hybrid_mode_cfg {
            HybridModeConfig::HybridEnabled => {
                log::info!("consensus: hybrid mode enabled with DAG ordering");
            }
            HybridModeConfig::DagPrimary => {
                log::info!("consensus: dag-primary mode enabled (DAG-only, no mempool fallback)");
            }
            HybridModeConfig::Standard => {
                // No special logging for standard mode
            }
        }

        // T76.5: Create the de-dup LRU cache for filtering already-committed tx hashes.
        // This is created once before the loop and shared across all iterations.
        #[cfg(feature = "dag-consensus")]
        let hybrid_dedup_cache = Arc::new(crate::dag_consensus_runner::HybridDedupCache::new());
        #[cfg(feature = "dag-consensus")]
        {
            let cache_size = hybrid_dedup_cache.capacity();
            log::info!("consensus: hybrid de-dup LRU cache initialized (capacity={})", cache_size);
        }

        // T76.6/T78.3: Set node_start_round watermark for stale batch detection.
        // initial_committed_height was captured before the node was wrapped in Arc<Mutex<_>>.
        #[cfg(feature = "dag-consensus")]
        if matches!(hybrid_mode_cfg, HybridModeConfig::HybridEnabled | HybridModeConfig::DagPrimary) {
            // Set node_start_round to the committed height at startup.
            // Any DAG batch with round <= this value is considered stale.
            hybrid_dedup_cache.set_node_start_round(initial_committed_height);
        }

        // T83.2: Initialize async persistence components
        log_async_persist_status();
        let async_persist_enabled = is_async_persist_enabled();
        let mem_head = Arc::new(CommittedMemHead::new());
        let persist_worker = if async_persist_enabled {
            if let Some(ref db_ref) = db {
                mem_head.set_enabled(true);
                log::info!("consensus: async persistence enabled, spawning worker");
                Some(PersistenceWorker::spawn(db_ref.clone(), mem_head.clone()))
            } else {
                log::warn!("consensus: async persistence requested but no DB handle available");
                None
            }
        } else {
            None
        };
        // T83.2: Clone async persistence handles for use in spawned task
        let mem_head_c = mem_head.clone();
        let async_persist_enabled_c = async_persist_enabled;
        // Clone the persist_worker for use in the spawned task
        let persist_worker_c = persist_worker.clone();

        // T83.3: Create block execution pipeline
        let pipeline_enabled = is_pipeline_enabled();
        let pipeline = BlockPipeline::new();
        let pipeline_state = pipeline.state();

        let join = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(tick_ms.max(1)));
			// expose T36.6 bridge metrics on /metrics immediately
			#[cfg(feature = "metrics")]
			register_t36_bridge_metrics();
            // T77.1/T78.3: Register DAG ordering latency metrics for hybrid and dag-primary modes
            #[cfg(all(feature = "metrics", feature = "dag-consensus"))]
            if matches!(hybrid_mode_cfg, HybridModeConfig::HybridEnabled | HybridModeConfig::DagPrimary) {
                crate::metrics::register_t77_dag_ordering_latency_metrics();
            }
            
            // T83.3: Log pipeline status
            log_pipeline_status();
            
            // T81.1: Log consensus mode at startup (persistence variant)
            #[cfg(feature = "dag-consensus")]
            {
                let dag_ordering_enabled = dag_ordering_enabled_from_env();
                log::info!(
                    "consensus: mode={:?}, dag_ordering_enabled={}, pipeline_enabled={}",
                    hybrid_mode_cfg, dag_ordering_enabled, pipeline_enabled
                );
            }
            
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
                
                // T76.12: Feed hybrid DAG with pending mempool transactions BEFORE consuming.
                // This is the key fix: submit pending txs at the START of each tick,
                // so that the DAG can order them and provide batches for block building.
                #[cfg(feature = "dag-consensus")]
                if matches!(hybrid_mode_cfg, HybridModeConfig::HybridEnabled | HybridModeConfig::DagPrimary) {
                    let hybrid_opt: Option<Arc<HybridDagHandle>> = hybrid_dag_c.lock().await.clone();
                    if let Some(hybrid_handle) = hybrid_opt {
                        // Get DAG runner handle for mempool access
                        let dag_opt: Option<Arc<DagRunnerHandle>> = dag_c.lock().await.clone();
                        if let Some(dag_handle) = dag_opt {
                            // Sample pending tx hashes from mempool.
                            // Use the same max_tx as aggregation config to ensure consistency
                            // between how many txs the DAG orders and how many can be consumed.
                            let agg_config = crate::adaptive_agg::adaptive_agg_config();
                            let max_txs_to_sample = agg_config.max_tx();
                            
                            // Get pending tx hashes from the shared mempool via DAG runner
                            let pending_hashes = dag_handle.sample_pending_tx_hashes(max_txs_to_sample).await;
                            
                            if !pending_hashes.is_empty() {
                                // Submit pending txs to the hybrid DAG
                                match hybrid_handle.submit_pending_txs(&pending_hashes, None) {
                                    Ok(count) => {
                                        log::debug!(
                                            "dag-hybrid: fed {} pending tx hashes to DAG for ordering",
                                            count
                                        );
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "dag-hybrid: failed to submit pending txs: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                
                // T76.3: Try hybrid batch consumption when in hybrid mode with ordering enabled.
                // When a batch is available with tx bytes, decode directly from bytes.
                // For any entries missing bytes, fall back to mempool lookup per-entry.
                // T76.7: Now uses multi-batch aggregation with configurable time budget.
                #[cfg(feature = "dag-consensus")]
                let mut hybrid_batch_used = false;
                #[cfg(feature = "dag-consensus")]
                let mut hybrid_aggregated_txs: Vec<SignedTx> = Vec::new();
                #[cfg(feature = "dag-consensus")]
                let mut hybrid_aggregated_stats: Option<HybridBatchStats> = None;
                // T76.5: Track de-dup and nonce prefilter statistics per batch
                #[cfg(feature = "dag-consensus")]
                let mut hybrid_filtered_seen: usize = 0;
                #[cfg(feature = "dag-consensus")]
                let mut hybrid_candidate_count: usize = 0;
                #[cfg(feature = "dag-consensus")]
                let mut hybrid_bad_nonce_prefilter: usize = 0;
                #[cfg(feature = "dag-consensus")]
                if matches!(hybrid_mode_cfg, HybridModeConfig::HybridEnabled | HybridModeConfig::DagPrimary) {
                    // T76.10/T78.3: Use adaptive aggregation config for time budget and soft caps.
                    // If EEZO_HYBRID_AGG_TIME_BUDGET_MS is set, use fixed budget.
                    // Otherwise, use adaptive calculation based on executor latency.
                    let agg_config = crate::adaptive_agg::adaptive_agg_config();
                    let agg_time_budget_ms = agg_config.current_time_budget_ms();
                    let agg_max_tx = agg_config.max_tx();
                    let agg_max_bytes = agg_config.max_bytes();
                    
                    // T76.12: Get min DAG threshold and batch timeout
                    let min_dag_tx = agg_config.min_dag_tx();
                    let batch_timeout_ms = agg_config.batch_timeout_ms();
                    
                    // T76.10: Update metrics for adaptive mode status
                    crate::metrics::observe_hybrid_agg_adaptive_enabled(agg_config.is_adaptive());
                    crate::metrics::observe_hybrid_agg_time_budget_ms(agg_time_budget_ms);
                    
                    // Try to get hybrid DAG handle
                    let hybrid_opt: Option<Arc<HybridDagHandle>> = hybrid_dag_c.lock().await.clone();
                    if let Some(hybrid_handle) = hybrid_opt {
                        // T76.12: Implement waiting logic for min_dag_tx and batch_timeout_ms
                        // If min_dag_tx > 0 and batch_timeout_ms > 0, wait for batches with timeout.
                        let wait_start = std::time::Instant::now();
                        let wait_timeout = std::time::Duration::from_millis(batch_timeout_ms);
                        let mut waited_for_batches = false;
                        
                        // T76.12: Should we wait for DAG batches before proceeding?
                        // Wait is only enabled if both min_dag_tx and batch_timeout_ms are > 0.
                        let should_wait_for_batches = min_dag_tx > 0 && batch_timeout_ms > 0;
                        
                        // If we need to wait for DAG batches and no batches are immediately available
                        if should_wait_for_batches && hybrid_handle.peek_ordered_queue_len() == 0 {
                            log::debug!(
                                "hybrid: waiting for DAG batches (min_dag_tx={}, timeout_ms={})",
                                min_dag_tx, batch_timeout_ms
                            );
                            
                            // Poll loop: wait until timeout or batches arrive.
                            // Uses 1ms polling interval which is appropriate for 10-20ms timeouts.
                            // This is a short-lived loop (max batch_timeout_ms iterations).
                            loop {
                                if hybrid_handle.peek_ordered_queue_len() > 0 {
                                    // Batches arrived
                                    waited_for_batches = true;
                                    log::debug!("hybrid: batches arrived after {:?}", wait_start.elapsed());
                                    break;
                                }
                                
                                if wait_start.elapsed() >= wait_timeout {
                                    // Timeout expired
                                    log::debug!("hybrid: timeout expired after {:?}, falling back", wait_start.elapsed());
                                    break;
                                }
                                
                                // Sleep for 1ms between polls (avoid busy-wait).
                                // 1ms granularity is appropriate for typical 10-20ms timeouts.
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                            }
                        }
                        
                        // T76.7: Check if any batches are available (after potential wait)
                        if hybrid_handle.peek_ordered_queue_len() > 0 {
                            // Get DAG runner handle for mempool access (needed by aggregation function)
                            let dag_opt: Option<Arc<DagRunnerHandle>> = dag_c.lock().await.clone();
                            
                            // Read block_byte_budget for aggregation, apply soft cap
                            let block_byte_budget = {
                                let guard = node_c.lock().await;
                                guard.cfg.block_byte_budget.min(agg_max_bytes)
                            };
                            
                            // Get account snapshot for nonce checking
                            let accounts = {
                                let guard = node_c.lock().await;
                                guard.accounts.clone()
                            };
                            
                            // T76.10: Use multi-batch aggregation with adaptive time budget and soft caps
                            let (agg_txs, agg_stats, cap_reason) = Self::collect_txs_from_aggregated_batches_with_caps(
                                &hybrid_handle,
                                dag_opt,
                                block_byte_budget,
                                &hybrid_dedup_cache,
                                &accounts,
                                agg_time_budget_ms,
                                agg_max_tx,
                                agg_max_bytes,
                            ).await;
                            
                            // T76.10: Record cap reason in metrics
                            crate::metrics::observe_hybrid_agg_cap_reason(cap_reason.as_str());
                            
                            if agg_stats.agg_batches > 0 {
                                hybrid_filtered_seen = agg_stats.filtered_seen;
                                hybrid_candidate_count = agg_stats.candidate;
                                hybrid_bad_nonce_prefilter = agg_stats.bad_nonce_pref;
                                
                                // T76.12: Check if we met the min_dag_tx threshold
                                let dag_tx_count = agg_txs.len();
                                
                                if dag_tx_count >= min_dag_tx || min_dag_tx == 0 {
                                    // Met threshold (or threshold disabled) - use DAG txs
                                    if !agg_txs.is_empty() {
                                        hybrid_aggregated_txs = agg_txs;
                                        hybrid_aggregated_stats = Some(agg_stats);
                                        hybrid_batch_used = true;
                                        crate::metrics::dag_hybrid_batches_used_inc();
                                        
                                        // T77.1: Record DAG ordering latency (time from wait start to successful batch consumption)
                                        let ordering_latency_secs = wait_start.elapsed().as_secs_f64();
                                        crate::metrics::observe_dag_ordering_latency_seconds(ordering_latency_secs);
                                        
                                        // T78.1: Enhanced logging for hybrid aggregation with strict profile status
                                        let strict_profile_str = if crate::adaptive_agg::is_strict_profile_enabled() {
                                            "strict_profile=on"
                                        } else {
                                            "strict_profile=off"
                                        };
                                        
                                        log::info!(
                                            "T78.1 hybrid-agg: time_budget_ms={} batches={} candidates={} used={} cap_reason={} {}",
                                            agg_time_budget_ms,
                                            hybrid_aggregated_stats.as_ref().map(|s| s.agg_batches).unwrap_or(0),
                                            hybrid_aggregated_stats.as_ref().map(|s| s.agg_candidates).unwrap_or(0),
                                            hybrid_aggregated_txs.len(),
                                            cap_reason.as_str(),
                                            strict_profile_str
                                        );
                                    } else {
                                        // Batches consumed but no valid txs - store stats for logging
                                        hybrid_aggregated_stats = Some(agg_stats);
                                        log::debug!("hybrid-agg: batches consumed but no valid txs after filtering");
                                        // T76.12/T78.4: Fallback with reason=empty (not in dag-primary mode)
                                        if !matches!(hybrid_mode_cfg, HybridModeConfig::DagPrimary) {
                                            crate::metrics::dag_hybrid_fallback_reason_inc("empty");
                                        }
                                    }
                                } else {
                                    // T76.12/T78.4: Did not meet min_dag_tx threshold - fallback (not in dag-primary mode)
                                    log::debug!(
                                        "hybrid: fallback (reason=min_dag_not_met, got {} < min {})",
                                        dag_tx_count, min_dag_tx
                                    );
                                    hybrid_aggregated_stats = Some(agg_stats);
                                    if !matches!(hybrid_mode_cfg, HybridModeConfig::DagPrimary) {
                                        crate::metrics::dag_hybrid_fallback_reason_inc("min_dag_not_met");
                                    }
                                }
                            } else {
                                // No batches consumed - fallback (not in dag-primary mode)
                                log::debug!("hybrid: fallback (reason=no_batches_aggregated)");
                                if !matches!(hybrid_mode_cfg, HybridModeConfig::DagPrimary) {
                                    crate::metrics::dag_hybrid_fallback_reason_inc("empty");
                                }
                            }
                        } else {
                            // No batches ready after potential wait - fallback (not in dag-primary mode)
                            if should_wait_for_batches {
                                // We were configured to wait but nothing came - timeout fallback
                                log::debug!("hybrid: fallback (reason=timeout, waited {:?})", wait_start.elapsed());
                                if !matches!(hybrid_mode_cfg, HybridModeConfig::DagPrimary) {
                                    crate::metrics::dag_hybrid_fallback_reason_inc("timeout");
                                }
                            } else {
                                // No wait configured and no batches - queue empty
                                log::debug!("hybrid: fallback (reason=queue_empty)");
                                if !matches!(hybrid_mode_cfg, HybridModeConfig::DagPrimary) {
                                    crate::metrics::dag_hybrid_fallback_reason_inc("queue_empty");
                                }
                            }
                            // T76.10: Record empty cap reason
                            crate::metrics::observe_hybrid_agg_cap_reason("empty");
                        }
                    } else {
                        // No hybrid handle attached yet - fallback (not in dag-primary mode)
                        log::debug!("hybrid: fallback (reason=no_handle)");
                        if !matches!(hybrid_mode_cfg, HybridModeConfig::DagPrimary) {
                            crate::metrics::dag_hybrid_fallback_reason_inc("no_handle");
                        }
                    }
                }

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
                
                // T76.5: Track hybrid batch stats for structured logging
                #[cfg(feature = "dag-consensus")]
                let mut hybrid_stats_opt: Option<HybridBatchStats> = None;

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
                    // T76.7: If hybrid batch aggregation succeeded, use the pre-aggregated transactions.
                    // Otherwise, fall back to DAG source or mempool as before.
                    #[cfg(feature = "dag-consensus")]
                    let txs = if hybrid_batch_used {
                        // T76.7: Use the pre-aggregated transactions from multi-batch aggregation
                        if !hybrid_aggregated_txs.is_empty() {
                            // Store stats for structured logging after execution
                            hybrid_stats_opt = hybrid_aggregated_stats.clone();
                            
                            // T76.7: Update metrics from aggregated stats
                            if let Some(ref stats) = hybrid_stats_opt {
                                crate::metrics::dag_hybrid_hashes_total_inc_by(stats.n as u64);
                                crate::metrics::dag_hybrid_hashes_resolved_inc_by(stats.used as u64);
                                crate::metrics::dag_hybrid_hashes_missing_inc_by(stats.missing as u64);
                                crate::metrics::dag_hybrid_decode_errors_inc_by(stats.decode_err as u64);
                                // Legacy metrics for backwards compatibility
                                crate::metrics::dag_hybrid_bytes_used_inc_by(stats.used as u64);
                                crate::metrics::dag_hybrid_bytes_missing_inc_by(stats.missing as u64);
                                crate::metrics::dag_hybrid_decode_error_inc_by(stats.decode_err as u64);
                            }
                            
                            hybrid_aggregated_txs
                        } else {
                            // Batches were consumed but no valid txs - fallback logic
                            hybrid_stats_opt = hybrid_aggregated_stats.clone();
                            
                            // T78.3: In DagPrimary mode, never fall back to mempool
                            let is_dag_primary = matches!(hybrid_mode_cfg, HybridModeConfig::DagPrimary);
                            
                            if let Some(ref stats) = hybrid_stats_opt {
                                // T76.6: Determine the reason for empty candidates and log appropriately
                                crate::metrics::dag_hybrid_empty_candidates_inc();
                                
                                if stats.decode_err > 0 {
                                    log::warn!(
                                        "hybrid-agg: aggregation failed with decode errors (reason=decode-errors, n={} decode_err={})",
                                        stats.n, stats.decode_err
                                    );
                                    if is_dag_primary {
                                        log::info!("dag-primary: no fallback to mempool, continuing with empty block");
                                        Vec::new()
                                    } else {
                                        // T78.4: Only increment fallback counter in dag-hybrid mode
                                        crate::metrics::dag_hybrid_fallback_inc();
                                        Self::collect_from_mempool(&mut guard, block_max_tx)
                                    }
                                } else if stats.filtered_seen == stats.n && stats.n > 0 {
                                    log::info!(
                                        "hybrid-agg: all batches filtered (reason=dedup-all, n={} filtered_seen={})",
                                        stats.n, stats.filtered_seen
                                    );
                                    crate::metrics::dag_hybrid_all_filtered_inc();
                                    let mempool_len = guard.mempool.len();
                                    if mempool_len == 0 || is_dag_primary {
                                        log::info!("hybrid-agg: no-candidates-mempool-empty, continuing without fallback");
                                        Vec::new()
                                    } else {
                                        // T78.4: Only increment fallback counter in dag-hybrid mode
                                        crate::metrics::dag_hybrid_fallback_inc();
                                        Self::collect_from_mempool(&mut guard, block_max_tx)
                                    }
                                } else {
                                    let mempool_len = guard.mempool.len();
                                    if mempool_len == 0 || is_dag_primary {
                                        log::info!(
                                            "hybrid-agg: no candidates (reason={}, n={} filtered={} bad_nonce={})",
                                            if is_dag_primary { "dag-primary-no-fallback" } else { "no-candidates-mempool-empty" },
                                            stats.n, stats.filtered_seen, stats.bad_nonce_pref
                                        );
                                        Vec::new()
                                    } else {
                                        log::info!(
                                            "hybrid-agg: no candidates (reason=filtered-out, n={} filtered={} bad_nonce={}), fallback to mempool",
                                            stats.n, stats.filtered_seen, stats.bad_nonce_pref
                                        );
                                        // T78.4: Only increment fallback counter in dag-hybrid mode
                                        crate::metrics::dag_hybrid_fallback_inc();
                                        Self::collect_from_mempool(&mut guard, block_max_tx)
                                    }
                                }
                            } else {
                                // No stats available - shouldn't happen but fallback anyway (unless dag-primary)
                                if is_dag_primary {
                                    log::warn!("dag-primary: no stats available, continuing with empty block");
                                    Vec::new()
                                } else {
                                    Self::collect_from_mempool(&mut guard, block_max_tx)
                                }
                            }
                        }
                    } else {
                        // T68.1: If DAG source is selected and returned txs, use those;
                        // otherwise fall back to mempool.
                        Self::collect_block_txs_with_dag_fallback(
                            block_tx_source,
                            dag_txs,
                            &mut guard,
                            block_max_tx,
                        )
                    };
                    
                    // Non-dag-consensus variant: just use dag_txs or mempool fallback
                    #[cfg(not(feature = "dag-consensus"))]
                    let txs = Self::collect_block_txs_with_dag_fallback(
                        block_tx_source,
                        dag_txs,
                        &mut guard,
                        block_max_tx,
                    );

                    let next_height = guard.height + 1;
                    
                    // T82.2d: Track in-flight count for ALL tx collection paths when actor is enabled.
                    // This shows txs currently being built into a block, regardless of source.
                    #[cfg(feature = "metrics")]
                    if crate::mempool_actor::is_mempool_actor_enabled() && !txs.is_empty() {
                        crate::metrics::mempool_inflight_len_set(txs.len());
                    }

                    // 3. Create executor input
                    // T76.4: Use partial failure tolerance for hybrid DAG batches to avoid
                    // full-block aborts when some txs fail. This allows the valid subset
                    // to be applied while dropping/deferring bad txs.
                    #[cfg(feature = "dag-consensus")]
                    let exec_input = if hybrid_batch_used {
                        ExecInput::with_partial_failure(txs, next_height)
                    } else {
                        ExecInput::new(txs, next_height)
                    };
                    
                    #[cfg(not(feature = "dag-consensus"))]
                    let exec_input = ExecInput::new(txs, next_height);
                    
                    // 4. Execute block using the executor
                    let exec_outcome = exec.execute_block(&mut guard, exec_input);
                    
                    // T76.4/T76.5: Log and emit metrics for hybrid batch apply diagnostics
                    #[cfg(feature = "dag-consensus")]
                    if hybrid_batch_used {
                        let apply_ok = exec_outcome.apply_ok;
                        let apply_fail = exec_outcome.apply_fail;
                        let reasons = &exec_outcome.failure_reasons;
                        
                        // T76.4: Emit apply_ok and apply_fail metrics
                        crate::metrics::dag_hybrid_apply_ok_inc_by(apply_ok as u64);
                        crate::metrics::dag_hybrid_apply_fail_inc_by(apply_fail as u64);
                        
                        // T76.5: Emit per-reason failure metrics
                        crate::metrics::dag_hybrid_apply_fail_bad_nonce_inc_by(reasons.bad_nonce as u64);
                        crate::metrics::dag_hybrid_apply_fail_insufficient_funds_inc_by(reasons.insufficient_funds as u64);
                        crate::metrics::dag_hybrid_apply_fail_invalid_sender_inc_by(reasons.invalid_sender as u64);
                        crate::metrics::dag_hybrid_apply_fail_other_inc_by(reasons.other as u64);
                        
                        // T76.5: Emit single structured log line per batch with all diagnostics
                        // Format: hybrid: n={n} filtered_seen={seen} candidate={cand} used={used} bad_nonce_pref={bn} missing={miss} decode_err={dec} apply_ok={ok} apply_fail={fail} size_bytes={sz}
                        if let Some(ref stats) = hybrid_stats_opt {
                            log::info!("{}", stats.to_log_string(apply_ok, apply_fail));
                        }
                        
                        // T76.5: Also log per-reason failure breakdown for detailed debugging
                        if apply_fail > 0 {
                            log::debug!(
                                "hybrid: apply failure breakdown bad_nonce={} insufficient_funds={} invalid_sender={} other={}",
                                reasons.bad_nonce, reasons.insufficient_funds, reasons.invalid_sender, reasons.other
                            );
                        }
                    }

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
                                        
                                        // T82.2d: Increment mempool batch metric on block commit
                                        record_mempool_batch_served_if_enabled(blk.header.tx_count);
                                    }

                                    // Update node pointers
                                    let curr_hash = blk.header.hash();
                                    guard.height = blk.header.height;
                                    guard.prev_hash = curr_hash;
                                    guard.last_header = Some(blk.header.clone());
                                    guard.last_txs = Some(blk.txs.clone());

                                    // T76.13: Clean up ledger mempool after hybrid block commit.
                                    // When hybrid mode is used, txs are sourced from the SharedMempool
                                    // via DAG ordering, not from the ledger mempool's drain_for_block.
                                    // If we don't clean up, the ledger mempool accumulates "zombie" txs
                                    // that have already been committed. These zombies cause liveness
                                    // issues when the fallback path drains them with stale nonces.
                                    #[cfg(feature = "dag-consensus")]
                                    if hybrid_batch_used && !blk.txs.is_empty() {
                                        let committed_pairs: Vec<(eezo_ledger::Address, u64)> = blk.txs.iter()
                                            .filter_map(|tx| {
                                                eezo_ledger::sender_from_pubkey_first20(tx)
                                                    .map(|sender| (sender, tx.core.nonce))
                                            })
                                            .collect();
                                        if !committed_pairs.is_empty() {
                                            let removed = guard.mempool.remove_committed_txs(&committed_pairs);
                                            if removed > 0 {
                                                log::debug!(
                                                    "hybrid: cleaned up {} txs from ledger mempool after commit at height={}",
                                                    removed, blk.header.height
                                                );
                                            }
                                        }
                                    }

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
                                    // T82.2c: Reset in-flight count on rollback (txs returned to pool)
                                    #[cfg(feature = "metrics")]
                                    {
                                        if crate::mempool_actor::is_mempool_actor_enabled() {
                                            crate::metrics::mempool_inflight_len_set(0);
                                        }
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
                            // T82.2c: Reset in-flight count on rollback (txs returned to pool)
                            #[cfg(feature = "metrics")]
                            {
                                if crate::mempool_actor::is_mempool_actor_enabled() {
                                    crate::metrics::mempool_inflight_len_set(0);
                                }
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
                            
                            // T82.2c: Reset in-flight count after block is committed.
                            // This reflects that txs are no longer in-flight (they've been included).
                            if crate::mempool_actor::is_mempool_actor_enabled() {
                                crate::metrics::mempool_inflight_len_set(0);
                            }
                        }
                        // --- END METRICS ---

                        // T60.0: block-only shadow tx hash summary (prep for DAG compare)
                        log_block_shadow_debug("dag_shadow_block", height, &blk_opt);

                        // T71.0: GPU hash comparison (optional, controlled by EEZO_NODE_GPU_HASH)
                        // This exercises the GPU hashing path without changing consensus behaviour.
                        let _ = compute_block_body_hash_with_gpu(&blk_opt, height);

                        // T90.0b: GPU hash diagnostic (non-consensus, feature-gated)
                        // Runs regardless of persistence feature to exercise GPU path in
                        // DagPrimary + STM mode with or without persistence.
                        // Uses EEZO_GPU_HASH_ENABLED=1 to enable.
                        if is_gpu_hash_enabled() {
                            if let Some(ref blk) = blk_opt {
                                if !blk.txs.is_empty() {
                                    let tx_bytes: Vec<Vec<u8>> = blk.txs.iter()
                                        .map(|tx| tx.to_bytes())
                                        .collect();
                                    // hash_batch_with_gpu_check computes CPU hashes,
                                    // compares with GPU if available, and logs mismatches.
                                    // Result is discarded: this is diagnostic only.
                                    let _ = hash_batch_with_gpu_check(&tx_bytes);
                                    log::debug!(
                                        "T90.0b: GPU hash diagnostic ran for block h={} ({} txs)",
                                        height, tx_bytes.len()
                                    );
                                }
                            }
                        }

                        // T75.0: Send committed block to shadow DAG (if enabled)
                        // T76.2: Also feed hybrid DAG handle for ordered batch consumption.
                        // This must not block or affect the main consensus path.
                        #[cfg(feature = "dag-consensus")]
                        {
                            if let Some(ref blk) = blk_opt {
                                // Build the summary once, reuse for both shadow and hybrid
                                let block_hash = blk.header.hash();
                                let tx_hashes: Vec<[u8; 32]> = blk.txs.iter().map(|tx| tx.hash()).collect();
                                
                                // T76.5/T82.2c: Record committed tx hashes in the de-dup cache.
                                // This prevents re-processing of the same txs in future batches.
                                // Uses canonical SignedTx.hash() as required by the spec.
                                // Now also applies to DagPrimary mode.
                                if matches!(hybrid_mode_cfg, HybridModeConfig::HybridEnabled | HybridModeConfig::DagPrimary) && !tx_hashes.is_empty() {
                                    hybrid_dedup_cache.record_committed_batch(&tx_hashes, height);
                                    log::debug!(
                                        "dag-hybrid: recorded {} committed tx hashes in de-dup cache at height={}",
                                        tx_hashes.len(), height
                                    );
                                }
                                
                                // T76.3: Include tx bytes for zero-copy consumption.
                                // TODO: Serialize txs to bytes for hybrid path.
                                // For now, tx_bytes is None - hybrid path will use mempool fallback.
                                let summary = ShadowBlockSummary {
                                    height,
                                    block_hash,
                                    tx_hashes,
                                    tx_bytes: None, // T76.3: Will be populated when available
                                    round: None,
                                    timestamp_ms: Some(blk.header.timestamp_ms),
                                };

                                // Try to get the shadow DAG sender
                                let sender_opt: Option<tokio::sync::mpsc::Sender<ShadowBlockSummary>> = 
                                    shadow_dag_c.lock().await.clone();
                                if let Some(sender) = sender_opt {
                                    // Send non-blocking; log warning if channel is full/closed
                                    if let Err(e) = sender.try_send(summary.clone()) {
                                        log::warn!(
                                            "dag-consensus: shadow send failed at height={}: {}",
                                            height, e
                                        );
                                    }
                                }

                                // T76.2: Also feed the hybrid DAG handle (if attached).
                                // This allows the DAG to order batches for the next block.
                                let hybrid_opt: Option<Arc<HybridDagHandle>> = hybrid_dag_c.lock().await.clone();
                                if let Some(hybrid) = hybrid_opt {
                                    hybrid.submit_committed_block_async(&summary).await;
                                    log::debug!(
                                        "dag-hybrid: fed committed block at height={} with {} txs",
                                        height, summary.tx_hashes.len()
                                    );
                                }
                            }
                        }

                        // update committed height gauge
                        #[cfg(feature = "metrics")]
                        {
                            crate::metrics::EEZO_BLOCK_HEIGHT.set(height as i64);
                        }

                        // T83.3: Mark block as committed in pipeline
                        // This allows the pipeline to discard stale prepared blocks
                        // and trigger preparation of the next block
                        {
                            let mut state = pipeline_state.lock();
                            state.mark_committed(height);
                        }

                        // capture the committed header hash once, reuse later for checkpoint
                        let mut last_commit_hash_opt: Option<[u8;32]> = None;
                        if log_every == 0 || height % log_every == 0 {
                            log::info!("consensus: committed height={}", height);
                        }
                        // --- T83.2: Persist FULL BLOCK (sync or async) ---
                        #[cfg(feature = "persistence")]
                        if let Some(ref db_handle) = db_c {
                            if let Some(ref blk) = blk_opt {
                                let hdr = &blk.header;

                                if hdr.height == height {
                                    last_commit_hash_opt = Some(hdr.hash());
                                    
                                    // T83.2: Check if async persistence is enabled
                                    if async_persist_enabled_c {
                                        // --- ASYNC PATH ---
                                        // 1. Apply block state changes to in-memory head
                                        // (Note: The actual state is already in node.accounts/supply,
                                        // we track modified accounts in mem_head for read-after-write)
                                        {
                                            let node_guard = node_c.lock().await;
                                            // Build write-set from current committed state
                                            // In a full implementation, we'd track only changed accounts
                                            // For now, we apply the full accounts to mem_head
                                            let write_set = BlockWriteSet {
                                                height,
                                                accounts: node_guard.accounts.iter()
                                                    .map(|(addr, acct)| (*addr, acct.clone()))
                                                    .collect(),
                                                supply: node_guard.supply.clone(),
                                                write_snapshot: false, // will handle snapshots separately
                                            };
                                            mem_head_c.apply_write_set(&write_set);
                                        }
                                        
                                        // 2. Determine if we need a snapshot at this height
                                        let snapshot_interval = std::env::var("EEZO_SNAPSHOT_INTERVAL")
                                            .ok()
                                            .and_then(|s| s.parse::<u64>().ok())
                                            .or_else(|| {
                                                std::env::var("EEZO_CHECKPOINT_EVERY")
                                                    .ok()
                                                    .and_then(|s| s.parse::<u64>().ok())
                                            })
                                            .unwrap_or(1000);
                                        
                                        let snap_opt = if snapshot_interval > 0 && height % snapshot_interval == 0 {
                                            let node_guard = node_c.lock().await;
                                            Some(StateSnapshot {
                                                height: node_guard.height,
                                                accounts: node_guard.accounts.clone(),
                                                supply: node_guard.supply.clone(),
                                                state_root: [0u8; 32],
                                                bridge: None,
                                                #[cfg(feature = "eth-ssz")]
                                                codec_version: 1,
                                                #[cfg(feature = "eth-ssz")]
                                                state_root_v2: [0u8; 32],
                                            })
                                        } else {
                                            None
                                        };
                                        
                                        // 3. Enqueue to persistence worker
                                        if let Some(ref pw) = persist_worker_c {
                                            if let Err(e) = pw.enqueue_block(
                                                height,
                                                hdr.clone(),
                                                blk.clone(),
                                                snap_opt,
                                            ).await {
                                                // Channel closed - fall back to sync write
                                                log::error!(
                                                    "❌ runner: async persist enqueue failed at h={}: {}, falling back to sync",
                                                    height, e
                                                );
                                                // Fallback to synchronous write
                                                if let Err(e2) = db_handle.put_header_and_block(height, hdr, blk) {
                                                    log::error!("❌ runner: sync fallback persist failed at h={}: {}", height, e2);
                                                }
                                            } else {
                                                log::debug!("runner: enqueued block h={} for async persistence", height);
                                            }
                                        } else {
                                            // Worker not available, fallback to sync
                                            log::warn!("runner: persist_worker not available at h={}, using sync write", height);
                                            if let Err(e) = db_handle.put_header_and_block(height, hdr, blk) {
                                                log::error!("❌ runner: failed to persist block at h={}: {}", height, e);
                                            }
                                        }
                                    } else {
                                        // --- SYNC PATH (original behavior) ---
                                        if let Err(e) = db_handle.put_header_and_block(height, hdr, blk) {
                                            log::error!("❌ runner: failed to persist block at h={}: {}", height, e);
                                        } else {
                                            log::debug!("runner: persisted block at h={}", height);
                                        }
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
                        }
                        // --- END T83.2 Block Persistence ---


                        // --- Phase 1 Snapshot Writing Logic (sync mode only) ---
                        // T83.2: Skip this section if async mode is enabled (snapshots handled above)
                        #[cfg(feature = "persistence")]
                        if !async_persist_enabled_c {
                            if let Some(ref db_handle) = db_c {
                                let snapshot_interval = std::env::var("EEZO_SNAPSHOT_INTERVAL")
                                    .ok()
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .or_else(|| {
                                        std::env::var("EEZO_CHECKPOINT_EVERY")
                                            .ok()
                                            .and_then(|s| s.parse::<u64>().ok())
                                    })
                                    .unwrap_or(1000);

                                if snapshot_interval > 0 && height % snapshot_interval == 0 {
                                    log::debug!("runner: h={} matches snapshot interval {}", height, snapshot_interval);
                                    let node_guard = node_c.lock().await;
                                    let snap = StateSnapshot {
                                        height: node_guard.height,
                                        accounts: node_guard.accounts.clone(),
                                        supply: node_guard.supply.clone(),
                                        state_root: [0u8; 32],
                                        bridge: None,
                                        #[cfg(feature = "eth-ssz")]
                                        codec_version: 1,
                                        #[cfg(feature = "eth-ssz")]
                                        state_root_v2: [0u8; 32],
                                    };
                                    drop(node_guard);

                                    match db_handle.put_state_snapshot(&snap) {
                                        Ok(_) => log::info!("✅ runner: wrote state snapshot at h={}", height),
                                        Err(e) => log::error!("❌ runner: snapshot write failed at h={}: {}", height, e),
                                    }
                                }
                            }
                        }
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
            #[cfg(feature = "dag-consensus")]
            shadow_dag_sender,
            #[cfg(feature = "dag-consensus")]
            hybrid_dag: hybrid_dag_store,
            // T83.2: Async persistence components
            mem_head,
            persist_worker,
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

    /// T75.0: attach the shadow DAG sender for feeding committed blocks to shadow consensus.
    ///
    /// This is called from main.rs after the shadow DAG runner is spawned.
    /// The sender is used to send ShadowBlockSummary on each block commit.
    #[cfg(feature = "dag-consensus")]
    pub async fn set_shadow_dag_sender(
        self: &Arc<Self>,
        sender: Option<tokio::sync::mpsc::Sender<ShadowBlockSummary>>,
    ) {
        {
            let mut guard = self.shadow_dag_sender.lock().await;
            *guard = sender;
        }
        log::info!("consensus: core_runner: shadow DAG sender attached");
    }

    /// T76.1: attach or clear the hybrid DAG handle.
    ///
    /// When set, the runner can try to consume ordered batches from the DAG
    /// as the primary tx source in hybrid mode.
    #[cfg(feature = "dag-consensus")]
    pub async fn set_hybrid_dag(
        self: &Arc<Self>,
        handle: Option<Arc<HybridDagHandle>>,
    ) {
        {
            let mut guard = self.hybrid_dag.lock().await;
            *guard = handle;
        }
        log::info!("consensus: core_runner: hybrid DAG handle attached");
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
        let mut txs = guard.mempool.drain_for_block(block_byte_budget, &guard.accounts);

        // Apply max_tx cap if configured, re-enqueue overflow
        if block_max_tx < usize::MAX && txs.len() > block_max_tx {
            let dropped = txs.split_off(block_max_tx);
            for tx in dropped {
                guard.mempool.enqueue_tx(tx);
            }
        }

        txs
    }

    /// T76.3: Process an OrderedBatch from DAG, extracting SignedTx from bytes.
    ///
    /// For each entry in the batch:
    /// - First check if bytes were pre-resolved from the shared mempool
    /// - If bytes are available (either in batch or resolved), decode directly
    /// - If bytes are missing from both sources, count as missing
    /// - Track metrics: bytes_used, bytes_missing, decode_errors
    ///
    /// Respects `block_max_bytes` cap, leaving remainder for next block.
    ///
    /// Returns:
    /// - `Ok(txs)`: vector of successfully decoded SignedTx
    /// - Remainder entries stay in mempool for next block (no drop)
    #[cfg(feature = "dag-consensus")]
    fn collect_txs_from_hybrid_batch_with_resolved(
        batch: &consensus_dag::OrderedBatch,
        resolved_bytes: &std::collections::HashMap<[u8; 32], bytes::Bytes>,
        block_max_bytes: usize,
    ) -> (Vec<SignedTx>, usize, usize, usize, usize) {
        // Statistics for logging and metrics
        let mut bytes_used: usize = 0;
        let mut bytes_missing: usize = 0;
        let mut decode_errors: usize = 0;
        let mut total_size_bytes: usize = 0;
        
        let mut txs: Vec<SignedTx> = Vec::new();
        let mut current_bytes: usize = 0;

        // T76.3: If batch has tx_hashes, iterate over them and use resolved_bytes
        // Otherwise fall back to the batch's iter_tx_entries (which may also have bytes)
        if let Some(hashes) = &batch.tx_hashes {
            for hash in hashes {
                // Check if we've exceeded block max_bytes cap
                if current_bytes >= block_max_bytes {
                    log::debug!(
                        "hybrid: block max_bytes cap reached ({} >= {}), leaving remainder",
                        current_bytes, block_max_bytes
                    );
                    break;
                }

                // T76.3: Try batch's tx_bytes first (if present and at this index),
                // otherwise fall back to resolved_bytes from shared mempool
                let hashes = batch.tx_hashes.as_ref().unwrap(); // safe: we're in the if let Some block
                let idx = hashes.iter().position(|h| h == hash).unwrap_or(usize::MAX);
                let batch_bytes = batch.tx_bytes.as_ref()
                    .and_then(|v| v.get(idx))
                    .and_then(|opt| opt.as_ref());
                
                // Use batch bytes if available, otherwise use resolved bytes
                if let Some(bytes) = batch_bytes.or_else(|| resolved_bytes.get(hash)) {
                    let tx_size = bytes.len();
                    
                    // Check if this tx would exceed the byte budget
                    if current_bytes + tx_size > block_max_bytes {
                        log::debug!(
                            "hybrid: tx would exceed block_max_bytes ({} + {} > {}), stopping",
                            current_bytes, tx_size, block_max_bytes
                        );
                        break;
                    }

                    // T76.9: Use helper that respects fast decode setting
                    match decode_tx_from_envelope_bytes(bytes) {
                        Some(stx) => {
                            txs.push(stx);
                            bytes_used += 1;
                            current_bytes += tx_size;
                            total_size_bytes += tx_size;
                        }
                        None => {
                            decode_errors += 1;
                            log::warn!(
                                "hybrid: decode error for tx hash=0x{}",
                                hex::encode(&hash[..4])
                            );
                        }
                    }
                } else {
                    // Bytes not found in resolved cache
                    bytes_missing += 1;
                    log::debug!(
                        "hybrid: missing bytes for tx hash=0x{}, will be processed via normal path",
                        hex::encode(&hash[..4])
                    );
                }
            }
        } else {
            // No tx_hashes in batch - use legacy iterator
            for (hash, bytes_opt) in batch.iter_tx_entries() {
                if current_bytes >= block_max_bytes {
                    log::debug!(
                        "hybrid: block max_bytes cap reached ({} >= {}), leaving remainder",
                        current_bytes, block_max_bytes
                    );
                    break;
                }

                // Try batch bytes first, then resolved
                let bytes = bytes_opt.or_else(|| resolved_bytes.get(&hash));
                
                if let Some(bytes_ref) = bytes {
                    let tx_size = bytes_ref.len();
                    
                    if current_bytes + tx_size > block_max_bytes {
                        log::debug!(
                            "hybrid: tx would exceed block_max_bytes ({} + {} > {}), stopping",
                            current_bytes, tx_size, block_max_bytes
                        );
                        break;
                    }

                    // T76.9: Use helper that respects fast decode setting
                    match decode_tx_from_envelope_bytes(bytes_ref) {
                        Some(stx) => {
                            txs.push(stx);
                            bytes_used += 1;
                            current_bytes += tx_size;
                            total_size_bytes += tx_size;
                        }
                        None => {
                            decode_errors += 1;
                            log::warn!(
                                "hybrid: decode error for tx hash=0x{}",
                                hex::encode(&hash[..4])
                            );
                        }
                    }
                } else {
                    bytes_missing += 1;
                    log::debug!(
                        "hybrid: missing bytes for tx hash=0x{}, will be processed via normal path",
                        hex::encode(&hash[..4])
                    );
                }
            }
        }

        (txs, bytes_used, bytes_missing, decode_errors, total_size_bytes)
    }

    /// T76.5: Process an OrderedBatch with de-dup filtering and nonce pre-check.
    ///
    /// This is the full pipeline for hybrid batch consumption:
    /// 1. Apply de-dup filter to remove already-committed tx hashes
    /// 2. Decode transactions from bytes
    /// 3. Apply nonce pre-check to remove stale-nonce transactions
    ///
    /// Returns a tuple of:
    /// - `txs`: Successfully decoded and validated transactions
    /// - Statistics: (n, filtered_seen, candidate, used, bad_nonce_pref, missing, decode_err, size_bytes)
    #[cfg(feature = "dag-consensus")]
    fn collect_txs_from_hybrid_batch_with_dedup_and_nonce_check(
        batch: &consensus_dag::OrderedBatch,
        resolved_bytes: &std::collections::HashMap<[u8; 32], bytes::Bytes>,
        block_max_bytes: usize,
        dedup_cache: &crate::dag_consensus_runner::HybridDedupCache,
        accounts: &eezo_ledger::Accounts,
    ) -> (Vec<SignedTx>, HybridBatchStats) {
        // T76.5: Get original batch size
        let n = match &batch.tx_hashes {
            Some(hashes) => hashes.len(),
            None => batch.tx_count(),
        };

        // T76.5: Step 1 - Apply de-dup filter
        let (candidate_hashes, filtered_seen) = if let Some(hashes) = &batch.tx_hashes {
            dedup_cache.filter_batch(hashes)
        } else {
            // No hashes to filter - collect all entries
            (Vec::new(), 0)
        };

        // T76.5: Update metrics for de-dup filtering
        crate::metrics::dag_hybrid_seen_before_inc_by(filtered_seen as u64);
        let candidate = candidate_hashes.len();
        crate::metrics::dag_hybrid_candidate_inc_by(candidate as u64);

        // If all hashes were filtered out, return early
        if candidate == 0 && filtered_seen > 0 {
            log::debug!(
                "hybrid: all {} hashes filtered by de-dup, no candidates to process",
                filtered_seen
            );
            return (Vec::new(), HybridBatchStats {
                n,
                filtered_seen,
                candidate: 0,
                used: 0,
                bad_nonce_pref: 0,
                missing: 0,
                decode_err: 0,
                size_bytes: 0,
                agg_batches: 1, // Single batch
                agg_candidates: 0, // No candidates after dedup
            });
        }

        // T76.5: Step 2 - Decode transactions from filtered candidates
        // Build a temporary batch with only the candidate hashes
        let mut txs: Vec<SignedTx> = Vec::new();
        let mut bytes_used: usize = 0;
        let mut bytes_missing: usize = 0;
        let mut decode_errors: usize = 0;
        let mut total_size_bytes: usize = 0;
        let mut current_bytes: usize = 0;

        for hash in &candidate_hashes {
            // Check if we've exceeded block max_bytes cap
            if current_bytes >= block_max_bytes {
                log::debug!(
                    "hybrid: block max_bytes cap reached ({} >= {}), leaving remainder",
                    current_bytes, block_max_bytes
                );
                break;
            }

            // Try to get bytes from batch or resolved
            let idx_opt = batch.tx_hashes.as_ref()
                .and_then(|h| h.iter().position(|hh| hh == hash));
            let batch_bytes = idx_opt.and_then(|idx| {
                batch.tx_bytes.as_ref()
                    .and_then(|v| v.get(idx))
                    .and_then(|opt| opt.as_ref())
            });
            
            if let Some(bytes) = batch_bytes.or_else(|| resolved_bytes.get(hash)) {
                let tx_size = bytes.len();
                
                if current_bytes + tx_size > block_max_bytes {
                    log::debug!(
                        "hybrid: tx would exceed block_max_bytes ({} + {} > {}), stopping",
                        current_bytes, tx_size, block_max_bytes
                    );
                    break;
                }

                // T76.9: Use helper that respects fast decode setting
                match decode_tx_from_envelope_bytes(bytes) {
                    Some(stx) => {
                        txs.push(stx);
                        bytes_used += 1;
                        current_bytes += tx_size;
                        total_size_bytes += tx_size;
                    }
                    None => {
                        decode_errors += 1;
                        log::warn!(
                            "hybrid: decode error for tx hash=0x{}",
                            hex::encode(&hash[..4])
                        );
                    }
                }
            } else {
                bytes_missing += 1;
                log::debug!(
                    "hybrid: missing bytes for tx hash=0x{}",
                    hex::encode(&hash[..4])
                );
            }
        }

        // T78.SAFE: Step 3 - Apply nonce contiguity filter
        // This replaces the old nonce_precheck with a stricter filter that enforces
        // contiguous nonce sequences per sender, preventing BadNonce execution failures.
        let (valid_indices, bad_nonce_count, gap_count) = 
            crate::dag_consensus_runner::nonce_contiguity_filter(&txs, accounts);
        
        // T76.5: Update metrics for nonce prefilter (now includes gaps)
        crate::metrics::dag_hybrid_bad_nonce_prefilter_inc_by(bad_nonce_count as u64);
        // T78.SAFE: Track nonce gap drops separately for observability
        crate::metrics::dag_hybrid_nonce_gap_dropped_inc_by(gap_count as u64);

        // Filter txs to only include valid indices, avoiding clones by using indices
        // to directly move elements from the original vector.
        let final_txs: Vec<SignedTx> = if valid_indices.len() == txs.len() {
            // All txs are valid - no filtering needed, move the entire vector
            txs
        } else {
            // Some txs were filtered - need to select only valid ones
            // Create a mask of which indices to keep
            let mut keep_mask = vec![false; txs.len()];
            for &idx in &valid_indices {
                keep_mask[idx] = true;
            }
            // Drain and filter in one pass
            txs.into_iter()
                .enumerate()
                .filter_map(|(i, tx)| if keep_mask[i] { Some(tx) } else { None })
                .collect()
        };

        let stats = HybridBatchStats {
            n,
            filtered_seen,
            candidate,
            used: bytes_used,
            bad_nonce_pref: bad_nonce_count,
            missing: bytes_missing,
            decode_err: decode_errors,
            size_bytes: total_size_bytes,
            agg_batches: 1, // Single batch - will be updated for multi-batch aggregation
            agg_candidates: candidate, // For single batch, agg_candidates == candidate
        };

        (final_txs, stats)
    }

    /// T76.7: Aggregate multiple OrderedBatches with de-dup filtering and nonce pre-check.
    ///
    /// This implements multi-batch aggregation per the T76.7 spec:
    /// - Consume ≥1 ready DAG batches for a single block
    /// - Stop aggregating when max_bytes exceeded, no more ready batches, or time budget elapsed
    /// - Run de-dup + nonce prefilter across the union of all candidates
    /// - Preserve T76.4 partial-failure execution semantics
    ///
    /// Returns a tuple of:
    /// - `txs`: Successfully decoded and validated transactions
    /// - `stats`: HybridBatchStats with agg_batches and agg_candidates set
    #[cfg(feature = "dag-consensus")]
    async fn collect_txs_from_aggregated_batches(
        hybrid_handle: &Arc<crate::dag_consensus_runner::HybridDagHandle>,
        dag_handle: Option<Arc<DagRunnerHandle>>,
        block_max_bytes: usize,
        dedup_cache: &crate::dag_consensus_runner::HybridDedupCache,
        accounts: &eezo_ledger::Accounts,
        agg_time_budget_ms: u64,
    ) -> (Vec<SignedTx>, HybridBatchStats) {
        use std::time::Instant;
        
        let agg_start = Instant::now();
        let time_budget = std::time::Duration::from_millis(agg_time_budget_ms);
        
        // Aggregated values
        let mut all_hashes: Vec<[u8; 32]> = Vec::new();
        let mut all_resolved_bytes: std::collections::HashMap<[u8; 32], bytes::Bytes> = std::collections::HashMap::new();
        let mut total_n: usize = 0;
        let mut batches_consumed: usize = 0;
        let mut current_bytes: usize = 0;
        let mut stale_batches_dropped: usize = 0;
        
        // Aggregation loop: consume batches until limits are reached
        loop {
            // Check time budget
            if agg_start.elapsed() >= time_budget {
                log::debug!(
                    "hybrid-agg: time budget elapsed ({:?} >= {:?}), stopping aggregation",
                    agg_start.elapsed(), time_budget
                );
                break;
            }
            
            // Check if more batches are available
            if hybrid_handle.peek_ordered_queue_len() == 0 {
                log::debug!("hybrid-agg: no more batches available, stopping aggregation");
                break;
            }
            
            // Try to get next batch
            match hybrid_handle.try_next_ordered_batch() {
                Some(batch) if !batch.is_empty() => {
                    // Check if batch is stale
                    if dedup_cache.is_stale_batch(batch.round) {
                        log::info!(
                            "hybrid-agg: dropping stale batch (reason=pre-start-round, round={}, node_start_round={})",
                            batch.round, dedup_cache.node_start_round()
                        );
                        crate::metrics::dag_hybrid_stale_batches_dropped_inc();
                        stale_batches_dropped += 1;
                        continue; // Try next batch
                    }
                    
                    // Get tx hashes from this batch
                    if let Some(hashes) = &batch.tx_hashes {
                        // Estimate bytes for this batch (rough estimate)
                        let estimated_batch_bytes = batch.total_bytes_size();
                        
                        // Check if adding this batch would exceed max_bytes
                        if current_bytes > 0 && current_bytes + estimated_batch_bytes > block_max_bytes {
                            log::debug!(
                                "hybrid-agg: batch would exceed max_bytes ({} + {} > {}), stopping",
                                current_bytes, estimated_batch_bytes, block_max_bytes
                            );
                            break;
                        }
                        
                        // Resolve bytes for this batch if needed
                        if let (Some(batch_hashes), None) = (&batch.tx_hashes, &batch.tx_bytes) {
                            if let Some(ref dag_h) = dag_handle {
                                let found = dag_h.get_bytes_for_hashes(batch_hashes).await;
                                for (hash, bytes_arc) in found {
                                    all_resolved_bytes.insert(hash, bytes::Bytes::from((*bytes_arc).clone()));
                                }
                            }
                        }
                        
                        // Add hashes from batch to aggregate
                        for hash in hashes {
                            all_hashes.push(*hash);
                        }
                        
                        // Copy bytes from batch if present
                        if let Some(tx_bytes) = &batch.tx_bytes {
                            for (i, bytes_opt) in tx_bytes.iter().enumerate() {
                                if let Some(bytes) = bytes_opt {
                                    if i < hashes.len() {
                                        all_resolved_bytes.insert(hashes[i], bytes.clone());
                                    }
                                }
                            }
                        }
                        
                        total_n += hashes.len();
                        current_bytes += estimated_batch_bytes;
                        batches_consumed += 1;
                        
                        log::debug!(
                            "hybrid-agg: consumed batch {} (round={}, txs={}, total_agg={})",
                            batches_consumed, batch.round, hashes.len(), total_n
                        );
                    }
                }
                Some(_) => {
                    // Empty batch - skip and continue
                    log::debug!("hybrid-agg: skipping empty batch");
                    continue;
                }
                None => {
                    // No batch available - stop
                    log::debug!("hybrid-agg: no batch available, stopping");
                    break;
                }
            }
        }
        
        // If no batches were consumed, return empty result
        if batches_consumed == 0 {
            log::debug!("hybrid-agg: no batches consumed, returning empty (stale_dropped={})", stale_batches_dropped);
            return (Vec::new(), HybridBatchStats {
                n: 0,
                filtered_seen: 0,
                candidate: 0,
                used: 0,
                bad_nonce_pref: 0,
                missing: 0,
                decode_err: 0,
                size_bytes: 0,
                agg_batches: batches_consumed,
                agg_candidates: 0,
            });
        }
        
        // Apply de-dup filter to the aggregated hashes (union de-dup)
        let (candidate_hashes, filtered_seen) = dedup_cache.filter_batch(&all_hashes);
        let candidate = candidate_hashes.len();
        
        // Update metrics for de-dup filtering
        crate::metrics::dag_hybrid_seen_before_inc_by(filtered_seen as u64);
        crate::metrics::dag_hybrid_candidate_inc_by(candidate as u64);
        
        // If all hashes were filtered out, return early
        if candidate == 0 && filtered_seen > 0 {
            log::debug!(
                "hybrid-agg: all {} hashes filtered by de-dup across {} batches, no candidates",
                filtered_seen, batches_consumed
            );
            return (Vec::new(), HybridBatchStats {
                n: total_n,
                filtered_seen,
                candidate: 0,
                used: 0,
                bad_nonce_pref: 0,
                missing: 0,
                decode_err: 0,
                size_bytes: 0,
                agg_batches: batches_consumed,
                agg_candidates: candidate,
            });
        }
        
        // Decode transactions from filtered candidates
        let mut txs: Vec<SignedTx> = Vec::new();
        let mut bytes_used: usize = 0;
        let mut bytes_missing: usize = 0;
        let mut decode_errors: usize = 0;
        let mut total_size_bytes: usize = 0;
        let mut current_tx_bytes: usize = 0;
        
        for hash in &candidate_hashes {
            // Check if we've exceeded block max_bytes cap
            if current_tx_bytes >= block_max_bytes {
                log::debug!(
                    "hybrid-agg: block max_bytes cap reached ({} >= {}), leaving remainder",
                    current_tx_bytes, block_max_bytes
                );
                break;
            }
            
            if let Some(bytes) = all_resolved_bytes.get(hash) {
                let tx_size = bytes.len();
                
                if current_tx_bytes + tx_size > block_max_bytes {
                    log::debug!(
                        "hybrid-agg: tx would exceed block_max_bytes ({} + {} > {}), stopping",
                        current_tx_bytes, tx_size, block_max_bytes
                    );
                    break;
                }
                
                // T76.9: Use helper that respects fast decode setting
                match decode_tx_from_envelope_bytes(bytes) {
                    Some(stx) => {
                        txs.push(stx);
                        bytes_used += 1;
                        current_tx_bytes += tx_size;
                        total_size_bytes += tx_size;
                    }
                    None => {
                        decode_errors += 1;
                        log::warn!(
                            "hybrid-agg: decode error for tx hash=0x{}",
                            hex::encode(&hash[..4])
                        );
                    }
                }
            } else {
                bytes_missing += 1;
                log::debug!(
                    "hybrid-agg: missing bytes for tx hash=0x{}",
                    hex::encode(&hash[..4])
                );
            }
        }
        
        // T78.SAFE: Apply nonce contiguity filter for aggregated batches
        let (valid_indices, bad_nonce_count, gap_count) = 
            crate::dag_consensus_runner::nonce_contiguity_filter(&txs, accounts);
        
        // Update metrics for nonce prefilter
        crate::metrics::dag_hybrid_bad_nonce_prefilter_inc_by(bad_nonce_count as u64);
        // T78.SAFE: Track nonce gap drops
        crate::metrics::dag_hybrid_nonce_gap_dropped_inc_by(gap_count as u64);
        
        // Filter txs to only include valid indices
        let final_txs: Vec<SignedTx> = if valid_indices.len() == txs.len() {
            txs
        } else {
            let mut keep_mask = vec![false; txs.len()];
            for &idx in &valid_indices {
                keep_mask[idx] = true;
            }
            txs.into_iter()
                .enumerate()
                .filter_map(|(i, tx)| if keep_mask[i] { Some(tx) } else { None })
                .collect()
        };
        
        log::info!(
            "hybrid-agg: aggregated {} batches, total_n={}, filtered_seen={}, candidates={}, used={}, gaps={}",
            batches_consumed, total_n, filtered_seen, candidate, bytes_used, gap_count
        );
        
        // Emit aggregation metrics
        crate::metrics::observe_hybrid_agg_batches_per_block(batches_consumed as u64);
        crate::metrics::observe_hybrid_agg_tx_candidates(candidate as u64);
        
        let stats = HybridBatchStats {
            n: total_n,
            filtered_seen,
            candidate,
            used: bytes_used,
            bad_nonce_pref: bad_nonce_count,
            missing: bytes_missing,
            decode_err: decode_errors,
            size_bytes: total_size_bytes,
            agg_batches: batches_consumed,
            agg_candidates: candidate,
        };
        
        (final_txs, stats)
    }

    /// T76.10: Aggregate multiple OrderedBatches with de-dup filtering, nonce pre-check,
    /// and soft caps on transaction count and bytes.
    ///
    /// This is an enhanced version of collect_txs_from_aggregated_batches that:
    /// - Applies soft caps on transaction count (max_tx) and total bytes (max_bytes)
    /// - Tracks the reason aggregation ended (time, bytes, tx, or empty)
    /// - Uses adaptive time budget from the adaptive_agg module
    ///
    /// Returns a tuple of:
    /// - `txs`: Successfully decoded and validated transactions
    /// - `stats`: HybridBatchStats with agg_batches and agg_candidates set
    /// - `cap_reason`: Reason why aggregation ended
    #[cfg(feature = "dag-consensus")]
    async fn collect_txs_from_aggregated_batches_with_caps(
        hybrid_handle: &Arc<crate::dag_consensus_runner::HybridDagHandle>,
        dag_handle: Option<Arc<DagRunnerHandle>>,
        block_max_bytes: usize,
        dedup_cache: &crate::dag_consensus_runner::HybridDedupCache,
        accounts: &eezo_ledger::Accounts,
        agg_time_budget_ms: u64,
        max_tx: usize,
        max_bytes: usize,
    ) -> (Vec<SignedTx>, HybridBatchStats, crate::adaptive_agg::AggCapReason) {
        use std::time::Instant;
        use crate::adaptive_agg::AggCapReason;
        
        let agg_start = Instant::now();
        let time_budget = std::time::Duration::from_millis(agg_time_budget_ms);
        
        // Use the smaller of block_max_bytes and max_bytes soft cap
        let effective_max_bytes = block_max_bytes.min(max_bytes);
        
        // Aggregated values
        let mut all_hashes: Vec<[u8; 32]> = Vec::new();
        let mut all_resolved_bytes: std::collections::HashMap<[u8; 32], bytes::Bytes> = std::collections::HashMap::new();
        let mut total_n: usize = 0;
        let mut batches_consumed: usize = 0;
        let mut current_bytes: usize = 0;
        let mut stale_batches_dropped: usize = 0;
        let mut cap_reason = AggCapReason::Empty; // Default to empty
        
        // Aggregation loop: consume batches until limits are reached
        loop {
            // Check time budget
            if agg_start.elapsed() >= time_budget {
                log::debug!(
                    "hybrid-agg: time budget elapsed ({:?} >= {:?}), stopping aggregation",
                    agg_start.elapsed(), time_budget
                );
                cap_reason = AggCapReason::Time;
                break;
            }
            
            // Check if we've hit the tx count cap
            if total_n >= max_tx {
                log::debug!(
                    "hybrid-agg: tx count cap reached ({} >= {}), stopping aggregation",
                    total_n, max_tx
                );
                cap_reason = AggCapReason::Tx;
                break;
            }
            
            // Check if we've hit the bytes cap
            if current_bytes >= effective_max_bytes {
                log::debug!(
                    "hybrid-agg: bytes cap reached ({} >= {}), stopping aggregation",
                    current_bytes, effective_max_bytes
                );
                cap_reason = AggCapReason::Bytes;
                break;
            }
            
            // Check if more batches are available
            if hybrid_handle.peek_ordered_queue_len() == 0 {
                log::debug!("hybrid-agg: no more batches available, stopping aggregation");
                cap_reason = AggCapReason::Empty;
                break;
            }
            
            // Try to get next batch
            match hybrid_handle.try_next_ordered_batch() {
                Some(batch) if !batch.is_empty() => {
                    // Check if batch is stale
                    if dedup_cache.is_stale_batch(batch.round) {
                        log::info!(
                            "hybrid-agg: dropping stale batch (reason=pre-start-round, round={}, node_start_round={})",
                            batch.round, dedup_cache.node_start_round()
                        );
                        crate::metrics::dag_hybrid_stale_batches_dropped_inc();
                        stale_batches_dropped += 1;
                        continue; // Try next batch
                    }
                    
                    // Get tx hashes from this batch
                    if let Some(hashes) = &batch.tx_hashes {
                        // Check if adding this batch would exceed tx count cap
                        if total_n + hashes.len() > max_tx {
                            // Only take as many as we can fit
                            let take_count = max_tx.saturating_sub(total_n);
                            if take_count == 0 {
                                log::debug!("hybrid-agg: tx cap reached, stopping");
                                cap_reason = AggCapReason::Tx;
                                break;
                            }
                            // Take partial batch
                            for hash in hashes.iter().take(take_count) {
                                all_hashes.push(*hash);
                            }
                            total_n += take_count;
                            batches_consumed += 1;
                            cap_reason = AggCapReason::Tx;
                            
                            log::debug!(
                                "hybrid-agg: partial batch {} (round={}, took {}/{} txs due to tx cap)",
                                batches_consumed, batch.round, take_count, hashes.len()
                            );
                            break;
                        }
                        
                        // Estimate bytes for this batch (rough estimate)
                        let estimated_batch_bytes = batch.total_bytes_size();
                        
                        // Check if adding this batch would exceed max_bytes
                        if current_bytes > 0 && current_bytes + estimated_batch_bytes > effective_max_bytes {
                            log::debug!(
                                "hybrid-agg: batch would exceed max_bytes ({} + {} > {}), stopping",
                                current_bytes, estimated_batch_bytes, effective_max_bytes
                            );
                            cap_reason = AggCapReason::Bytes;
                            break;
                        }
                        
                        // Resolve bytes for this batch if needed
                        if let (Some(batch_hashes), None) = (&batch.tx_hashes, &batch.tx_bytes) {
                            if let Some(ref dag_h) = dag_handle {
                                let found = dag_h.get_bytes_for_hashes(batch_hashes).await;
                                for (hash, bytes_arc) in found {
                                    all_resolved_bytes.insert(hash, bytes::Bytes::from((*bytes_arc).clone()));
                                }
                            }
                        }
                        
                        // Add hashes from batch to aggregate
                        for hash in hashes {
                            all_hashes.push(*hash);
                        }
                        
                        // Copy bytes from batch if present
                        if let Some(tx_bytes) = &batch.tx_bytes {
                            for (i, bytes_opt) in tx_bytes.iter().enumerate() {
                                if let Some(bytes) = bytes_opt {
                                    if i < hashes.len() {
                                        all_resolved_bytes.insert(hashes[i], bytes.clone());
                                    }
                                }
                            }
                        }
                        
                        total_n += hashes.len();
                        current_bytes += estimated_batch_bytes;
                        batches_consumed += 1;
                        
                        log::debug!(
                            "hybrid-agg: consumed batch {} (round={}, txs={}, total_agg={})",
                            batches_consumed, batch.round, hashes.len(), total_n
                        );
                    }
                }
                Some(_) => {
                    // Empty batch - skip and continue
                    log::debug!("hybrid-agg: skipping empty batch");
                    continue;
                }
                None => {
                    // No batch available - stop
                    log::debug!("hybrid-agg: no batch available, stopping");
                    cap_reason = AggCapReason::Empty;
                    break;
                }
            }
        }
        
        // If no batches were consumed, return empty result
        if batches_consumed == 0 {
            log::debug!("hybrid-agg: no batches consumed, returning empty (stale_dropped={})", stale_batches_dropped);
            return (Vec::new(), HybridBatchStats {
                n: 0,
                filtered_seen: 0,
                candidate: 0,
                used: 0,
                bad_nonce_pref: 0,
                missing: 0,
                decode_err: 0,
                size_bytes: 0,
                agg_batches: batches_consumed,
                agg_candidates: 0,
            }, cap_reason);
        }
        
        // Apply de-dup filter to the aggregated hashes (union de-dup)
        let (candidate_hashes, filtered_seen) = dedup_cache.filter_batch(&all_hashes);
        let candidate = candidate_hashes.len();
        
        // Update metrics for de-dup filtering
        crate::metrics::dag_hybrid_seen_before_inc_by(filtered_seen as u64);
        crate::metrics::dag_hybrid_candidate_inc_by(candidate as u64);
        
        // If all hashes were filtered out, return early
        if candidate == 0 && filtered_seen > 0 {
            log::debug!(
                "hybrid-agg: all {} hashes filtered by de-dup across {} batches, no candidates",
                filtered_seen, batches_consumed
            );
            return (Vec::new(), HybridBatchStats {
                n: total_n,
                filtered_seen,
                candidate: 0,
                used: 0,
                bad_nonce_pref: 0,
                missing: 0,
                decode_err: 0,
                size_bytes: 0,
                agg_batches: batches_consumed,
                agg_candidates: candidate,
            }, cap_reason);
        }
        
        // Decode transactions from filtered candidates (with tx count cap)
        let mut txs: Vec<SignedTx> = Vec::new();
        let mut bytes_used: usize = 0;
        let mut bytes_missing: usize = 0;
        let mut decode_errors: usize = 0;
        let mut total_size_bytes: usize = 0;
        let mut current_tx_bytes: usize = 0;
        
        for hash in &candidate_hashes {
            // Check if we've exceeded tx count cap
            if txs.len() >= max_tx {
                log::debug!(
                    "hybrid-agg: tx count cap reached during decode ({} >= {}), leaving remainder",
                    txs.len(), max_tx
                );
                cap_reason = AggCapReason::Tx;
                break;
            }
            
            // Check if we've exceeded block max_bytes cap
            if current_tx_bytes >= effective_max_bytes {
                log::debug!(
                    "hybrid-agg: block max_bytes cap reached ({} >= {}), leaving remainder",
                    current_tx_bytes, effective_max_bytes
                );
                cap_reason = AggCapReason::Bytes;
                break;
            }
            
            if let Some(bytes) = all_resolved_bytes.get(hash) {
                let tx_size = bytes.len();
                
                if current_tx_bytes + tx_size > effective_max_bytes {
                    log::debug!(
                        "hybrid-agg: tx would exceed block_max_bytes ({} + {} > {}), stopping",
                        current_tx_bytes, tx_size, effective_max_bytes
                    );
                    cap_reason = AggCapReason::Bytes;
                    break;
                }
                
                // T76.9: Use helper that respects fast decode setting
                match decode_tx_from_envelope_bytes(bytes) {
                    Some(stx) => {
                        txs.push(stx);
                        bytes_used += 1;
                        current_tx_bytes += tx_size;
                        total_size_bytes += tx_size;
                    }
                    None => {
                        decode_errors += 1;
                        log::warn!(
                            "hybrid-agg: decode error for tx hash=0x{}",
                            hex::encode(&hash[..4])
                        );
                    }
                }
            } else {
                bytes_missing += 1;
                log::debug!(
                    "hybrid-agg: missing bytes for tx hash=0x{}",
                    hex::encode(&hash[..4])
                );
            }
        }
        
        // T78.SAFE: Apply nonce contiguity filter with caps
        let (valid_indices, bad_nonce_count, gap_count) = 
            crate::dag_consensus_runner::nonce_contiguity_filter(&txs, accounts);
        
        // Update metrics for nonce prefilter
        crate::metrics::dag_hybrid_bad_nonce_prefilter_inc_by(bad_nonce_count as u64);
        // T78.SAFE: Track nonce gap drops
        crate::metrics::dag_hybrid_nonce_gap_dropped_inc_by(gap_count as u64);
        
        // Filter txs to only include valid indices
        let final_txs: Vec<SignedTx> = if valid_indices.len() == txs.len() {
            txs
        } else {
            let mut keep_mask = vec![false; txs.len()];
            for &idx in &valid_indices {
                keep_mask[idx] = true;
            }
            txs.into_iter()
                .enumerate()
                .filter_map(|(i, tx)| if keep_mask[i] { Some(tx) } else { None })
                .collect()
        };
        
        log::info!(
            "hybrid-agg: aggregated {} batches, total_n={}, filtered_seen={}, candidates={}, used={}, gaps={}, cap_reason={}",
            batches_consumed, total_n, filtered_seen, candidate, bytes_used, gap_count, cap_reason.as_str()
        );
        
        // Emit aggregation metrics
        crate::metrics::observe_hybrid_agg_batches_per_block(batches_consumed as u64);
        crate::metrics::observe_hybrid_agg_tx_candidates(candidate as u64);
        
        let stats = HybridBatchStats {
            n: total_n,
            filtered_seen,
            candidate,
            used: bytes_used,
            bad_nonce_pref: bad_nonce_count,
            missing: bytes_missing,
            decode_err: decode_errors,
            size_bytes: total_size_bytes,
            agg_batches: batches_consumed,
            agg_candidates: candidate,
        };
        
        (final_txs, stats, cap_reason)
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
    use super::{ExecutorMode, HybridModeConfig};
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

    // -------------------------------------------------------------------------
    // T76.1: Tests for HybridModeConfig
    // -------------------------------------------------------------------------

    #[test]
    fn test_hybrid_mode_config_standard_by_default() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Clear relevant env vars
        std::env::remove_var("EEZO_CONSENSUS_MODE");
        std::env::remove_var("EEZO_DAG_ORDERING_ENABLED");
        
        // T81.5: Default behavior depends on build profile:
        // - devnet-safe: defaults to DagPrimary
        // - generic: defaults to Standard
        #[cfg(feature = "devnet-safe")]
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::DagPrimary);
        #[cfg(not(feature = "devnet-safe"))]
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::Standard);
    }

    #[test]
    fn test_hybrid_mode_config_standard_when_unknown_mode_used() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // T85.0: Test that unknown modes do NOT enable any special mode
        // They're treated as invalid and HybridModeConfig::from_env()
        // falls through to Standard (since they don't match dag-hybrid or dag-primary).
        std::env::set_var("EEZO_CONSENSUS_MODE", "unknown-mode");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "true");
        
        // HybridModeConfig::from_env() only recognizes dag-primary and dag-hybrid
        // Any other value results in Standard
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::Standard);
        
        std::env::remove_var("EEZO_CONSENSUS_MODE");
        std::env::remove_var("EEZO_DAG_ORDERING_ENABLED");
    }

    #[test]
    fn test_hybrid_mode_config_standard_when_dag() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        std::env::set_var("EEZO_CONSENSUS_MODE", "dag");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "true");
        
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::Standard);
        
        std::env::remove_var("EEZO_CONSENSUS_MODE");
        std::env::remove_var("EEZO_DAG_ORDERING_ENABLED");
    }

    #[test]
    fn test_hybrid_mode_config_standard_when_hybrid_but_ordering_disabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        std::env::set_var("EEZO_CONSENSUS_MODE", "dag-hybrid");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "false");
        
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::Standard);
        
        std::env::remove_var("EEZO_CONSENSUS_MODE");
        std::env::remove_var("EEZO_DAG_ORDERING_ENABLED");
    }

    #[test]
    fn test_hybrid_mode_config_enabled_when_hybrid_and_ordering_enabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Test with dag-hybrid and true
        std::env::set_var("EEZO_CONSENSUS_MODE", "dag-hybrid");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "true");
        
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::HybridEnabled);
        
        // Test with dag_hybrid (underscore) and 1
        std::env::set_var("EEZO_CONSENSUS_MODE", "dag_hybrid");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "1");
        
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::HybridEnabled);
        
        // Test with yes
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "yes");
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::HybridEnabled);
        
        // Test with on
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "on");
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::HybridEnabled);
        
        std::env::remove_var("EEZO_CONSENSUS_MODE");
        std::env::remove_var("EEZO_DAG_ORDERING_ENABLED");
    }

    // -------------------------------------------------------------------------
    // T77.SAFE-1: HybridBatchStats Tests
    // -------------------------------------------------------------------------

    /// T77.SAFE-1: Test that HybridBatchStats produces the expected log format.
    #[cfg(feature = "dag-consensus")]
    #[test]
    fn t77_hybrid_batch_stats_log_format() {
        use super::HybridBatchStats;

        let stats = HybridBatchStats {
            n: 100,
            filtered_seen: 20,
            candidate: 80,
            used: 75,
            bad_nonce_pref: 3,
            missing: 1,
            decode_err: 1,
            size_bytes: 9000,
            agg_batches: 2,
            agg_candidates: 85,
        };

        let log_str = stats.to_log_string(70, 5);

        // Verify the log string contains all expected fields
        assert!(log_str.contains("n=100"), "Missing n=100");
        assert!(log_str.contains("filtered_seen=20"), "Missing filtered_seen=20");
        assert!(log_str.contains("candidate=80"), "Missing candidate=80");
        assert!(log_str.contains("used=75"), "Missing used=75");
        assert!(log_str.contains("bad_nonce_pref=3"), "Missing bad_nonce_pref=3");
        assert!(log_str.contains("missing=1"), "Missing missing=1");
        assert!(log_str.contains("decode_err=1"), "Missing decode_err=1");
        assert!(log_str.contains("apply_ok=70"), "Missing apply_ok=70");
        assert!(log_str.contains("apply_fail=5"), "Missing apply_fail=5");
        assert!(log_str.contains("size_bytes=9000"), "Missing size_bytes=9000");
        assert!(log_str.contains("agg_batches=2"), "Missing agg_batches=2");
        assert!(log_str.contains("agg_candidates=85"), "Missing agg_candidates=85");
    }

    /// T77.SAFE-1: Test HybridBatchStats default values.
    #[cfg(feature = "dag-consensus")]
    #[test]
    fn t77_hybrid_batch_stats_default() {
        use super::HybridBatchStats;

        let stats = HybridBatchStats::default();

        assert_eq!(stats.n, 0);
        assert_eq!(stats.filtered_seen, 0);
        assert_eq!(stats.candidate, 0);
        assert_eq!(stats.used, 0);
        assert_eq!(stats.bad_nonce_pref, 0);
        assert_eq!(stats.missing, 0);
        assert_eq!(stats.decode_err, 0);
        assert_eq!(stats.size_bytes, 0);
        assert_eq!(stats.agg_batches, 0);
        assert_eq!(stats.agg_candidates, 0);
    }

    // -------------------------------------------------------------------------
    // T78.4 — DAG-primary mode behavior tests
    // -------------------------------------------------------------------------

    /// T78.4: Test that DagPrimary mode is correctly detected from environment.
    #[test]
    fn test_dag_primary_mode_detection() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Test dag-primary with hyphen
        std::env::set_var("EEZO_CONSENSUS_MODE", "dag-primary");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "true");
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::DagPrimary);
        
        // Test dag_primary with underscore
        std::env::set_var("EEZO_CONSENSUS_MODE", "dag_primary");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "true");
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::DagPrimary);
        
        // Test case insensitivity
        std::env::set_var("EEZO_CONSENSUS_MODE", "DAG-PRIMARY");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "true");
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::DagPrimary);
        
        // Verify dag-primary works regardless of ordering enabled flag
        std::env::set_var("EEZO_CONSENSUS_MODE", "dag-primary");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "false");
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::DagPrimary);
        
        std::env::remove_var("EEZO_CONSENSUS_MODE");
        std::env::remove_var("EEZO_DAG_ORDERING_ENABLED");
    }

    /// T78.4: Test that dag-primary mode never falls back to hybrid mode.
    #[test]
    fn test_dag_primary_vs_hybrid_mode_distinction() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // DagPrimary mode
        std::env::set_var("EEZO_CONSENSUS_MODE", "dag-primary");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "true");
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::DagPrimary);
        
        // DagHybrid mode
        std::env::set_var("EEZO_CONSENSUS_MODE", "dag-hybrid");
        std::env::set_var("EEZO_DAG_ORDERING_ENABLED", "true");
        assert_eq!(HybridModeConfig::from_env(), HybridModeConfig::HybridEnabled);
        
        // Verify they're not equal
        assert_ne!(HybridModeConfig::DagPrimary, HybridModeConfig::HybridEnabled);
        
        std::env::remove_var("EEZO_CONSENSUS_MODE");
        std::env::remove_var("EEZO_DAG_ORDERING_ENABLED");
    }

    /// T78.4: Verify that DagPrimary matches pattern correctly.
    #[test]
    fn test_dag_primary_pattern_matching() {
        let dag_primary = HybridModeConfig::DagPrimary;
        let hybrid_enabled = HybridModeConfig::HybridEnabled;
        let standard = HybridModeConfig::Standard;
        
        // Test matches! macro behavior
        assert!(matches!(dag_primary, HybridModeConfig::DagPrimary));
        assert!(!matches!(hybrid_enabled, HybridModeConfig::DagPrimary));
        assert!(!matches!(standard, HybridModeConfig::DagPrimary));
        
        // Test that hybrid matches correctly
        assert!(matches!(hybrid_enabled, HybridModeConfig::HybridEnabled));
        assert!(!matches!(dag_primary, HybridModeConfig::HybridEnabled));
    }
}