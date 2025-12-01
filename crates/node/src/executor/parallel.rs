//! executor/parallel.rs
//!
//! T54 — Parallel block executor for EEZO.
//!
//! Sealevel-style "wave" scheduling:
//!   1) build per-tx access lists
//!   2) pack a wave of non-conflicting txs
//!   3) execute the wave in parallel (using fine-grained bucket locks)
//!   4) commit via a locked BlockBuildContext wrapper
//!
//! All state mutations happen through the context guard to keep safety simple.

use std::collections::HashSet;
use std::env;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use rayon::prelude::*;
use smallvec::SmallVec;

use eezo_ledger::{SignedTx, SingleNode};
use eezo_ledger::Block;
use crate::executor::{ExecInput, ExecOutcome, Executor};
use eezo_ledger::tx::{Access, AccessTarget};

// optional metrics
#[cfg(feature = "metrics")]
use crate::metrics::{
    EEZO_EXEC_PARALLEL_WAVES_TOTAL,
    EEZO_EXEC_PARALLEL_WAVE_LEN,
    EEZO_EXEC_PARALLEL_APPLY_SECONDS,
    EEZO_EXEC_WAVE_FUSE_TOTAL,
    EEZO_EXEC_WAVE_FUSED_LEN,
};

// T72.0: Import detailed executor perf metric helpers
use crate::metrics::{
    observe_exec_block_prepare_seconds,
    observe_exec_block_apply_seconds,
    observe_exec_block_commit_seconds,
    observe_exec_tx_apply_seconds,
    observe_exec_txs_per_block,
    observe_exec_block_bytes,
};

/// PreparedTx: Precomputed transaction metadata to avoid redundant access_list() calls.
/// 
/// T54.6 FIX: Instead of calling access_list() 5+ times per transaction, we compute it
/// once and store the result along with the precomputed bucket.
/// 
/// Using SmallVec<[Access; 4]> avoids heap allocation for most transactions (typical access
/// list has 2-3 entries: sender, receiver, supply, maybe 1-2 buckets).
#[derive(Debug, Clone)]
struct PreparedTx<'a> {
    /// Reference to the original signed transaction
    tx: &'a SignedTx,
    /// Precomputed access list (cached result of tx.access_list())
    access: SmallVec<[Access; 4]>,
    /// Precomputed sender bucket for parallel execution
    bucket: u16,
}

impl<'a> PreparedTx<'a> {
    /// Create a PreparedTx from a SignedTx by computing access list and bucket once.
    fn from_tx(tx: &'a SignedTx) -> Self {
        let access: SmallVec<[Access; 4]> = SmallVec::from_iter(tx.access_list());
        
        // Compute bucket: prefer explicit Bucket target, else hash sender
        let bucket = access
            .iter()
            .find_map(|a| match a.target {
                AccessTarget::Bucket(b) => Some(b),
                _ => None,
            })
            .unwrap_or_else(|| {
                // Fallback: hash sender deterministically to get bucket
                let mut acc: u32 = 0x9E37_79B9;
                if let Some(sender) = eezo_ledger::sender_from_pubkey_first20(tx) {
                    for b in sender.0 {
                        acc ^= b as u32;
                        acc = acc.rotate_left(5).wrapping_mul(0x85EB_CA6B);
                    }
                }
                acc as u16
            });
        
        Self { tx, access, bucket }
    }
}

/// T54.1: Greedy deterministic wave builder using PreparedTx
/// Build wide, conflict-free waves in a single forward pass:
/// - Same order in, same order preserved within each wave
/// - A tx conflicts if ANY of its access targets is already used in the current wave
/// - When conflict appears, we seal the wave and start a new one
///
/// T54.6 FIX: Uses PreparedTx which has precomputed access lists - no redundant calls.
fn build_waves_greedy<'a>(prepared: &'a [PreparedTx<'a>]) -> Vec<Vec<&'a PreparedTx<'a>>> {
    let mut waves: Vec<Vec<&PreparedTx>> = Vec::new();
    let mut used: HashSet<AccessTarget> = HashSet::new();
    let mut current: Vec<&PreparedTx> = Vec::new();

    for ptx in prepared.iter() {
        let mut conflict = false;

        // Check for conflicts using precomputed access list
        for a in ptx.access.iter() {
            if used.contains(&a.target) {
                conflict = true;
                break;
            }
        }

        if conflict {
            // seal current wave
            if !current.is_empty() {
                waves.push(current);
                current = Vec::new();
                used.clear();
            }
        }

        // add tx to current wave and mark its access targets
        for a in ptx.access.iter() {
            used.insert(a.target);
        }
        current.push(ptx);
    }

    if !current.is_empty() {
        waves.push(current);
    }

    waves
}

/// env flag: EEZO_EXEC_WAVE_COMPACT (default=on). Set to "0" to disable.
#[inline]
fn wave_compact_enabled() -> bool {
    env::var("EEZO_EXEC_WAVE_COMPACT").map(|v| v != "0").unwrap_or(true)
}

/// fill `used` with all access targets touched by `wave` using precomputed access lists
fn fill_used_for_wave<'a>(wave: &[&'a PreparedTx<'a>], used: &mut HashSet<AccessTarget>) {
    for ptx in wave {
        for a in ptx.access.iter() {
            used.insert(a.target);
        }
    }
}

/// Try to move a **non-conflicting prefix** of `next_wave` into `curr_wave`.
/// Preserves order and determinism. Returns how many txs were moved.
fn merge_prefix_if_clean<'a>(
    curr_wave: &mut Vec<&'a PreparedTx<'a>>,
    next_wave: &mut Vec<&'a PreparedTx<'a>>,
    used: &mut HashSet<AccessTarget>,
) -> usize {
    let mut k = 0usize;
    'scan: for ptx in next_wave.iter() {
        // conflict check using precomputed access list
        for a in ptx.access.iter() {
            if used.contains(&a.target) {
                break 'scan;
            }
        }
        // no conflict → extend tentative prefix
        k += 1;
        // and remember these keys to keep checking cumulatively
        for a in ptx.access.iter() {
            used.insert(a.target);
        }
    }

    if k > 0 {
        // move the first k txs from next_wave into curr_wave (preserving order)
        let moved: Vec<_> = next_wave.drain(0..k).collect();
        curr_wave.extend(moved);
    }
    k
}

/// T54.3: compact adjacent waves by greedily absorbing clean prefixes from followers.
/// Example:
///   [AAA][BB][C]  →  [AAAB][BC] → [AAABC]    (only when conflict-free)
fn compact_waves_prefix<'a>(
    waves: Vec<Vec<&'a PreparedTx<'a>>>
) -> Vec<Vec<&'a PreparedTx<'a>>> {
    if waves.len() <= 1 { return waves; }

    let mut waves = waves;
    let mut i = 0usize;
    while i + 1 < waves.len() {
        // build a used-set for the current accumulated wave
        let mut used: HashSet<AccessTarget> = HashSet::new();
        fill_used_for_wave(&waves[i], &mut used);

        // Use split_at_mut for safe disjoint mutable borrows
        let moved = {
            let (head, tail) = waves.split_at_mut(i + 1);
            let curr = &mut head[i];
            let next = &mut tail[0];
            merge_prefix_if_clean(curr, next, &mut used)
        };

        let next_empty = {
            let (_, tail) = waves.split_at_mut(i + 1);
            tail[0].is_empty()
        };

        if next_empty {
            // drop empty wave
            waves.remove(i + 1);
            // keep i the same; there may be more waves to absorb
        } else {
            // couldn't fully absorb; advance to next boundary
            i += 1;
        }

        // if nothing moved and next wave isn't empty, advancing prevents infinite loops
        if moved == 0 && i + 1 < waves.len() && !waves[i + 1].is_empty() {
            i += 1;
        }
    }

    waves
}

/// env: EEZO_EXEC_HYBRID (default=on). Set "0" to disable.
#[inline]
fn hybrid_enabled() -> bool {
    std::env::var("EEZO_EXEC_HYBRID").map(|v| v != "0").unwrap_or(true)
}

/// env: EEZO_EXEC_HYBRID_SPLIT_PCT (50..=95, default=80)
#[inline]
fn hybrid_split_pct() -> u64 {
    std::env::var("EEZO_EXEC_HYBRID_SPLIT_PCT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|p| p.clamp(50, 95))
        .unwrap_or(80)
}

/// env: EEZO_EXEC_HYBRID_MIN_SLICE (default=128)
#[inline]
fn hybrid_min_slice() -> usize {
    std::env::var("EEZO_EXEC_HYBRID_MIN_SLICE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(128)
}

/// Split one oversized wave into contiguous, deterministic subwaves.
/// Preserves tx order. Slices count is bounded by `lanes` and `min_slice`.
fn slice_wave_contiguous<'a>(
    wave: Vec<&'a PreparedTx<'a>>,
    lanes: usize,
    min_slice: usize,
) -> Vec<Vec<&'a PreparedTx<'a>>> {
    let n = wave.len();
    if n <= min_slice || lanes <= 1 {
        return vec![wave];
    }
    // choose number of slices so each slice is at least `min_slice`
    let mut slices = (n + min_slice - 1) / min_slice; // ceil(n / min_slice)
    slices = slices.clamp(1, lanes.min(n));
    let chunk = (n + slices - 1) / slices; // ceil(n / slices)

    let mut out = Vec::with_capacity(slices);
    let mut i = 0usize;
    while i < n {
        let j = (i + chunk).min(n);
        out.push(wave[i..j].to_vec());
        i = j;
    }
    out
}

/// Apply hybrid balancing: after greedy build + compaction,
/// split waves that are too large relative to the batch.
fn apply_hybrid_balancing<'a>(
    waves: Vec<Vec<&'a PreparedTx<'a>>>,
    lanes: usize,
    batch_len: usize,
) -> Vec<Vec<&'a PreparedTx<'a>>> {
    if !hybrid_enabled() || lanes <= 1 || waves.is_empty() {
        return waves;
    }
    let pct = hybrid_split_pct();     // default 80
    let min_slice = hybrid_min_slice(); // default 128
    let thresh = (batch_len as u128 * pct as u128 / 100) as usize;

    let mut balanced = Vec::with_capacity(waves.len());
    for w in waves.into_iter() {
        if w.len() >= thresh && w.len() >= (min_slice * 2) {
            // split deterministically into contiguous chunks
            let parts = slice_wave_contiguous(w, lanes, min_slice);
            balanced.extend(parts);
        } else {
            balanced.push(w);
        }
    }
    balanced
}

/// Parallel executor using conflict-free wave scheduling.
pub struct ParallelExecutor {
    threads: usize,
}

impl ParallelExecutor {
    pub fn new(threads: usize) -> Self {
        Self { threads }
    }
}

impl Executor for ParallelExecutor {
    fn execute_block(
        &self,
        node: &mut SingleNode,
        input: ExecInput,
    ) -> ExecOutcome {
        let start = Instant::now();

        // T54.6 FIX: Prepare all transactions ONCE - compute access lists and buckets upfront
        // This eliminates 5+ redundant access_list() calls per transaction
        // CRITICAL: Use par_iter to parallelize preparation across all CPUs
        let prepare_start = Instant::now();
        let prepared: Vec<PreparedTx> = input.txs
            .par_iter()  // PARALLEL iteration - huge speedup for large batches
            .map(|tx| PreparedTx::from_tx(tx))
            .collect();
        let prepare_elapsed = prepare_start.elapsed();

        // T54.1: build wide deterministic waves using prepared transactions
        let wave_build_start = Instant::now();
        let mut waves = build_waves_greedy(&prepared);
        let built = waves.len();
        let wave_build_elapsed = wave_build_start.elapsed();

        // T54.3: compact adjacent waves
        let compact_start = Instant::now();
        if wave_compact_enabled() {
            waves = compact_waves_prefix(waves);
        }
        let compacted_out = built.saturating_sub(waves.len());
        let compact_elapsed = compact_start.elapsed();

        // T54.6: small-wave fusion using precomputed access lists (no redundant calls)
        let fusion_start = Instant::now();
        let small_limit = std::env::var("EEZO_EXEC_SMALL_FUSE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(8);

        let mut i = 0usize;
        while i + 1 < waves.len() {
            if waves[i + 1].len() <= small_limit {
                // check conflicts using precomputed access lists
                let mut used = std::collections::HashSet::new();
                fill_used_for_wave(&waves[i], &mut used);

                let mut k = 0usize;
                'scan2: for ptx in waves[i + 1].iter() {
                    for a in ptx.access.iter() {
                        if used.contains(&a.target) {
                            break 'scan2;
                        }
                    }
                    // mark cumulative
                    for a in ptx.access.iter() {
                        used.insert(a.target);
                    }
                    k += 1;
                }

                if k == waves[i + 1].len() {
                    // fully fuse wave[i+1] into wave[i]
                    let sz = waves[i + 1].len();

                    // Safely borrow two disjoint slices, then drain from `next` into `curr`
                    {
                        let (head, tail) = waves.split_at_mut(i + 1);
                        let curr = &mut head[i];
                        let next = &mut tail[0];
                        curr.extend(next.drain(..));
                    }

                    // Now `waves[i+1]` is empty; remove it
                    waves.remove(i + 1);

                    #[cfg(feature = "metrics")]
                    {
                        EEZO_EXEC_WAVE_FUSE_TOTAL.inc();
                        EEZO_EXEC_WAVE_FUSED_LEN.observe(sz as f64);
                    }

                    // Do not advance `i`; check the enlarged waves[i] against the (new) waves[i+1]
                    continue;
                }
            }
            i += 1;
        }
        let fusion_elapsed = fusion_start.elapsed();

        // T54.4: split oversized waves deterministically to improve CPU balance
        let slice_start = Instant::now();
        let lanes = self.threads.max(1);
        let before_slice = waves.len();
        waves = apply_hybrid_balancing(waves, lanes, prepared.len());
        let sliced_out = waves.len().saturating_sub(before_slice);
        let slice_elapsed = slice_start.elapsed();

        let first = waves.get(0).map(|w| w.len()).unwrap_or(0);
        log::info!(
            "executor: waves built={}, compacted -{} → {}; sliced +{} → {}; first_wave={}, batch={}, lanes={} | timings: prepare={:.3}ms, build={:.3}ms, compact={:.3}ms, fusion={:.3}ms, slice={:.3}ms",
            built,
            compacted_out,
            before_slice,
            sliced_out,
            waves.len(),
            first,
            prepared.len(),
            lanes,
            prepare_elapsed.as_secs_f64() * 1000.0,
            wave_build_elapsed.as_secs_f64() * 1000.0,
            compact_elapsed.as_secs_f64() * 1000.0,
            fusion_elapsed.as_secs_f64() * 1000.0,
            slice_elapsed.as_secs_f64() * 1000.0
        );

        #[cfg(feature = "metrics")]
        {
            for wave in &waves {
                EEZO_EXEC_PARALLEL_WAVE_LEN.observe(wave.len() as f64);
            }
            EEZO_EXEC_PARALLEL_WAVES_TOTAL.inc_by(waves.len() as u64);
        }

        // 2) create the shared block-build context (now internally thread-safe)
        // a) Change the context type to Arc<BlockBuildContext> (no outer Mutex)
        let prev = node
            .last_committed_header()
            .map(|h| h.hash())
            .unwrap_or([0u8; 32]);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let accounts = node.accounts.clone();
        let supply = node.supply.clone();

        // New Arc<BlockBuildContext> — BlockBuildContext is now internally synchronized
        let ctx = std::sync::Arc::new(eezo_ledger::block::BlockBuildContext::start(
            prev,
            input.height,
            timestamp_ms,
            accounts,
            supply,
        ));

        // 3) execute waves (T54.5: per-tx bucket-scoped lock)
        // T54.6 FIX: Use precomputed bucket from PreparedTx - no redundant computation
        let apply_start = Instant::now();
        let mut total_wave_time: f64 = 0.0;
        let mut max_wave_time: f64 = 0.0;
        for wave in waves {
            let wave_start = Instant::now();

            // process this wave *in parallel* across buckets
            wave.par_iter().for_each(|ptx| {
                // If a global error was flagged, skip work early
                if ctx.has_error() {
                    return;
                }

                // Use precomputed bucket from PreparedTx (already computed in from_tx)
                if let Err(e) = ctx.apply_tx_parallel_bucketed(ptx.tx, ptx.bucket) {
                    ctx.flag_error(e);
                }
            });

            let wave_elapsed = wave_start.elapsed().as_secs_f64();
            total_wave_time += wave_elapsed;
            max_wave_time = max_wave_time.max(wave_elapsed);

            #[cfg(feature = "metrics")]
            {
                EEZO_EXEC_PARALLEL_APPLY_SECONDS.observe(wave_elapsed);
            }

            if ctx.has_error() {
                break;
            }
        }
        let apply_elapsed = apply_start.elapsed();

        // 4) finalize
        let finalize_start = Instant::now();
        let elapsed = start.elapsed();
        
        // c) Finalize the block (no change in semantics, but simplified call)
        let maybe_block = if !ctx.has_error() {
            Some(ctx.finish())
        } else {
            None
        };

        if maybe_block.is_none() {
            let err = "parallel executor: tx apply failed".to_string();
            return ExecOutcome::new(Err(err), elapsed, 0);
        }

        let block: Result<Block, String> = maybe_block.ok_or_else(|| {
            "parallel executor: missing block after finish".to_string()
        });

        let tx_count = match &block {
            Ok(b) => b.txs.len(),
            Err(_) => 0,
        };
        let finalize_elapsed = finalize_start.elapsed();

        // T72.0: Record detailed executor performance metrics
        // Prepare = all pre-apply work (prefetch, wave build, compact, fusion, slice)
        let total_prepare_secs = prepare_elapsed.as_secs_f64()
            + wave_build_elapsed.as_secs_f64()
            + compact_elapsed.as_secs_f64()
            + fusion_elapsed.as_secs_f64()
            + slice_elapsed.as_secs_f64();
        observe_exec_block_prepare_seconds(total_prepare_secs);

        // Apply = time spent executing the wave loop
        observe_exec_block_apply_seconds(apply_elapsed.as_secs_f64());

        // Commit = time spent finalizing the block
        observe_exec_block_commit_seconds(finalize_elapsed.as_secs_f64());

        // Per-tx metrics
        observe_exec_txs_per_block(tx_count as u64);
        if tx_count > 0 {
            // Average per-tx apply time
            let per_tx_sec = apply_elapsed.as_secs_f64() / tx_count as f64;
            observe_exec_tx_apply_seconds(per_tx_sec);
        }

        // T72.0: Calculate and record total block bytes
        // Using to_bytes().len() since SignedTx doesn't have encoded_len()
        if let Ok(ref b) = block {
            let block_bytes: u64 = b.txs.iter().map(|tx| tx.to_bytes().len() as u64).sum();
            if block_bytes > 0 {
                observe_exec_block_bytes(block_bytes);
            }
        }

        // Comprehensive timing breakdown for performance analysis
        log::info!(
            "executor timing: total={:.3}ms | prepare={:.3}ms ({:.1}%), build={:.3}ms ({:.1}%), compact={:.3}ms ({:.1}%), fusion={:.3}ms ({:.1}%), slice={:.3}ms ({:.1}%), apply={:.3}ms ({:.1}%, avg_wave={:.3}ms, max_wave={:.3}ms), finalize={:.3}ms ({:.1}%)",
            elapsed.as_secs_f64() * 1000.0,
            prepare_elapsed.as_secs_f64() * 1000.0,
            (prepare_elapsed.as_secs_f64() / elapsed.as_secs_f64()) * 100.0,
            wave_build_elapsed.as_secs_f64() * 1000.0,
            (wave_build_elapsed.as_secs_f64() / elapsed.as_secs_f64()) * 100.0,
            compact_elapsed.as_secs_f64() * 1000.0,
            (compact_elapsed.as_secs_f64() / elapsed.as_secs_f64()) * 100.0,
            fusion_elapsed.as_secs_f64() * 1000.0,
            (fusion_elapsed.as_secs_f64() / elapsed.as_secs_f64()) * 100.0,
            slice_elapsed.as_secs_f64() * 1000.0,
            (slice_elapsed.as_secs_f64() / elapsed.as_secs_f64()) * 100.0,
            apply_elapsed.as_secs_f64() * 1000.0,
            (apply_elapsed.as_secs_f64() / elapsed.as_secs_f64()) * 100.0,
            (total_wave_time / prepared.len().max(1) as f64) * 1000.0,
            max_wave_time * 1000.0,
            finalize_elapsed.as_secs_f64() * 1000.0,
            (finalize_elapsed.as_secs_f64() / elapsed.as_secs_f64()) * 100.0
        );

        ExecOutcome::new(block, elapsed, tx_count)
    }
}