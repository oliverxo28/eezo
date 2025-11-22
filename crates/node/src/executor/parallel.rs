//! executor/parallel.rs
//!
//! T54 — Parallel block executor for EEZO.
//!
//! Sealevel-style “wave” scheduling:
//!   1) build per-tx access lists
//!   2) pack a wave of non-conflicting txs
//!   3) execute the wave in parallel
//!   4) commit via a locked BlockBuildContext wrapper
//!
//! All state mutations happen through the context guard to keep safety simple.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rayon::prelude::*;

use eezo_ledger::{ConsensusError, SignedTx, SingleNode};
use eezo_ledger::Block;
use crate::executor::{ExecInput, ExecOutcome, Executor};

// optional metrics
#[cfg(feature = "metrics")]
use crate::metrics::{
    EEZO_EXEC_PARALLEL_WAVES_TOTAL,
    EEZO_EXEC_PARALLEL_WAVE_LEN,
    EEZO_EXEC_PARALLEL_APPLY_SECONDS,
};

#[derive(Debug)]
struct TxMeta<'a> {
    tx: &'a SignedTx,
    access: Vec<eezo_ledger::tx::Access>,
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

        // 1) gather access lists (conflict detection data)
        let metas: Vec<TxMeta> = input
            .txs
            .iter()
            .map(|tx| TxMeta { tx, access: tx.access_list() })
            .collect();

        // 2) create the shared block-build context (coarse lock)
        // Ensure BlockBuildContext::start uses correct, explicit parameters.
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
        let mut ctx = eezo_ledger::block::BlockBuildContext::start(
            prev,
            input.height,
            timestamp_ms,
            accounts,
            supply,
        );
        let ctx = Arc::new(Mutex::new(ctx));

        // 3) schedule waves
        let mut waves: Vec<Vec<&SignedTx>> = Vec::new();
        {
            let mut remaining: Vec<&TxMeta> = metas.iter().collect();

            while !remaining.is_empty() {
                let mut used = HashSet::new();
                let mut wave: Vec<&SignedTx> = Vec::new();
                let mut next_remaining = Vec::with_capacity(remaining.len());

                for meta in remaining {
                    // check for any overlap with already-used targets
                    let mut conflict = false;
                    for a in &meta.access {
                        if used.contains(&a.target) {
                            conflict = true;
                            break;
                        }
                    }

                    if conflict {
                        next_remaining.push(meta);
                    } else {
                        for a in &meta.access {
                            used.insert(a.target);
                        }
                        wave.push(meta.tx);
                    }
                }

                waves.push(wave);
                remaining = next_remaining;
            }
        }

        #[cfg(feature = "metrics")]
        {
            for wave in &waves {
                EEZO_EXEC_PARALLEL_WAVE_LEN.observe(wave.len() as f64);
            }
            EEZO_EXEC_PARALLEL_WAVES_TOTAL.inc_by(waves.len() as u64);
        }

        // 4) execute waves
        for wave in waves {
            let wave_start = Instant::now();

            // apply each tx via the guarded context; mutations happen behind the lock
            wave.par_iter().for_each(|stx| {
                let res = {
                    let mut guard = ctx.lock().expect("ctx lock poisoned");
                    guard.apply_tx_parallel_safe(stx)
                };

                if let Err(e) = res {
                    // mark failure; executor will abort after this wave
                    let mut guard = ctx.lock().expect("ctx lock poisoned");
                    guard.flag_error(e);
                }
            });

            #[cfg(feature = "metrics")]
            {
                let sec = wave_start.elapsed().as_secs_f64().max(0.0);
                EEZO_EXEC_PARALLEL_APPLY_SECONDS.observe(sec);
            }

            // stop early if any tx failed in this wave
            if ctx.lock().expect("ctx lock poisoned").has_error() {
                break;
            }
        }

        // 5) finalize
        let elapsed = start.elapsed();
        let (maybe_block, failed) = {
            let guard = ctx.lock().expect("ctx lock poisoned");
            let has_err = guard.has_error();
            let blk = if !has_err { Some(guard.finish()) } else { None };
            (blk, has_err)
        };

        if failed {
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

        ExecOutcome::new(block, elapsed, tx_count)
    }
}