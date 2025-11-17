use anyhow::{Context, Result};
use reqwest::Client;
use std::fs::{self, OpenOptions, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH, Instant};
use tokio::time::sleep;
use tokio::time::timeout;
use rand::{thread_rng, Rng};
use serde::Deserialize;

// needed for `.abi_encode()` on the PI tuple
use alloy_sol_types::SolValue;

use crate::metrics::{
    JOBS_TOTAL,
    LAST_HEIGHT,
    FAILURES_TOTAL,
    JobTimer,
    GC_REMOVED_TOTAL,
    CLAIMS_TOTAL,
    CLAIM_TIMEOUTS_TOTAL,
    GAPS_HEALED_TOTAL,
};

use crate::pi_builder::build_pi_for_height;
use crate::v1_mldsa::prove_mldsa_batch;

// Use the atomic writer that drops a READY marker last + GC hook (T37.8)
use crate::proof_writer::{write_proof_files_atomic_with_ready, write_proof_files_with_digest_atomic, gc_proof_dirs, write_snark_proof_stub};
use crate::pi_canonical::CanonicalPi;
use blake3::hash as blake3_hash;

/// Jittered sleep: waits for `base_ms + [0, jitter_ms]`.
#[inline]
async fn sleep_with_jitter(base_ms: u64, jitter_ms: u64) {
    let mut rng = thread_rng();
    let extra: u64 = if jitter_ms == 0 { 0 } else { rng.gen_range(0..=jitter_ms) };
    sleep(Duration::from_millis(base_ms + extra)).await;
}

// tiny helpers for readability
const OK_BASE_MS: u64 = 300;      // after a successful proof
const RETRY_BASE_MS: u64 = 1200;  // base when header not ready / parse failed
const RETRY_JITTER_MS: u64 = 250; // jitter window for retries
const RETRY_MAX_MS: u64 = 10_000; // max backoff cap

// env-tunable knobs (fallbacks keep behavior sane if env missing)
fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}
fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => default,
    }
}
fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

#[derive(Deserialize)]
struct BridgeSummary { latest_height: u64 }

/// The configuration for the prover loop.
pub struct ProverConfig {
    pub node_url: String,          // e.g. "http://127.0.0.1:8080"
    pub proof_root: PathBuf,       // e.g. "/home/user/eezo/proof"
    pub checkpoint_every: u64,     // 32
    pub batch_size: u32,           // e.g. 16
    pub chain_id20: [u8; 20],      // bound into PI v2
    pub poll_interval_ms: u64,     // default 500
    // (kept for future LC-follow)
    pub eth_rpc: String,           // e.g. "http://127.0.0.1:8545"
    pub lc_addr: String,           // 0x...
}

/// Round x up to the next multiple of m (m>0).
fn round_up_to_multiple(x: u64, m: u64) -> u64 {
    if m == 0 { return x; }
    let r = x % m;
    if r == 0 { x } else { x + (m - r) }
}

fn ready_marker_path(dir: &Path) -> PathBuf {
    dir.join("READY")
}

fn ready_marker_exists(dir: &Path) -> bool {
    ready_marker_path(dir).exists()
}

fn lock_path(dir: &Path) -> PathBuf {
    dir.join(".lock")
}

/// Clean any stale partials in a target dir.
fn clean_partials(dir: &Path) -> Result<()> {
    let pi_partial = dir.join("public_inputs.hex.partial");
    let pf_partial = dir.join("proof.hex.partial");
	let dg_partial = dir.join("pi_digest.hex.partial");
    if pi_partial.exists() { fs::remove_file(&pi_partial).context("remove pi.partial")?; }
    if pf_partial.exists() { fs::remove_file(&pf_partial).context("remove pf.partial")?; }
	if dg_partial.exists() { fs::remove_file(&dg_partial).context("remove pi_digest.partial")?; }
    Ok(())
}

/// Try to read the node's latest checkpoint height from /bridge/summary.
/// Returns Ok(height) on success; on timeout or parse error we bubble the error
/// and the caller will just back off lightly.
async fn fetch_latest_height(client: &Client, node_url: &str) -> Result<u64> {
    // keep this very short so it never blocks the loop for long
    let url = format!("{}/bridge/summary", node_url.trim_end_matches('/'));
    // 2s hard cap on the HTTP call
    let resp = timeout(
        Duration::from_secs(2),
        client.get(&url).send()
    )
    .await
    .context("latest: http timeout")?
    .context("latest: http send")?;

    let bs: BridgeSummary = resp.json().await.context("latest: json")?;
    Ok(bs.latest_height)
}

/// Return the lowest checkpoint height (multiple of `interval`) whose folder lacks READY.
fn next_missing_height_from_fs(root: &Path, interval: u64) -> u64 {
    // start at the first checkpoint (interval), then step by `interval`
    let mut h = interval.max(1);
    loop {
        let dir = root.join(format!("h{}", h));
        let ready = ready_marker_exists(&dir);
        if !ready {
            return h;
        }
        h = h.saturating_add(interval);
    }
}

/// Remove a stale lock if older than the configured threshold.
fn maybe_reclaim_stale_lock(dir: &Path, stale_secs: u64) -> Result<bool> {
    let lp = lock_path(dir);
    if !lp.exists() { return Ok(false); }
    let meta = fs::metadata(&lp).context("lock metadata")?;
    let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let age = SystemTime::now().duration_since(mtime).unwrap_or(Duration::from_secs(0)).as_secs();
        if age >= stale_secs {
        fs::remove_file(&lp).context("remove stale lock")?;
        // metrics: this is a stale claim timeout
        CLAIM_TIMEOUTS_TOTAL.inc();
        return Ok(true);
    }
    Ok(false)
}

/// Try to acquire a lock by creating `.lock` with O_EXCL semantics.
fn try_acquire_lock(dir: &Path) -> Result<Option<File>> {
    let lp = lock_path(dir);
    match OpenOptions::new().write(true).create_new(true).open(&lp) {
        Ok(mut f) => {
            // write a tiny payload (pid + timestamp), then fsync
            let pid = std::process::id();
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let _ = write!(f, "pid={pid} ts={ts}\n");
            let _ = f.sync_all();
            Ok(Some(f))
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(None)
            } else {
                Err(e).context("acquire lock")
            }
        }
    }
}

/// Startup healer: scan `proof/` and fix any half-done work.
fn heal_backlog(root: &Path, interval: u64, stale_secs: u64) -> Result<(u64, u64)> {
    let mut healed_partials = 0u64;
    let mut reclaimed = 0u64;
    // iterate heights we might have created; we don't know max, so walk existing dirs
    if let Ok(read) = fs::read_dir(root) {
        for ent in read.flatten() {
            let p = ent.path();
            if !p.is_dir() { continue; }
            let name = ent.file_name().to_string_lossy().to_string();
            if !name.starts_with('h') { continue; }
            // best-effort parse of "h{H}"
            if let Ok(h) = name[1..].parse::<u64>() {
                if h % interval != 0 { continue; }
                if ready_marker_exists(&p) { continue; }
                // clean partials
                clean_partials(&p).ok();
                healed_partials += 1;
                // reclaim stale locks if any
                if maybe_reclaim_stale_lock(&p, stale_secs).unwrap_or(false) {
                    reclaimed += 1;
                }
            }
        }
    }
    Ok((healed_partials, reclaimed))
}

/// Exponential backoff helper, capped at RETRY_MAX_MS.
fn next_backoff_ms(cur: u64) -> u64 {
    let doubled = cur.saturating_mul(2);
    std::cmp::min(doubled, RETRY_MAX_MS)
}


/// The main automatic loop.
/// It never returns unless a fatal filesystem error happens.
pub async fn run_prover_loop(cfg: ProverConfig) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("failed building HTTP client")?;
    // healer: reclaim stale locks & clean partials once on startup
    let lock_stale_secs = env_u64("EEZO_PROVER_LOCK_STALE_SECS", 300); // 5 minutes
    let (healed, reclaimed) = heal_backlog(&cfg.proof_root, cfg.checkpoint_every, lock_stale_secs)?;
        if healed > 0 || reclaimed > 0 {
        log::info!(
            "prover: startup heal — cleaned_partials={} reclaimed_locks={}",
            healed,
            reclaimed
        );
        // metrics: count how many gap dirs we healed (partials cleaned)
        GAPS_HEALED_TOTAL.inc_by(healed as u64);
        // metrics: reclaimed stale locks are also counted as claim timeouts
        CLAIM_TIMEOUTS_TOTAL.inc_by(reclaimed as u64);
    }

    // how many checkpoint rotations to keep on disk (T37.8 lifecycle policy)
    // e.g., with interval=32 and retain_rotations=2, we keep ~64 heights worth.
    let retain_rotations = env_u64("EEZO_PROVER_RETAIN_ROTATIONS", 2);

    // retry budget per height
    let max_retries_per_height = env_u32("EEZO_PROVER_MAX_RETRIES", 8);		

    loop {
        // 1) Pick the *lowest missing* checkpoint height from the filesystem.
        //    This naturally aligns with LC+relay which always need the next multiple (h32, h64, ...).
        let next_h = next_missing_height_from_fs(&cfg.proof_root, cfg.checkpoint_every);
        log::info!("prover: next target (lowest-missing from fs) = {}", next_h);

        // 1.1) Guard: don't start work until the node has actually emitted at least this height.
        // This avoids long stretches of backoff while the node hasn't reached the next multiple yet.
        match fetch_latest_height(&client, &cfg.node_url).await {
            Ok(latest) => {
                if latest < next_h {
                    log::debug!(
                        "prover: node latest={} < target={}, waiting for next emission...",
                        latest, next_h
                    );
                    // small, polite wait; don't create dirs or locks yet
                    sleep_with_jitter(OK_BASE_MS, 150).await;
                    continue;
                }
            }
            Err(e) => {
                // If we can't read the latest now, just wait briefly and retry the loop.
                log::warn!("prover: failed to read /bridge/summary → {} (will retry)", e);
                sleep_with_jitter(RETRY_BASE_MS, RETRY_JITTER_MS).await;
                continue;
            }
        }

        let h_dir = cfg.proof_root.join(format!("h{}", next_h));

        // 2) Idempotency: if READY already present, skip and poll again.
        if ready_marker_exists(&h_dir) {
            log::debug!("prover: h{} already ready; polling again soon.", next_h);
            sleep_with_jitter(OK_BASE_MS, 150).await;
            continue;
        }
        // Ensure directory exists and stale partials are gone.
        fs::create_dir_all(&h_dir).context("mkdir h{H}")?;
        clean_partials(&h_dir)?;

        // 2.5) LOCK: claim the height to avoid clashes with other provers.
        // First, attempt stale-lock reclamation; then try to create a new lock.
        let _ = maybe_reclaim_stale_lock(&h_dir, lock_stale_secs)?;
        let maybe_lock = try_acquire_lock(&h_dir)?;
        if maybe_lock.is_none() {
            // someone else is working on it; back off briefly and re-scan
            log::debug!("prover: h{} locked by another prover; backing off.", next_h);
            sleep_with_jitter(OK_BASE_MS, 150).await;
            continue;
        }
        // we own the lock from here; drop on success or on giving up
        let mut _lock_file = maybe_lock.unwrap();
        // metrics: track claimed heights
        CLAIMS_TOTAL.inc();		

        // bounded retry with exponential backoff for this height
        let mut tries: u32 = 0;
        let mut backoff_ms: u64 = RETRY_BASE_MS;
        let height_start = Instant::now();		

        // Try fetching header + building PI
        loop {
            match build_pi_for_height(
                &client,
                &cfg.node_url,
                next_h,
                cfg.chain_id20,
                cfg.batch_size,
            )
            .await
            {
                Ok((pis, triples)) => {
                    let timer = JobTimer::start();
                    // --------------------------
                    // Call ML-DSA prover
                    // --------------------------
                    let proof = match prove_mldsa_batch(
                        &pis,
                        triples.iter().map(|(pk, msg, sig)| (&pk[..], &msg[..], &sig[..])),
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            log::error!("prover: prove_mldsa_batch failed at h={} → {}", next_h, e);
                            FAILURES_TOTAL.inc();
                            tries = tries.saturating_add(1);
                            if tries >= max_retries_per_height {
                                log::warn!("prover: giving up (proof failure budget exceeded) on h{}; releasing lock.", next_h);
                                // drop lock by exiting loop
                                break;
                            }
                            sleep_with_jitter(backoff_ms, RETRY_JITTER_MS).await;
                            backoff_ms = next_backoff_ms(backoff_ms);
                            continue;
                        }
                    };

                    // ABI-encoded PI for the relay to submit
                    let pi_abi = pis.as_abi_tuple().abi_encode();

                    // runtime toggle: whether to emit pi_digest.hex (default: true)
                    let write_pi_digest = env_bool("EEZO_PROVER_WRITE_PI_DIGEST", true);
                    let (maybe_digest, digest_hex_opt);
                    if write_pi_digest {
                        // ---- T38.7: build CanonicalPi digest (rotation/suite aware) ----
                        // synthetic header_hash = blake3(tx_root || state_root || sig_batch_digest)
                        let mut concat = Vec::with_capacity(32 + 32 + 32);
                        concat.extend_from_slice(&pis.tx_root_v2);
                        concat.extend_from_slice(&pis.state_root_v2);
                        concat.extend_from_slice(&pis.sig_batch_digest);
                        let hdr_hash: [u8;32] = (*blake3_hash(&concat).as_bytes()).into();
                        let canon = CanonicalPi {
                            chain_id20: cfg.chain_id20,
                            suite_id: (pis.suite_id as u8),
                            circuit_version: pis.circuit_version as u8,
                            ssz_version: 2,
                            header_hash: hdr_hash,
                            txs_root_v2: pis.tx_root_v2,
                            state_root_v2: pis.state_root_v2,
                            sig_batch_digest: pis.sig_batch_digest,
                            height: pis.height,
                        };
                        let pi_digest = canon.digest(); // [u8;32]
                        maybe_digest = Some(pi_digest);
                        digest_hex_opt = Some(format!("0x{}", hex::encode(pi_digest)));
                    } else {
                        maybe_digest = None;
                        digest_hex_opt = None;
                    }

                    // --------------------------
                    // Atomic write (+ optional pi_digest.hex) + READY marker
                    // --------------------------
                    let hdir = cfg.proof_root.join(format!("h{}", next_h));
                    let write_res = if let Some(d) = maybe_digest {
                        write_proof_files_with_digest_atomic(&hdir, &pi_abi, &proof, Some(&d)).await
                    } else {
                        write_proof_files_atomic_with_ready(&hdir, &pi_abi, &proof).await
                    };
                    if let Err(e) = write_res {
                        log::error!("prover: write failed for h={} → {}", next_h, e);
                        FAILURES_TOTAL.inc();
                        tries = tries.saturating_add(1);
                        if tries >= max_retries_per_height {
                            log::warn!("prover: giving up (write failure budget exceeded) on h{}; releasing lock.", next_h);
                            break;
                        }
                        sleep_with_jitter(backoff_ms, RETRY_JITTER_MS).await;
                        backoff_ms = next_backoff_ms(backoff_ms);
                        continue;
                    } else {
                        // success path: release lock by removing it explicitly
                        let _ = fs::remove_file(lock_path(&hdir));
                        JOBS_TOTAL.inc();
                        LAST_HEIGHT.set(next_h as i64);
                        timer.finish();
                        log::info!("prover: wrote proof for height {} (elapsed {:?})", next_h, height_start.elapsed());
                        if let Some(dhex) = digest_hex_opt {
                            log::info!("prover: pi_digest for h{} = {}", next_h, dhex);
                        }

                        // 🎯 PATCH: Write the required snark_proof.bin stub
                        if let Some(d) = maybe_digest {
                             if let Err(e) = write_snark_proof_stub(&hdir, &d).await {
                                log::warn!("prover: failed to write snark stub for h{} → {}", next_h, e);
                                // non-fatal warning, proceed with STARK flow
                             }
                        }

                        // ── T37.8: run GC after a successful READY write ────────────────
                        match gc_proof_dirs(&cfg.proof_root, next_h, cfg.checkpoint_every, retain_rotations) {
                            Ok(removed) => {
                                if removed > 0 {
                                    log::info!("prover: gc removed {} old proof dir(s) after h{}", removed, next_h);
									GC_REMOVED_TOTAL.inc_by(removed as u64);
                                } else {
                                    log::debug!("prover: gc removed 0 dirs (retain_rotations={})", retain_rotations);
                                }
                            }
                            Err(e) => {
                                // non-fatal: GC failures should not block the loop
                                log::warn!("prover: gc failed after h{} → {}", next_h, e);
                            }
                        }
                        break; // done with this height
                    }
                }
                Err(e) => {
                    // header/PI not ready; backoff and retry within the same claimed height
                    log::warn!("prover: header/PI not ready for h={} → {}. Retrying with backoff ({} ms).", next_h, e, backoff_ms);
                    FAILURES_TOTAL.inc();
                    tries = tries.saturating_add(1);
                    if tries >= max_retries_per_height {
                        log::warn!("prover: giving up (pi-builder budget exceeded) on h{}; releasing lock.", next_h);
                        break;
                    }
                    sleep_with_jitter(backoff_ms, RETRY_JITTER_MS).await;
                    backoff_ms = next_backoff_ms(backoff_ms);
                }
            }
        }
        // ensure lock is gone if we gave up
        let _ = fs::remove_file(lock_path(&h_dir));
 
         // Short sleep after a successful proof write.
        sleep_with_jitter(OK_BASE_MS, 150).await;
    }
}