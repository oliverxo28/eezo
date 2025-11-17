use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
//use std::path::Path as _; // keep Path in scope for spawn_blocking clone
use std::ffi::OsStr;
use log::{debug, info, warn};

/// Ensure directory exists, equivalent to `mkdir -p`.
fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory {:?}", path))?;
    Ok(())
}

/// Return `<dir>/READY` path.
pub fn ready_marker_path(dir: &Path) -> PathBuf {
    dir.join("READY")
}

/// Check if `<dir>/READY` exists.
pub fn ready_marker_exists(dir: &Path) -> bool {
    ready_marker_path(dir).exists()
}

/// Write a byte vector as lowercase hex into a file.
/// The file is truncated each time.
fn write_hex_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }

    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("failed to open {:?}", path))?;

    let hex = hex::encode(bytes);
    f.write_all(hex.as_bytes())
        .with_context(|| format!("failed to write hex into {:?}", path))?;

    Ok(())
}
/// Atomically write hex by first writing to `*.partial` and then renaming.
fn atomic_write_hex_file(final_path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = final_path.parent() {
        ensure_dir(parent)?;
    }
    let tmp_path = final_path.with_extension("partial");
    // 1) write to temporary
    write_hex_file(&tmp_path, bytes)
        .with_context(|| format!("failed to write temporary {:?}", tmp_path))?;
    // 2) rename atomically over the final destination
    fs::rename(&tmp_path, final_path)
        .with_context(|| format!("failed to atomically rename {:?} -> {:?}", tmp_path, final_path))?;
    Ok(())
}

/// Clean up any lingering `*.partial` files inside a given proof dir.
pub fn clean_partials(dir: &Path) -> Result<()> {
    let pi_partial = dir.join("public_inputs.hex.partial");
    let pf_partial = dir.join("proof.hex.partial");
    if pi_partial.exists() {
        fs::remove_file(&pi_partial).context("remove public_inputs.hex.partial")?;
    }
    if pf_partial.exists() {
        fs::remove_file(&pf_partial).context("remove proof.hex.partial")?;
    }
    Ok(())
}

/// Path to `.lock` in a given proof dir.
pub fn lock_path(dir: &Path) -> PathBuf {
    dir.join(".lock")
}

/// Try to acquire a lock by creating `.lock` with O_EXCL-like semantics.
/// Returns `Ok(Some(File))` if lock acquired, `Ok(None)` if already locked.
pub fn try_acquire_lock(dir: &Path) -> Result<Option<File>> {
    ensure_dir(dir)?;
    let lp = lock_path(dir);
    match OpenOptions::new().create_new(true).write(true).open(&lp) {
        Ok(mut f) => {
            let pid = std::process::id();
            let ts = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _ = writeln!(f, "pid={pid} ts={ts}");
            let _ = f.sync_all();
            Ok(Some(f))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(e).context("acquire .lock failed"),
    }
}

/// Remove a `.lock` file if present.
pub fn remove_lock(dir: &Path) -> Result<()> {
    let lp = lock_path(dir);
    if lp.exists() {
        fs::remove_file(&lp).context("remove .lock")?;
    }
    Ok(())
}

/// Touch a READY marker to indicate both files are fully written.
fn write_ready_marker(dir: &Path) -> Result<()> {
    ensure_dir(dir)?;
    let path = ready_marker_path(dir);
    let f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .with_context(|| format!("failed to create READY marker at {:?}", path))?;
    // fsync so the marker is durable before the relay reacts to it
    f.sync_all()
        .with_context(|| format!("failed to fsync READY marker at {:?}", path))?;
    // best-effort directory sync to increase durability on some FSes
    if let Some(dirpath) = path.parent() {
        if let Ok(dirfd) = OpenOptions::new().read(true).open(dirpath) {
            let _ = dirfd.sync_all();
        }
    }
    Ok(())
}

/// Write a stub SNARK proof file (e.g., a simple digest of the PI)
/// to snark_proof.bin in the given directory.
pub async fn write_snark_proof_stub(dir: &Path, pi_digest: &[u8]) -> Result<()> {
    let path = dir.join("snark_proof.bin");
    // The placeholder SNARK verifier requires the proof to be 32 bytes and equal to the PI digest.
    // We use the PI digest bytes as the proof stub.
    if pi_digest.len() != 32 {
        anyhow::bail!("pi_digest must be 32 bytes for snark stub");
    }
    
    // Write raw bytes (not hex)
    tokio::fs::write(&path, pi_digest)
        .await
        .with_context(|| format!("failed to write snark proof stub to {:?}", path))?;

    log::info!(target: "eezo_prover", "prover: emitted snark_proof.bin stub for dir={:?}", dir);
    Ok(())
}

/// Top-level entry: write both PI and proof into
/// proof/h{height}/public_inputs.hex
/// proof/h{height}/proof.hex
pub fn write_proof_files(
    root: &Path,     // e.g. "/mnt/data/eezo/proof"
    height: u64,
    public_inputs: &[u8],
    proof: &[u8],
) -> Result<PathBuf> {
    // Build directory: /proof/h{H}
    let dir = root.join(format!("h{}", height));
    ensure_dir(&dir)?;

    let pi_file = dir.join("public_inputs.hex");
    let pf_file = dir.join("proof.hex");

    // Write atomically: *.partial -> rename, then mark READY
    atomic_write_hex_file(&pi_file, public_inputs)
        .with_context(|| format!("failed atomic write {:?}", pi_file))?;
    atomic_write_hex_file(&pf_file, proof)
        .with_context(|| format!("failed atomic write {:?}", pf_file))?;
    write_ready_marker(&dir)?;
	
	// 🎯 ADD THE NEW LOG HERE:
	log::info!(target: "eezo_prover", "prover: completed package for h{:05} dir={:?} (public_inputs.hex + proof.hex)", height, dir);

    Ok(dir)
}
/// Async wrapper used by the prover loop:
/// write both files atomically into an existing `h{H}` directory and then create `READY`.
/// This matches the symbol imported by `prover_loop.rs`.
pub async fn write_proof_files_atomic_with_ready(
    dir: &Path,
    public_inputs_hex: &[u8],
    proof_hex: &[u8],
) -> Result<()> {
    // Move data into the blocking task
    let dir = dir.to_path_buf();
    let pi = public_inputs_hex.to_vec();
    let pf = proof_hex.to_vec();

    tokio::task::spawn_blocking(move || -> Result<()> {
        // Ensure directory exists
        ensure_dir(&dir)?;

        // Final file paths
        let pi_file = dir.join("public_inputs.hex");
        let pf_file = dir.join("proof.hex");
        // Clean any partials first (defensive, helps gap healing).
        let _ = clean_partials(&dir);

        // Atomic writes: *.partial -> rename
        atomic_write_hex_file(&pi_file, &pi)
            .with_context(|| format!("failed atomic write {:?}", pi_file))?;
        atomic_write_hex_file(&pf_file, &pf)
            .with_context(|| format!("failed atomic write {:?}", pf_file))?;

        // Touch READY as the last step (relay uses this as submit signal)
        write_ready_marker(&dir)?;
        Ok(())
    })
    .await
    .expect("spawn_blocking(join) failed")?;

    Ok(())
}
/// NEW: async writer for an optional `pi_digest.hex` alongside PI+proof.
/// If `pi_digest_hex` is `None`, behavior is identical to the 2-file writer.
pub async fn write_proof_files_with_digest_atomic(
    dir: &Path,
    public_inputs_hex: &[u8],
    proof_hex: &[u8],
    pi_digest_hex: Option<&[u8]>,
) -> Result<()> {
    // Move data into the blocking task
    let dir = dir.to_path_buf();
    let pi = public_inputs_hex.to_vec();
    let pf = proof_hex.to_vec();
    let dg = pi_digest_hex.map(|b| b.to_vec());

    tokio::task::spawn_blocking(move || -> Result<()> {
        ensure_dir(&dir)?;
        let pi_file = dir.join("public_inputs.hex");
        let pf_file = dir.join("proof.hex");
        let dg_file = dir.join("pi_digest.hex");
        let _ = clean_partials(&dir);

        atomic_write_hex_file(&pi_file, &pi)
            .with_context(|| format!("failed atomic write {:?}", pi_file))?;
        atomic_write_hex_file(&pf_file, &pf)
            .with_context(|| format!("failed atomic write {:?}", pf_file))?;
        if let Some(d) = dg {
            atomic_write_hex_file(&dg_file, &d)
                .with_context(|| format!("failed atomic write {:?}", dg_file))?;
        }
        write_ready_marker(&dir)?;
        Ok(())
    })
    .await
    .expect("spawn_blocking(join) failed")?;
    Ok(())
}
// ─────────────────────────────────────────────────────────────────────────────
// GC / lifecycle helpers (T37.8)
// ─────────────────────────────────────────────────────────────────────────────

/// Consider a partial dir "hot" for this TTL; we won't delete it during that window.
const PARTIAL_TTL: Duration = Duration::from_secs(10 * 60); // 10 minutes

fn parse_height_from_name(name: &OsStr) -> Option<u64> {
    let s = name.to_str()?;
    if let Some(rest) = s.strip_prefix('h') {
        return rest.parse::<u64>().ok();
    }
    None
}

fn has_lock(dir: &Path) -> bool {
    lock_path(dir).exists()
}

fn has_ready(dir: &Path) -> bool {
    ready_marker_exists(dir)
}

fn entry_modified_age(path: &Path) -> Option<Duration> {
    let meta = fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    SystemTime::now().duration_since(mtime).ok()
}

/// List `(height, path)` for directories named `h{height}` directly under `root`.
fn list_proof_dirs(root: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    for ent in fs::read_dir(root).with_context(|| format!("read_dir {:?}", root))? {
        let ent = ent?;
        if ent.file_type()?.is_dir() {
            let name = ent.file_name();
            if let Some(h) = parse_height_from_name(&name) {
                out.push((h, ent.path()));
            }
        }
    }
    out.sort_by_key(|(h, _)| *h);
    Ok(out)
}

/// Garbage-collect proof dirs:
/// - Keep the last `retain_rotations * checkpoint_every` worth of heights.
/// - Remove **older** completed dirs (with READY).
/// - Remove **old partials** (without READY) only if older than `PARTIAL_TTL`.
/// - Never touch dirs with `.lock` present.
///
/// Returns number of directories removed.
pub fn gc_proof_dirs(
    root: &Path,
    current_height: u64,
    checkpoint_every: u64,
    retain_rotations: u64,
) -> Result<usize> {
    let mut removed = 0usize;
    let keep_span = checkpoint_every.saturating_mul(retain_rotations);
    let keep_floor = current_height.saturating_sub(keep_span);

    for (h, dir) in list_proof_dirs(root)? {
        if h >= keep_floor {
            // recent enough, always keep
            continue;
        }
        if has_lock(&dir) {
            debug!(target: "eezo_prover", "gc: skipping hot/locked h{:05} dir={:?}", h, dir);
            continue;
        }
        if has_ready(&dir) {
            // completed, old -> safe to delete
            match fs::remove_dir_all(&dir) {
                Ok(()) => {
                    info!(target: "eezo_prover", "gc: removed stale h{:05} dir={:?}", h, dir);
                    removed += 1;
                }
                Err(e) => {
                    warn!(target: "eezo_prover", "gc: failed to remove stale h{:05} dir={:?} error={:?}", h, dir, e);
                }
            }
        } else {
            // partial; only delete if sufficiently old
            let age = entry_modified_age(&dir).unwrap_or_default();
            if age >= PARTIAL_TTL {
                match fs::remove_dir_all(&dir) {
                    Ok(()) => {
                        info!(target: "eezo_prover", "gc: removed partial h{:05} dir={:?} age_secs={}", h, dir, age.as_secs());
                        removed += 1;
                    }
                    Err(e) => {
                        warn!(target: "eezo_prover", "gc: failed to remove partial h{:05} dir={:?} error={:?}", h, dir, e);
                    }
                }
            } else {
                debug!(target: "eezo_prover", "gc: skipping hot partial h{:05} dir={:?} age_secs={}", h, dir, age.as_secs());
            }
        }
    }
    Ok(removed)
}