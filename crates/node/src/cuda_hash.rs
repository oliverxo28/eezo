// =============================================================================
// T91.2 — CUDA BLAKE3 Shadow Path for eezo-node
// =============================================================================
//
// This module provides the CUDA BLAKE3 shadow hashing path for eezo-node.
// CPU BLAKE3 remains canonical (no consensus changes).
//
// When EEZO_CUDA_HASH_ENABLED=1 at runtime, the node will:
// 1. Use CudaBlake3Engine::hash_many() to hash all block tx payloads on CUDA.
// 2. Compare the CUDA digests against CPU BLAKE3 for the same data.
// 3. Record metrics about successes/failures/mismatches/bytes.
//
// If CUDA is unavailable or fails, the node gracefully falls back to CPU-only.
// =============================================================================

use std::env;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "cuda-hash")]
use eezo_cuda_hash::{CudaBlake3Engine, CudaBlake3Error};

// Static flag to track whether we've logged CUDA init status
static CUDA_INIT_LOGGED: AtomicBool = AtomicBool::new(false);

/// Number of bytes to display when logging hash prefixes (4 bytes = 8 hex chars).
#[cfg(feature = "cuda-hash")]
const HASH_DISPLAY_PREFIX_BYTES: usize = 4;

/// T91.2: Check if CUDA hashing is enabled via EEZO_CUDA_HASH_ENABLED env var.
///
/// Returns true only if EEZO_CUDA_HASH_ENABLED=1.
/// Default is off (returns false).
pub fn is_cuda_hash_enabled() -> bool {
    env::var("EEZO_CUDA_HASH_ENABLED")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// T91.2: Run CUDA BLAKE3 shadow hash comparison for a block's transaction payloads.
///
/// This function is called after a block is committed. It:
/// 1. Checks if EEZO_CUDA_HASH_ENABLED=1; returns immediately if not.
/// 2. Skips if tx_bytes is empty.
/// 3. Lazily initializes a CudaBlake3Engine (stored in cuda_engine).
/// 4. Computes CUDA hashes via hash_many().
/// 5. Computes CPU BLAKE3 hashes as ground truth.
/// 6. Compares all digests and updates metrics.
///
/// CPU BLAKE3 is always canonical. CUDA is for diagnostic/comparison only.
/// This function never panics; all errors are logged and counted.
///
/// # Arguments
///
/// * `cuda_engine` - Mutable reference to cached engine (None = not yet initialized)
/// * `tx_bytes` - Slice of transaction byte vectors to hash
#[cfg(feature = "cuda-hash")]
pub fn run_t91_2_cuda_hash_shadow(
    cuda_engine: &mut Option<CudaBlake3Engine>,
    tx_bytes: &[Vec<u8>],
) {
    // 1. Check runtime toggle
    if !is_cuda_hash_enabled() {
        return;
    }

    // 2. Skip empty batches
    if tx_bytes.is_empty() {
        return;
    }

    // 3. Lazily initialize CUDA engine
    if cuda_engine.is_none() {
        match CudaBlake3Engine::new() {
            Ok(engine) => {
                // Successfully initialized - store and set gauge
                *cuda_engine = Some(engine);
                crate::metrics::cuda_hash_enabled_set(1);
                
                // Log one-time message
                if !CUDA_INIT_LOGGED.swap(true, Ordering::Relaxed) {
                    log::info!("T91.2: CUDA BLAKE3 engine initialized for shadow hashing");
                }
            }
            Err(e) => {
                // Initialization failed - count failure
                crate::metrics::cuda_hash_failures_inc();
                crate::metrics::cuda_hash_enabled_set(0);
                
                // Log one-time warning
                if !CUDA_INIT_LOGGED.swap(true, Ordering::Relaxed) {
                    log::warn!(
                        "T91.2: CUDA engine initialization failed (shadow hashing disabled): {}",
                        e
                    );
                }
                return;
            }
        }
    }

    // 4. Get reference to engine (guaranteed to be Some after init)
    let engine = cuda_engine.as_ref().expect(
        "T91.2: cuda_engine should be Some after successful initialization"
    );

    // 5. Prepare input slices for hash_many
    let input_slices: Vec<&[u8]> = tx_bytes.iter().map(|v| v.as_slice()).collect();

    // 6. Call CUDA hash_many
    let cuda_result = engine.hash_many(&input_slices);

    match cuda_result {
        Ok(cuda_hashes) => {
            // 7. Compute CPU BLAKE3 hashes as ground truth
            let cpu_hashes: Vec<[u8; 32]> = tx_bytes
                .iter()
                .map(|bytes| *blake3::hash(bytes).as_bytes())
                .collect();

            // 8. Compare lengths
            if cuda_hashes.len() != cpu_hashes.len() {
                log::warn!(
                    "T91.2: CUDA/CPU hash count mismatch (CUDA={}, CPU={})",
                    cuda_hashes.len(),
                    cpu_hashes.len()
                );
                crate::metrics::cuda_hash_mismatch_inc();
                return;
            }

            // 9. Compare each digest
            let mut any_mismatch = false;
            for (i, (cuda, cpu)) in cuda_hashes.iter().zip(cpu_hashes.iter()).enumerate() {
                if cuda != cpu {
                    any_mismatch = true;
                    log::warn!(
                        "T91.2: CUDA/CPU hash mismatch at tx index {}: CUDA=0x{} CPU=0x{}",
                        i,
                        hex::encode(&cuda[..HASH_DISPLAY_PREFIX_BYTES]),
                        hex::encode(&cpu[..HASH_DISPLAY_PREFIX_BYTES])
                    );
                    crate::metrics::cuda_hash_mismatch_inc();
                }
            }

            // 10. If all match, record success
            if !any_mismatch {
                crate::metrics::cuda_hash_jobs_inc();
                
                // Sum up total input bytes
                let total_bytes: u64 = tx_bytes.iter().map(|v| v.len() as u64).sum();
                crate::metrics::cuda_hash_bytes_inc(total_bytes);
                
                log::debug!(
                    "T91.2: CUDA shadow hash verified {} txs ({} bytes)",
                    tx_bytes.len(),
                    total_bytes
                );
            }
        }
        Err(e) => {
            // CUDA compute failed - count and log
            crate::metrics::cuda_hash_failures_inc();
            log::warn!("T91.2: CUDA hash_many failed: {}", e);
        }
    }
}

/// T91.2: Stub version when cuda-hash feature is not compiled.
///
/// This no-op version ensures the API is always available, but does nothing
/// when the feature is disabled.
#[cfg(not(feature = "cuda-hash"))]
pub fn run_t91_2_cuda_hash_shadow(
    _cuda_engine: &mut Option<()>,
    _tx_bytes: &[Vec<u8>],
) {
    // No-op when cuda-hash feature is disabled
}

// =============================================================================
// T91.2: Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to serialize env var access across tests
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn t91_2_is_cuda_hash_enabled_default_off() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::remove_var("EEZO_CUDA_HASH_ENABLED");
        assert!(!is_cuda_hash_enabled());
    }

    #[test]
    fn t91_2_is_cuda_hash_enabled_when_set_to_1() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("EEZO_CUDA_HASH_ENABLED", "1");
        assert!(is_cuda_hash_enabled());
        env::remove_var("EEZO_CUDA_HASH_ENABLED");
    }

    #[test]
    fn t91_2_is_cuda_hash_enabled_when_set_to_0() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("EEZO_CUDA_HASH_ENABLED", "0");
        assert!(!is_cuda_hash_enabled());
        env::remove_var("EEZO_CUDA_HASH_ENABLED");
    }

    #[test]
    fn t91_2_is_cuda_hash_enabled_when_set_to_other() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("EEZO_CUDA_HASH_ENABLED", "true");
        assert!(!is_cuda_hash_enabled()); // Only "1" is valid
        env::remove_var("EEZO_CUDA_HASH_ENABLED");
    }

    /// T91.2: Test that run_t91_2_cuda_hash_shadow returns early when disabled.
    #[test]
    fn t91_2_shadow_returns_early_when_disabled() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::remove_var("EEZO_CUDA_HASH_ENABLED");

        #[cfg(feature = "cuda-hash")]
        {
            let mut engine: Option<CudaBlake3Engine> = None;
            let tx_bytes = vec![b"test tx".to_vec()];
            
            // Should return immediately without doing anything
            run_t91_2_cuda_hash_shadow(&mut engine, &tx_bytes);
            
            // Engine should still be None (no init attempted)
            assert!(engine.is_none());
        }

        #[cfg(not(feature = "cuda-hash"))]
        {
            let mut engine: Option<()> = None;
            let tx_bytes = vec![b"test tx".to_vec()];
            run_t91_2_cuda_hash_shadow(&mut engine, &tx_bytes);
        }
    }

    /// T91.2: Test that run_t91_2_cuda_hash_shadow returns early on empty input.
    #[test]
    fn t91_2_shadow_returns_early_on_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        env::set_var("EEZO_CUDA_HASH_ENABLED", "1");

        #[cfg(feature = "cuda-hash")]
        {
            let mut engine: Option<CudaBlake3Engine> = None;
            let tx_bytes: Vec<Vec<u8>> = vec![];
            
            // Should return immediately without initializing engine
            run_t91_2_cuda_hash_shadow(&mut engine, &tx_bytes);
            
            // Engine should still be None (no init attempted for empty)
            assert!(engine.is_none());
        }

        #[cfg(not(feature = "cuda-hash"))]
        {
            let mut engine: Option<()> = None;
            let tx_bytes: Vec<Vec<u8>> = vec![];
            run_t91_2_cuda_hash_shadow(&mut engine, &tx_bytes);
        }

        env::remove_var("EEZO_CUDA_HASH_ENABLED");
    }
}
