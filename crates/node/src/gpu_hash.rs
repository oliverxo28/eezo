// =============================================================================
// T71.0 — Safe GPU hashing adapter for the node
//
// This module provides a GPU-accelerated hashing option inside the node for
// block commitments. Key properties:
//
//   - No consensus rule changes
//   - No block format changes
//   - No change in hash values (bit-for-bit identical to CPU)
//   - Fully optional, controlled by env vars
//
// The node can compute certain hashes (e.g. block tx list commitments) via
// GPU when enabled. CPU remains the default and always-correct path.
// If GPU disagrees with CPU, the node logs + counts it and falls back to CPU.
// =============================================================================

use std::env;
use std::sync::OnceLock;

/// The hash backend mode for the node.
///
/// This determines how block body hashes are computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeHashBackend {
    /// Pure CPU hashing only. No GPU involvement. (Default)
    CpuOnly,
    /// CPU is canonical; GPU runs in parallel for comparison/validation.
    /// Any mismatch is logged and counted, but CPU result is always used.
    CpuWithGpuShadow,
    /// GPU result used if it matches CPU; otherwise fallback to CPU.
    /// CPU is still computed and verified; GPU cannot override a mismatched result.
    GpuPreferred,
}

impl Default for NodeHashBackend {
    fn default() -> Self {
        NodeHashBackend::CpuOnly
    }
}

impl NodeHashBackend {
    /// Parse backend mode from the EEZO_NODE_GPU_HASH environment variable.
    ///
    /// Values:
    ///   - "off" (default) → CpuOnly
    ///   - "shadow" → CpuWithGpuShadow
    ///   - "prefer" → GpuPreferred
    pub fn from_env() -> Self {
        match env::var("EEZO_NODE_GPU_HASH")
            .unwrap_or_else(|_| "off".to_string())
            .to_lowercase()
            .as_str()
        {
            "shadow" => NodeHashBackend::CpuWithGpuShadow,
            "prefer" => NodeHashBackend::GpuPreferred,
            _ => NodeHashBackend::CpuOnly,
        }
    }
}

/// Engine for computing block body hashes with optional GPU acceleration.
///
/// This wraps the prover's GPU hashing implementation (when the `gpu-hash`
/// feature is enabled) and provides a safe API that:
///
///   1. Always computes the CPU digest as ground truth
///   2. Optionally runs GPU for comparison (shadow mode) or acceleration (prefer mode)
///   3. Never panics the node on GPU errors or mismatches
///   4. Logs and counts all GPU events for observability
pub struct NodeHashEngine {
    backend: NodeHashBackend,
}

/// Global default engine, initialized once per process from env.
static DEFAULT_ENGINE: OnceLock<NodeHashBackend> = OnceLock::new();

impl NodeHashEngine {
    /// Create a new engine from environment configuration.
    ///
    /// Reads EEZO_NODE_GPU_HASH to determine the backend mode.
    /// Logs the selected mode at startup.
    pub fn from_env() -> Self {
        let backend = *DEFAULT_ENGINE.get_or_init(|| {
            let mode = NodeHashBackend::from_env();
            let mode_str = match mode {
                NodeHashBackend::CpuOnly => "off",
                NodeHashBackend::CpuWithGpuShadow => "shadow",
                NodeHashBackend::GpuPreferred => "prefer",
            };
            log::info!("node_gpu_hash: mode = {}", mode_str);
            mode
        });

        NodeHashEngine { backend }
    }

    /// Create an engine with a specific backend (for testing).
    #[cfg(test)]
    pub fn with_backend(backend: NodeHashBackend) -> Self {
        NodeHashEngine { backend }
    }

    /// Get the current backend mode.
    pub fn backend(&self) -> NodeHashBackend {
        self.backend
    }

    /// Hash a slice of bytes representing a "block body" (e.g. concatenated tx encodings).
    ///
    /// Returns the canonical CPU digest and optionally runs GPU for comparison.
    ///
    /// Behavior by mode:
    ///   - CpuOnly: Pure CPU hash, no GPU involvement
    ///   - CpuWithGpuShadow: CPU hash + GPU comparison (CPU result returned)
    ///   - GpuPreferred: CPU hash + GPU comparison (CPU result returned; GPU just validated)
    ///
    /// Note: In all modes, the returned digest is always the CPU digest.
    /// GPU can only match or mismatch; it never changes the result.
    pub fn hash_block_body(&self, bytes: &[u8]) -> [u8; 32] {
        // 1) Always compute CPU digest as ground truth
        let cpu_digest = *blake3::hash(bytes).as_bytes();

        match self.backend {
            NodeHashBackend::CpuOnly => {
                // Pure CPU path - no GPU involvement
                cpu_digest
            }
            NodeHashBackend::CpuWithGpuShadow | NodeHashBackend::GpuPreferred => {
                // GPU comparison path
                self.run_gpu_comparison(bytes, cpu_digest)
            }
        }
    }

    /// Run GPU comparison and return the (always-canonical) CPU digest.
    ///
    /// This function:
    ///   1. Attempts GPU hashing
    ///   2. Compares GPU result to CPU
    ///   3. Logs and counts mismatches/errors
    ///   4. Returns CPU digest (never GPU)
    fn run_gpu_comparison(&self, bytes: &[u8], cpu_digest: [u8; 32]) -> [u8; 32] {
        use crate::metrics::{
            node_gpu_hash_attempts_inc, node_gpu_hash_error_inc, node_gpu_hash_mismatch_inc,
            node_gpu_hash_success_inc,
        };

        // Increment attempt counter
        node_gpu_hash_attempts_inc();

        // Try GPU hashing
        match self.gpu_hash_internal(bytes) {
            Ok(gpu_digest) => {
                if gpu_digest == cpu_digest {
                    // GPU matches CPU - success
                    node_gpu_hash_success_inc();
                } else {
                    // GPU mismatch - log warning and count
                    node_gpu_hash_mismatch_inc();
                    log::warn!(
                        "node_gpu_hash: mismatch between GPU and CPU digest (mode={:?}, bytes_len={})",
                        self.backend,
                        bytes.len()
                    );
                }
            }
            Err(e) => {
                // GPU error - log and count, fallback to CPU
                node_gpu_hash_error_inc();
                log::error!(
                    "node_gpu_hash: GPU hashing failed (mode={:?}, error={}), using CPU fallback",
                    self.backend,
                    e
                );
            }
        }

        // Always return CPU digest
        cpu_digest
    }

    /// Internal GPU hashing implementation.
    ///
    /// When the `gpu-hash` feature is enabled, this calls into the prover's
    /// GPU batch hashing API. Otherwise, it just returns the CPU hash.
    ///
    /// TODO (T71.x): Wire in real GPU backend from eezo-prover when gpu-hash feature is active.
    /// For now, we use a stub that just returns the CPU hash to exercise the adapter + metrics.
    #[allow(unused_variables)]
    fn gpu_hash_internal(&self, bytes: &[u8]) -> Result<[u8; 32], String> {
        // TODO (T71.x): When gpu-hash feature is enabled, use the prover's GPU implementation.
        // The code would look like:
        //
        // #[cfg(feature = "gpu-hash")]
        // {
        //     use eezo_prover::gpu_hash::{Blake3GpuBatch, default_batch_engine};
        //     let offsets = [0u32];
        //     let lens = [bytes.len() as u32];
        //     let mut digests_out = [0u8; 32];
        //     let mut batch = Blake3GpuBatch {
        //         input_blob: bytes,
        //         offsets: &offsets,
        //         lens: &lens,
        //         digests_out: &mut digests_out,
        //     };
        //     let engine = default_batch_engine();
        //     engine.hash_batch(&mut batch).map_err(|e| format!("GPU batch hash failed: {}", e))?;
        //     Ok(digests_out)
        // }

        // For T71.0: This is a stub that just returns the CPU hash.
        // This exercises the adapter + metrics structure without requiring real GPU.
        // Real GPU integration will be added in a follow-up T71.x task.
        Ok(*blake3::hash(bytes).as_bytes())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to ensure env var tests run sequentially (env vars are process-global)
    static ENV_TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn backend_from_env_defaults_to_cpu_only() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        // Clear the env var to test default
        std::env::remove_var("EEZO_NODE_GPU_HASH");
        assert_eq!(NodeHashBackend::from_env(), NodeHashBackend::CpuOnly);
    }

    #[test]
    fn backend_from_env_parses_off() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::set_var("EEZO_NODE_GPU_HASH", "off");
        assert_eq!(NodeHashBackend::from_env(), NodeHashBackend::CpuOnly);
        std::env::remove_var("EEZO_NODE_GPU_HASH");
    }

    #[test]
    fn backend_from_env_parses_shadow() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::set_var("EEZO_NODE_GPU_HASH", "shadow");
        assert_eq!(NodeHashBackend::from_env(), NodeHashBackend::CpuWithGpuShadow);
        std::env::remove_var("EEZO_NODE_GPU_HASH");
    }

    #[test]
    fn backend_from_env_parses_prefer() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::set_var("EEZO_NODE_GPU_HASH", "prefer");
        assert_eq!(NodeHashBackend::from_env(), NodeHashBackend::GpuPreferred);
        std::env::remove_var("EEZO_NODE_GPU_HASH");
    }

    #[test]
    fn backend_from_env_case_insensitive() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::set_var("EEZO_NODE_GPU_HASH", "SHADOW");
        assert_eq!(NodeHashBackend::from_env(), NodeHashBackend::CpuWithGpuShadow);

        std::env::set_var("EEZO_NODE_GPU_HASH", "Prefer");
        assert_eq!(NodeHashBackend::from_env(), NodeHashBackend::GpuPreferred);

        std::env::remove_var("EEZO_NODE_GPU_HASH");
    }

    #[test]
    fn backend_from_env_unknown_defaults_to_cpu() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::set_var("EEZO_NODE_GPU_HASH", "unknown_value");
        assert_eq!(NodeHashBackend::from_env(), NodeHashBackend::CpuOnly);
        std::env::remove_var("EEZO_NODE_GPU_HASH");
    }

    #[test]
    fn hash_block_body_matches_direct_blake3() {
        let engine = NodeHashEngine::with_backend(NodeHashBackend::CpuOnly);

        let test_data = b"test block body data for hashing";
        let expected = *blake3::hash(test_data).as_bytes();
        let result = engine.hash_block_body(test_data);

        assert_eq!(result, expected);
    }

    #[test]
    fn hash_block_body_empty_input() {
        let engine = NodeHashEngine::with_backend(NodeHashBackend::CpuOnly);

        let expected = *blake3::hash(b"").as_bytes();
        let result = engine.hash_block_body(b"");

        assert_eq!(result, expected);
    }

    #[test]
    fn hash_block_body_large_input() {
        let engine = NodeHashEngine::with_backend(NodeHashBackend::CpuOnly);

        // 1 MB of data
        let large_data = vec![0xABu8; 1024 * 1024];
        let expected = *blake3::hash(&large_data).as_bytes();
        let result = engine.hash_block_body(&large_data);

        assert_eq!(result, expected);
    }

    #[test]
    fn hash_block_body_shadow_mode_returns_cpu_digest() {
        // In shadow mode without real GPU, the stub returns CPU hash,
        // so result should still match direct blake3
        let engine = NodeHashEngine::with_backend(NodeHashBackend::CpuWithGpuShadow);

        let test_data = b"shadow mode test data";
        let expected = *blake3::hash(test_data).as_bytes();
        let result = engine.hash_block_body(test_data);

        assert_eq!(result, expected);
    }

    #[test]
    fn hash_block_body_prefer_mode_returns_cpu_digest() {
        // In prefer mode without real GPU, the stub returns CPU hash,
        // so result should still match direct blake3
        let engine = NodeHashEngine::with_backend(NodeHashBackend::GpuPreferred);

        let test_data = b"prefer mode test data";
        let expected = *blake3::hash(test_data).as_bytes();
        let result = engine.hash_block_body(test_data);

        assert_eq!(result, expected);
    }
}