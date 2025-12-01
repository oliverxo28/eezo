// =============================================================================
// T71.0 / T71.1 / T71.2 — Safe GPU hashing adapter for the node
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
//
// T71.1: Wire to the real eezo-prover GPU backend (GpuBlake3Context) instead
// of the stub. Node uses EEZO_NODE_GPU_HASH (not prover's EEZO_GPU_HASH_REAL).
//
// T71.2: Improved observability for GPU init failures:
//   - New gauge: eezo_node_gpu_hash_enabled (0=disabled/failed, 1=enabled)
//   - Better error logging with full error chain
//   - Clarified metric semantics (attempts_total vs error_total)
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

// =============================================================================
// T71.1 — RealGpuHandle: thin wrapper over the prover's GPU hash backend
// =============================================================================

/// T71.1: Wrapper around the real GPU hash backend from eezo-prover.
///
/// This struct owns the prover's `GpuBlake3Context` and exposes a simple
/// `hash_block_body` method that uses the batch hashing API.
///
/// When the `gpu-hash` feature is disabled, this is a stub that always fails.
#[cfg(feature = "gpu-hash")]
pub struct RealGpuHandle {
    /// The underlying GPU context from eezo-prover.
    ctx: eezo_prover::gpu_hash::GpuBlake3Context,
}

/// T71.1: Mutex to protect GPU initialization (env var manipulation is not thread-safe).
#[cfg(feature = "gpu-hash")]
static GPU_INIT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// T71.1: Cached GPU handle result, initialized once per process.
#[cfg(feature = "gpu-hash")]
static GPU_HANDLE_CACHE: OnceLock<Option<RealGpuHandle>> = OnceLock::new();

#[cfg(feature = "gpu-hash")]
impl RealGpuHandle {
    /// T71.1: Attempt to initialize the real GPU backend (cached, thread-safe).
    ///
    /// This creates a `GpuBlake3Context` from the prover crate. We override
    /// the prover's env var (EEZO_GPU_HASH_REAL) temporarily to "1" so that
    /// the context attempts real GPU initialization, but this is controlled
    /// by the node's EEZO_NODE_GPU_HASH env var at a higher level.
    ///
    /// Returns a reference to the cached handle, or None if GPU initialization failed.
    /// Initialization is performed only once per process.
    pub fn try_init() -> Option<&'static Self> {
        GPU_HANDLE_CACHE
            .get_or_init(|| Self::init_gpu_backend_internal())
            .as_ref()
    }

    /// T71.1: Internal GPU initialization with thread-safe env var manipulation.
    /// T71.2: Sets the eezo_node_gpu_hash_enabled gauge and logs detailed errors.
    fn init_gpu_backend_internal() -> Option<RealGpuHandle> {
        use eezo_prover::gpu_hash::GpuBlake3Context;

        // T71.1: Acquire mutex to ensure thread-safe env var manipulation.
        // We use into_inner() on poison errors because GPU init failure is not
        // critical - we simply fall back to CPU hashing. The mutex protects
        // env var manipulation, not critical data integrity.
        let _guard = GPU_INIT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        // T71.1: The prover's GpuBlake3Context::new() checks EEZO_GPU_HASH_REAL.
        // We temporarily set it to "1" to request real GPU init, but only if
        // the node's EEZO_NODE_GPU_HASH is shadow or prefer (already checked
        // by caller). We use a scope guard pattern to ensure the env var is
        // always restored, even if GpuBlake3Context::new() panics.
        let original_val = env::var("EEZO_GPU_HASH_REAL").ok();
        env::set_var("EEZO_GPU_HASH_REAL", "1");

        // Scope guard: restore env var on any exit path (including panic)
        struct EnvGuard(Option<String>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.0 {
                    Some(v) => env::set_var("EEZO_GPU_HASH_REAL", v),
                    None => env::remove_var("EEZO_GPU_HASH_REAL"),
                }
            }
        }
        let _env_guard = EnvGuard(original_val);

        let result = GpuBlake3Context::new();

        match result {
            Ok(ctx) if ctx.is_available() => {
                log::info!("node_gpu_hash: GPU backend initialized successfully");
                // T71.2: Set enabled gauge to 1 when GPU init succeeds
                crate::metrics::node_gpu_hash_enabled_set(1);
                Some(RealGpuHandle { ctx })
            }
            Ok(_) => {
                // T71.2: Context created but device/queue unavailable
                log::error!(
                    "node_gpu_hash: GPU init failed: adapter found but device/queue unavailable; \
                     falling back to CPU"
                );
                crate::metrics::node_gpu_hash_error_inc();
                // T71.2: Set enabled gauge to 0 when GPU is not usable
                crate::metrics::node_gpu_hash_enabled_set(0);
                None
            }
            Err(e) => {
                // T71.2: Full error chain via Display and Debug for diagnostics
                log::error!(
                    "node_gpu_hash: GPU init failed: {} ({:?}); falling back to CPU",
                    e, e
                );
                crate::metrics::node_gpu_hash_error_inc();
                // T71.2: Set enabled gauge to 0 when GPU init fails
                crate::metrics::node_gpu_hash_enabled_set(0);
                None
            }
        }
    }

    /// T71.1: Hash a block body using the real GPU backend.
    ///
    /// Uses the prover's `Blake3GpuBackend::hash_batch` API with a single
    /// message. This batch API is required because the prover's GPU backend
    /// only exposes batch hashing, but the overhead is minimal for single
    /// messages since we're already paying the GPU kernel launch cost.
    ///
    /// Returns the 32-byte digest on success.
    pub fn hash_block_body(&self, bytes: &[u8]) -> Result<[u8; 32], String> {
        use eezo_prover::gpu_hash::{Blake3GpuBackend, Blake3GpuBatch};

        // T71.1: Check for integer overflow when casting bytes.len() to u32.
        // On 64-bit systems, usize can be larger than u32::MAX. This is a rare
        // edge case (>4GB input) but we handle it gracefully with an error.
        let byte_len = bytes.len();
        let len: u32 = byte_len
            .try_into()
            .map_err(|_| format!("Input too large for GPU hashing: {} bytes exceeds u32::MAX", byte_len))?;

        let offsets = [0u32];
        let lens = [len];
        let mut digests_out = [0u8; 32];

        let mut batch = Blake3GpuBatch {
            input_blob: bytes,
            offsets: &offsets,
            lens: &lens,
            digests_out: &mut digests_out,
        };

        self.ctx
            .hash_batch(&mut batch)
            .map_err(|e| format!("GPU batch hash failed: {}", e))?;

        Ok(digests_out)
    }
}

/// T71.1/T71.2: Stub RealGpuHandle when gpu-hash feature is disabled.
/// This is a zero-sized type that should never be instantiated.
#[cfg(not(feature = "gpu-hash"))]
pub struct RealGpuHandle {
    // Private field prevents external construction
    _private: (),
}

/// T71.1: Static flag for logging the stub message only once.
#[cfg(not(feature = "gpu-hash"))]
static STUB_LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(not(feature = "gpu-hash"))]
impl RealGpuHandle {
    /// T71.1/T71.2: Stub init that always returns None (no GPU available).
    /// Logs the stub message only once per process and sets enabled gauge to 0.
    pub fn try_init() -> Option<&'static Self> {
        // Log only on first call
        if !STUB_LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            log::info!("node_gpu_hash: gpu-hash feature disabled; using CPU-only");
            // T71.2: Set enabled gauge to 0 when feature is disabled
            crate::metrics::node_gpu_hash_enabled_set(0);
        }
        None
    }

    /// T71.1: Stub hash method for type compatibility.
    /// This method is never called because try_init() always returns None,
    /// but it's needed for the compiler to verify type signatures match.
    #[allow(dead_code)]
    pub fn hash_block_body(&self, _bytes: &[u8]) -> Result<[u8; 32], String> {
        // This should never be reached since try_init() returns None
        unreachable!("GPU hash_block_body called in stub mode")
    }
}

// =============================================================================
// T71.1 — NodeHashEngine with optional RealGpuHandle
// =============================================================================

/// Engine for computing block body hashes with optional GPU acceleration.
///
/// T71.1: This now wraps a real GPU handle from eezo-prover when available.
/// The API provides a safe interface that:
///
///   1. Always computes the CPU digest as ground truth
///   2. Optionally runs GPU for comparison (shadow mode) or acceleration (prefer mode)
///   3. Never panics the node on GPU errors or mismatches
///   4. Logs and counts all GPU events for observability
pub struct NodeHashEngine {
    backend: NodeHashBackend,
    /// T71.1: Optional reference to the cached GPU backend (cached once per process).
    gpu: Option<&'static RealGpuHandle>,
}

/// Global default engine mode, initialized once per process from env.
static DEFAULT_ENGINE: OnceLock<NodeHashBackend> = OnceLock::new();

impl NodeHashEngine {
    /// Create a new engine from environment configuration.
    ///
    /// T71.1: Reads EEZO_NODE_GPU_HASH to determine the backend mode.
    /// When mode is shadow or prefer, attempts to initialize the real GPU backend.
    /// Logs the selected mode and GPU status at startup.
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

        // T71.1: Initialize GPU handle if needed (cached once per process).
        let gpu = match backend {
            NodeHashBackend::CpuOnly => None,
            NodeHashBackend::CpuWithGpuShadow | NodeHashBackend::GpuPreferred => {
                // try_init returns Option<&'static RealGpuHandle> - cached internally.
                RealGpuHandle::try_init()
            }
        };

        NodeHashEngine { backend, gpu }
    }

    /// Create an engine with a specific backend (for testing).
    /// T71.1: When using GPU modes without the gpu-hash feature, GPU will be None.
    #[cfg(test)]
    pub fn with_backend(backend: NodeHashBackend) -> Self {
        NodeHashEngine { backend, gpu: None }
    }

    /// Get the current backend mode.
    pub fn backend(&self) -> NodeHashBackend {
        self.backend
    }

    /// T71.1: Check if GPU backend is available.
    pub fn has_gpu(&self) -> bool {
        self.gpu.is_some()
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

        match (&self.backend, self.gpu) {
            // T71.1: CpuOnly mode or no GPU handle - pure CPU path
            (NodeHashBackend::CpuOnly, _) | (_, None) => cpu_digest,
            // T71.1: GPU modes with available handle - run comparison
            (NodeHashBackend::CpuWithGpuShadow, Some(gpu))
            | (NodeHashBackend::GpuPreferred, Some(gpu)) => {
                self.run_gpu_comparison(gpu, bytes, cpu_digest)
            }
        }
    }

    /// Run GPU comparison and return the (always-canonical) CPU digest.
    ///
    /// T71.1: This function uses the real GPU handle to compute a digest,
    /// compares it to CPU, logs and counts mismatches/errors,
    /// and always returns the CPU digest.
    fn run_gpu_comparison(
        &self,
        gpu: &RealGpuHandle,
        bytes: &[u8],
        cpu_digest: [u8; 32],
    ) -> [u8; 32] {
        use crate::metrics::{
            node_gpu_hash_attempts_inc, node_gpu_hash_error_inc, node_gpu_hash_mismatch_inc,
            node_gpu_hash_success_inc,
        };

        // Increment attempt counter
        node_gpu_hash_attempts_inc();

        // T71.1: Try real GPU hashing via RealGpuHandle
        match gpu.hash_block_body(bytes) {
            Ok(gpu_digest) => {
                if gpu_digest == cpu_digest {
                    // GPU matches CPU - success
                    node_gpu_hash_success_inc();
                } else {
                    // GPU mismatch - log warning and count
                    node_gpu_hash_mismatch_inc();
                    log::warn!(
                        "node_gpu_hash: T71.1 mismatch between GPU and CPU digest (mode={:?}, bytes_len={})",
                        self.backend,
                        bytes.len()
                    );
                }
            }
            Err(e) => {
                // GPU error - log and count, fallback to CPU
                node_gpu_hash_error_inc();
                log::error!(
                    "node_gpu_hash: T71.1 GPU hashing failed (mode={:?}, error={}), using CPU fallback",
                    self.backend,
                    e
                );
            }
        }

        // Always return CPU digest
        cpu_digest
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
        // T71.1: In shadow mode without real GPU handle (gpu=None),
        // the engine returns the CPU digest directly.
        // This is the expected fallback behavior.
        let engine = NodeHashEngine::with_backend(NodeHashBackend::CpuWithGpuShadow);

        let test_data = b"shadow mode test data";
        let expected = *blake3::hash(test_data).as_bytes();
        let result = engine.hash_block_body(test_data);

        assert_eq!(result, expected);
    }

    #[test]
    fn hash_block_body_prefer_mode_returns_cpu_digest() {
        // T71.1: In prefer mode without real GPU handle (gpu=None),
        // the engine returns the CPU digest directly.
        // This is the expected fallback behavior.
        let engine = NodeHashEngine::with_backend(NodeHashBackend::GpuPreferred);

        let test_data = b"prefer mode test data";
        let expected = *blake3::hash(test_data).as_bytes();
        let result = engine.hash_block_body(test_data);

        assert_eq!(result, expected);
    }

    // =========================================================================
    // T71.1: Additional tests for GPU handle behavior
    // =========================================================================

    #[test]
    fn t71_1_engine_with_backend_has_no_gpu_by_default() {
        // T71.1: with_backend creates an engine with gpu=None,
        // so has_gpu() should return false.
        let engine = NodeHashEngine::with_backend(NodeHashBackend::CpuWithGpuShadow);
        assert!(!engine.has_gpu());

        let engine = NodeHashEngine::with_backend(NodeHashBackend::GpuPreferred);
        assert!(!engine.has_gpu());

        let engine = NodeHashEngine::with_backend(NodeHashBackend::CpuOnly);
        assert!(!engine.has_gpu());
    }

    #[test]
    fn t71_1_cpu_only_mode_never_uses_gpu() {
        // T71.1: In CpuOnly mode, even if somehow a GPU handle existed,
        // the engine would not use it (the match pattern ignores it).
        // Here we just verify CpuOnly mode works correctly.
        let engine = NodeHashEngine::with_backend(NodeHashBackend::CpuOnly);

        let test_data = b"cpu only mode never uses gpu";
        let expected = *blake3::hash(test_data).as_bytes();
        let result = engine.hash_block_body(test_data);

        assert_eq!(result, expected);
    }

    #[test]
    fn t71_1_hash_always_returns_cpu_digest() {
        // T71.1: Invariant - hash_block_body always returns the CPU digest.
        // This is true regardless of mode or GPU availability.
        for mode in [
            NodeHashBackend::CpuOnly,
            NodeHashBackend::CpuWithGpuShadow,
            NodeHashBackend::GpuPreferred,
        ] {
            let engine = NodeHashEngine::with_backend(mode);
            let test_data = b"invariant test data for T71.1";
            let expected = *blake3::hash(test_data).as_bytes();
            let result = engine.hash_block_body(test_data);

            assert_eq!(
                result, expected,
                "T71.1 invariant violated: mode={:?} did not return CPU digest",
                mode
            );
        }
    }
}