// =============================================================================
// T71.0 / T71.1 / T71.2 — Safe GPU hashing adapter for the node
// T90.0 — GPU Hash Plumbing for eezo-node (non-consensus, feature-gated)
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
//
// T90.0: GPU Hash Plumbing milestone — clean GPU hash module for eezo-node.
//   - Reuses eezo-prover GPU BLAKE3 (wgpu/WGSL) patterns
//   - Feature-gated: `gpu-hash` Cargo feature
//   - Env-gated: `EEZO_GPU_HASH_ENABLED=1` (default: off)
//   - Non-consensus: GPU hashes are verified against CPU but not used for state roots
//   - Clear metrics: eezo_gpu_hash_* for observability
//
// Modules reused from eezo-prover:
//   - crates/eezo-prover/src/gpu_hash.rs: GpuBlake3Context, Blake3GpuBatch, Blake3GpuBackend
//   - wgpu/WGSL shader pipeline for BLAKE3 compute
//
// Differences between prover and node GPU usage:
//   - Prover: primarily batch hashing for proofs, synchronous
//   - Node: single-message hashing for block body, with CPU validation
//   - Node uses EEZO_GPU_HASH_ENABLED env var (default: off)
//   - Prover uses EEZO_GPU_HASH_REAL env var
// =============================================================================

use std::env;
use std::sync::OnceLock;
use std::time::Instant;

// =============================================================================
// T90.0 — GpuHashBackend API (clean interface for node GPU hashing)
// =============================================================================

/// Error type for GPU hash backend operations.
///
/// T90.0: Provides clear error variants for GPU hashing failures.
#[derive(Debug, Clone)]
pub enum GpuHashBackendError {
    /// GPU device is not available (no adapter, headless, driver issues).
    DeviceUnavailable(String),
    /// GPU compute operation failed during hash computation.
    ComputeFailure(String),
    /// Feature is disabled at compile time.
    FeatureDisabled,
    /// Feature is disabled at runtime via env var.
    RuntimeDisabled,
}

impl std::fmt::Display for GpuHashBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuHashBackendError::DeviceUnavailable(msg) => {
                write!(f, "GPU device unavailable: {}", msg)
            }
            GpuHashBackendError::ComputeFailure(msg) => {
                write!(f, "GPU compute failure: {}", msg)
            }
            GpuHashBackendError::FeatureDisabled => {
                write!(f, "gpu-hash feature is not compiled in")
            }
            GpuHashBackendError::RuntimeDisabled => {
                write!(f, "GPU hashing disabled (EEZO_GPU_HASH_ENABLED != 1)")
            }
        }
    }
}

impl std::error::Error for GpuHashBackendError {}

/// T90.0: Check if GPU hashing is enabled via EEZO_GPU_HASH_ENABLED env var.
///
/// Returns true only if EEZO_GPU_HASH_ENABLED=1.
/// Default is off (returns false).
pub fn is_gpu_hash_enabled() -> bool {
    env::var("EEZO_GPU_HASH_ENABLED")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// GPU BLAKE3 hashing backend for eezo-node.
///
/// T90.0: This struct provides a clean API for GPU-accelerated BLAKE3 hashing.
/// It wraps the eezo-prover GPU backend and provides:
///   - Feature-gated compilation (`gpu-hash` feature)
///   - Runtime enable/disable via `EEZO_GPU_HASH_ENABLED=1`
///   - Batch hashing of multiple messages
///   - Graceful fallback on GPU failures
///
/// The backend uses the same BLAKE3 semantics as CPU hashing (same personalization,
/// same endianness) to ensure bit-for-bit identical results.
#[cfg(feature = "gpu-hash")]
pub struct GpuHashBackend {
    /// The underlying GPU context from eezo-prover.
    ctx: eezo_prover::gpu_hash::GpuBlake3Context,
}

#[cfg(feature = "gpu-hash")]
impl GpuHashBackend {
    /// Create a new GPU hash backend.
    ///
    /// T90.0: This attempts to initialize the GPU backend if:
    ///   1. The `gpu-hash` feature is compiled in
    ///   2. `EEZO_GPU_HASH_ENABLED=1` is set in the environment
    ///   3. A suitable GPU adapter and device are available
    ///
    /// Returns `Err(GpuHashBackendError::RuntimeDisabled)` if EEZO_GPU_HASH_ENABLED != 1.
    /// Returns `Err(GpuHashBackendError::DeviceUnavailable)` if GPU init fails.
    pub fn new() -> Result<Self, GpuHashBackendError> {
        // Check runtime env var first
        if !is_gpu_hash_enabled() {
            return Err(GpuHashBackendError::RuntimeDisabled);
        }

        // Temporarily set EEZO_GPU_HASH_REAL=1 for eezo-prover initialization
        let original_val = env::var("EEZO_GPU_HASH_REAL").ok();
        env::set_var("EEZO_GPU_HASH_REAL", "1");

        // Scope guard to restore env var
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

        use eezo_prover::gpu_hash::GpuBlake3Context;

        match GpuBlake3Context::new() {
            Ok(ctx) if ctx.is_available() => {
                log::info!("T90.0: GpuHashBackend initialized successfully");
                crate::metrics::gpu_hash_enabled_set(1);
                Ok(GpuHashBackend { ctx })
            }
            Ok(_) => {
                log::warn!(
                    "T90.0: GPU adapter found but device/queue unavailable"
                );
                crate::metrics::gpu_hash_enabled_set(0);
                crate::metrics::gpu_hash_failures_inc();
                Err(GpuHashBackendError::DeviceUnavailable(
                    "adapter found but device/queue unavailable".to_string(),
                ))
            }
            Err(e) => {
                log::warn!("T90.0: GPU initialization failed: {}", e);
                crate::metrics::gpu_hash_enabled_set(0);
                crate::metrics::gpu_hash_failures_inc();
                Err(GpuHashBackendError::DeviceUnavailable(e.to_string()))
            }
        }
    }

    /// Hash a batch of messages using BLAKE3 on the GPU.
    ///
    /// T90.0: Returns a Vec of 32-byte BLAKE3 digests, one per input message.
    /// Uses the same BLAKE3 semantics as CPU hashing.
    ///
    /// # Arguments
    /// * `inputs` - Slice of byte vectors to hash
    ///
    /// # Returns
    /// * `Ok(Vec<[u8; 32]>)` - Vector of 32-byte digests
    /// * `Err(GpuHashBackendError)` - If GPU compute fails
    pub fn blake3_batch(&self, inputs: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, GpuHashBackendError> {
        use eezo_prover::gpu_hash::{Blake3GpuBackend, Blake3GpuBatch};

        if inputs.is_empty() {
            return Ok(Vec::new());
        }

        let start = Instant::now();
        let n = inputs.len();

        // Build concatenated input blob and metadata
        let mut input_blob: Vec<u8> = Vec::new();
        let mut offsets: Vec<u32> = Vec::with_capacity(n);
        let mut lens: Vec<u32> = Vec::with_capacity(n);
        let mut total_bytes: u64 = 0;

        for msg in inputs {
            let off = input_blob.len();
            input_blob.extend_from_slice(msg);
            offsets.push(off.try_into().map_err(|_| {
                GpuHashBackendError::ComputeFailure("offset overflow".to_string())
            })?);
            lens.push(msg.len().try_into().map_err(|_| {
                GpuHashBackendError::ComputeFailure("length overflow".to_string())
            })?);
            total_bytes += msg.len() as u64;
        }

        let mut digests_out = vec![0u8; n * 32];

        let mut batch = Blake3GpuBatch {
            input_blob: &input_blob,
            offsets: &offsets,
            lens: &lens,
            digests_out: &mut digests_out,
        };

        self.ctx
            .hash_batch(&mut batch)
            .map_err(|e| GpuHashBackendError::ComputeFailure(e.to_string()))?;

        // Record metrics
        let elapsed = start.elapsed().as_secs_f64();
        crate::metrics::gpu_hash_jobs_inc();
        crate::metrics::gpu_hash_latency_observe(elapsed);
        crate::metrics::gpu_hash_bytes_inc(total_bytes);

        // Convert flat buffer to Vec of arrays
        let mut result = Vec::with_capacity(n);
        for i in 0..n {
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&digests_out[i * 32..(i + 1) * 32]);
            result.push(digest);
        }

        Ok(result)
    }

    /// Hash a single message using BLAKE3 on the GPU.
    ///
    /// Convenience wrapper around `blake3_batch` for single-message hashing.
    pub fn blake3_single(&self, input: &[u8]) -> Result<[u8; 32], GpuHashBackendError> {
        let inputs = vec![input.to_vec()];
        let results = self.blake3_batch(&inputs)?;
        Ok(results.into_iter().next().unwrap_or([0u8; 32]))
    }
}

/// T90.0: Stub GpuHashBackend when gpu-hash feature is disabled.
#[cfg(not(feature = "gpu-hash"))]
pub struct GpuHashBackend {
    _private: (),
}

#[cfg(not(feature = "gpu-hash"))]
impl GpuHashBackend {
    /// Stub new() that returns FeatureDisabled error.
    pub fn new() -> Result<Self, GpuHashBackendError> {
        Err(GpuHashBackendError::FeatureDisabled)
    }

    /// Stub blake3_batch that always fails.
    pub fn blake3_batch(&self, _inputs: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, GpuHashBackendError> {
        Err(GpuHashBackendError::FeatureDisabled)
    }

    /// Stub blake3_single that always fails.
    pub fn blake3_single(&self, _input: &[u8]) -> Result<[u8; 32], GpuHashBackendError> {
        Err(GpuHashBackendError::FeatureDisabled)
    }
}

// =============================================================================
// T90.0 — Diagnostic GPU vs CPU hash comparison
// =============================================================================

/// T90.0: Compare GPU and CPU hashes for a batch of inputs.
///
/// This function:
/// 1. Computes CPU hashes as ground truth
/// 2. If EEZO_GPU_HASH_ENABLED=1 and GPU is available, computes GPU hashes
/// 3. Asserts that GPU hashes match CPU hashes bit-for-bit
/// 4. Returns CPU hashes (always canonical for consensus)
///
/// Any mismatch is logged as an error and counted in metrics.
/// Consensus always uses CPU hashes.
pub fn hash_batch_with_gpu_check(inputs: &[Vec<u8>]) -> Vec<[u8; 32]> {
    // 1. Compute CPU hashes (ground truth)
    let cpu_hashes: Vec<[u8; 32]> = inputs
        .iter()
        .map(|msg| *blake3::hash(msg).as_bytes())
        .collect();

    // 2. Check if GPU is enabled
    if !is_gpu_hash_enabled() {
        return cpu_hashes;
    }

    // 3. Try to create GPU backend and compute hashes
    #[cfg(feature = "gpu-hash")]
    {
        // Use a cached backend (avoid reinitializing on every call)
        static GPU_BACKEND: OnceLock<Option<GpuHashBackend>> = OnceLock::new();
        
        let backend = GPU_BACKEND.get_or_init(|| {
            match GpuHashBackend::new() {
                Ok(b) => Some(b),
                Err(e) => {
                    log::warn!("T90.0: GPU backend init failed: {}", e);
                    None
                }
            }
        });

        if let Some(gpu) = backend {
            match gpu.blake3_batch(inputs) {
                Ok(gpu_hashes) => {
                    // 4. Compare GPU vs CPU
                    let mut mismatch_count = 0;
                    for (i, (cpu, gpu)) in cpu_hashes.iter().zip(gpu_hashes.iter()).enumerate() {
                        if cpu != gpu {
                            mismatch_count += 1;
                            log::error!(
                                "T90.0: GPU/CPU hash mismatch at index {}: CPU={} GPU={}",
                                i,
                                hex::encode(cpu),
                                hex::encode(gpu)
                            );
                        }
                    }
                    if mismatch_count > 0 {
                        crate::metrics::gpu_hash_mismatch_inc_by(mismatch_count);
                        log::error!(
                            "T90.0: {} GPU/CPU hash mismatches detected (using CPU as canonical)",
                            mismatch_count
                        );
                    }
                }
                Err(e) => {
                    log::error!("T90.0: GPU batch hash failed: {}", e);
                    crate::metrics::gpu_hash_failures_inc();
                }
            }
        }
    }

    // Always return CPU hashes (canonical for consensus)
    cpu_hashes
}

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

    // =========================================================================
    // T90.0: GPU Hash Plumbing tests
    // =========================================================================

    #[test]
    fn t90_0_gpu_hash_backend_error_display() {
        // T90.0: Test error display formatting
        let err = GpuHashBackendError::DeviceUnavailable("no adapter".to_string());
        assert!(err.to_string().contains("no adapter"));

        let err = GpuHashBackendError::ComputeFailure("shader error".to_string());
        assert!(err.to_string().contains("shader error"));

        let err = GpuHashBackendError::FeatureDisabled;
        assert!(err.to_string().contains("feature"));

        let err = GpuHashBackendError::RuntimeDisabled;
        assert!(err.to_string().contains("EEZO_GPU_HASH_ENABLED"));
    }

    #[test]
    fn t90_0_is_gpu_hash_enabled_default_off() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        // Clear the env var to test default
        std::env::remove_var("EEZO_GPU_HASH_ENABLED");
        assert!(!is_gpu_hash_enabled());
    }

    #[test]
    fn t90_0_is_gpu_hash_enabled_off_when_zero() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::set_var("EEZO_GPU_HASH_ENABLED", "0");
        assert!(!is_gpu_hash_enabled());
        std::env::remove_var("EEZO_GPU_HASH_ENABLED");
    }

    #[test]
    fn t90_0_is_gpu_hash_enabled_on_when_one() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::set_var("EEZO_GPU_HASH_ENABLED", "1");
        assert!(is_gpu_hash_enabled());
        std::env::remove_var("EEZO_GPU_HASH_ENABLED");
    }

    #[test]
    fn t90_0_hash_batch_with_gpu_check_returns_cpu_hashes() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        // Ensure GPU is disabled
        std::env::remove_var("EEZO_GPU_HASH_ENABLED");

        let inputs = vec![
            b"message 1".to_vec(),
            b"message 2".to_vec(),
            b"".to_vec(),
            vec![0u8; 1000],
        ];

        let results = hash_batch_with_gpu_check(&inputs);

        // Verify each result matches CPU BLAKE3
        for (input, result) in inputs.iter().zip(results.iter()) {
            let expected = *blake3::hash(input).as_bytes();
            assert_eq!(*result, expected);
        }
    }

    #[test]
    fn t90_0_hash_batch_empty_inputs() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::remove_var("EEZO_GPU_HASH_ENABLED");

        let inputs: Vec<Vec<u8>> = vec![];
        let results = hash_batch_with_gpu_check(&inputs);
        assert!(results.is_empty());
    }

    #[test]
    fn t90_0_gpu_hash_backend_new_returns_error_when_disabled() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::remove_var("EEZO_GPU_HASH_ENABLED");

        let result = GpuHashBackend::new();
        assert!(result.is_err());

        // Check the error type
        match result {
            #[cfg(feature = "gpu-hash")]
            Err(GpuHashBackendError::RuntimeDisabled) => (),
            #[cfg(not(feature = "gpu-hash"))]
            Err(GpuHashBackendError::FeatureDisabled) => (),
            _ => panic!("Expected RuntimeDisabled or FeatureDisabled error"),
        }
    }

    #[test]
    fn t90_0_hash_batch_various_sizes() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        std::env::remove_var("EEZO_GPU_HASH_ENABLED");

        // Test various input sizes including edge cases
        let inputs = vec![
            vec![],                  // empty
            vec![0u8; 1],           // 1 byte
            vec![0u8; 64],          // single BLAKE3 chunk
            vec![0u8; 65],          // just over one chunk
            vec![0u8; 1024],        // 1 KB
        ];

        let results = hash_batch_with_gpu_check(&inputs);
        assert_eq!(results.len(), inputs.len());

        for (input, result) in inputs.iter().zip(results.iter()) {
            let expected = *blake3::hash(input).as_bytes();
            assert_eq!(*result, expected, "Hash mismatch for input of size {}", input.len());
        }
    }
}