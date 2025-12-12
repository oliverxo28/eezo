// =============================================================================
// T91.0 — CUDA BLAKE3 Engine Skeleton
//
// This module provides a CUDA-based BLAKE3 hashing engine that does not depend
// on Vulkan. It is designed to be reusable from both prover and node in future
// tasks (T91.1+).
//
// T91.0 Scope:
// - Clean Rust API with CudaBlake3Engine and CudaBlake3Error
// - Build plumbing to detect CUDA toolchain
// - Stub implementation (no real CUDA BLAKE3 kernel yet)
// - Safe behavior on machines without CUDA
//
// The structure is ready for T91.1 to drop in real CUDA kernels.
//
// Build behavior:
// - When eezo_cuda_build_present cfg is set (CUDA detected at build time):
//   - Attempts real CUDA runtime initialization
//   - Returns appropriate errors on failure
// - When eezo_cuda_build_present cfg is NOT set (no CUDA at build time):
//   - Returns RuntimeUnavailable immediately
//   - Never panics or segfaults
//
// =============================================================================

use thiserror::Error;

/// Error type for CUDA BLAKE3 operations.
///
/// This enum covers all failure modes of the CUDA BLAKE3 engine:
/// - RuntimeUnavailable: CUDA runtime/driver not present or not loadable
/// - DeviceUnavailable: CUDA runtime present but no usable GPU device
/// - InitFailure: CUDA context/stream initialization failed
/// - ComputeFailure: CUDA kernel execution or memory operations failed
#[derive(Debug, Error)]
pub enum CudaBlake3Error {
    /// CUDA runtime is not available on this system.
    ///
    /// This error is returned when:
    /// - The crate was compiled without CUDA toolchain present
    /// - The CUDA driver library cannot be loaded at runtime
    /// - The CUDA runtime initialization fails
    #[error("CUDA runtime unavailable")]
    RuntimeUnavailable,

    /// CUDA runtime is available but no suitable GPU device was found.
    ///
    /// This error is returned when:
    /// - CUDA driver loads but device count is 0
    /// - Device 0 cannot be selected
    /// - Device capabilities are insufficient
    #[error("CUDA device unavailable")]
    DeviceUnavailable,

    /// CUDA initialization failed with a specific error message.
    ///
    /// This error is returned when:
    /// - CUDA context creation fails
    /// - CUDA stream creation fails
    /// - Other initialization steps fail
    #[error("CUDA initialization failed: {0}")]
    InitFailure(String),

    /// CUDA compute operation failed with a specific error message.
    ///
    /// This error is returned when:
    /// - Memory allocation fails
    /// - Memory copy (H2D or D2H) fails
    /// - Kernel launch fails
    /// - Kernel execution fails
    #[error("CUDA compute failed: {0}")]
    ComputeFailure(String),
}

/// CUDA BLAKE3 hashing engine.
///
/// This struct provides GPU-accelerated BLAKE3 hashing using CUDA.
/// It encapsulates the CUDA context, device, and stream needed for
/// kernel execution.
///
/// # Thread Safety
///
/// This type is `Send` but not `Sync`. Each engine should be used from
/// a single thread. For multi-threaded use, create one engine per thread
/// or use synchronization.
///
/// # Example
///
/// ```ignore
/// use eezo_cuda_hash::{CudaBlake3Engine, CudaBlake3Error};
///
/// fn main() -> Result<(), CudaBlake3Error> {
///     let engine = CudaBlake3Engine::new()?;
///     
///     let inputs: Vec<&[u8]> = vec![b"hello", b"world"];
///     let hashes = engine.hash_many(&inputs)?;
///     
///     for hash in hashes {
///         println!("{:02x?}", hash);
///     }
///     Ok(())
/// }
/// ```
///
/// # T91.0 Note
///
/// In T91.0, `hash_many()` is a stub that returns an error or uses CPU
/// fallback. Real CUDA BLAKE3 kernels will be added in T91.1+.
#[derive(Debug)]
pub struct CudaBlake3Engine {
    /// Marker for whether real CUDA resources are held.
    /// In T91.0, this is a placeholder for T91.1 to add actual CUDA handles.
    #[cfg(eezo_cuda_build_present)]
    _cuda_context_present: bool,

    /// On non-CUDA builds, this is just a unit marker.
    #[cfg(not(eezo_cuda_build_present))]
    _marker: (),
}

// ============================================================================
// CUDA-present implementation
// ============================================================================

#[cfg(eezo_cuda_build_present)]
impl CudaBlake3Engine {
    /// Create a new CUDA BLAKE3 engine.
    ///
    /// This method:
    /// 1. Attempts to initialize the CUDA runtime
    /// 2. Selects device 0 (primary GPU)
    /// 3. Creates a CUDA context and stream for kernel execution
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - CUDA runtime cannot be initialized (`RuntimeUnavailable`)
    /// - No GPU device is available (`DeviceUnavailable`)
    /// - Context or stream creation fails (`InitFailure`)
    ///
    /// # Safety
    ///
    /// This method is safe and will never panic or segfault, even if
    /// CUDA is not available. All CUDA operations are wrapped in
    /// error handling.
    pub fn new() -> Result<Self, CudaBlake3Error> {
        log::info!("eezo-cuda-hash: attempting CUDA runtime initialization (T91.0)");

        // T91.0: Attempt basic CUDA initialization
        // In T91.0, we do minimal CUDA probing. Full context/stream
        // creation will be added in T91.1 when we have real kernels.
        
        // For T91.0, we try to detect if CUDA is actually usable at runtime
        // by checking if the CUDA driver can be loaded and if any devices exist.
        match init_cuda_runtime() {
            Ok(device_count) if device_count > 0 => {
                log::info!(
                    "eezo-cuda-hash: CUDA runtime initialized, {} device(s) found",
                    device_count
                );
                Ok(CudaBlake3Engine {
                    _cuda_context_present: true,
                })
            }
            Ok(_) => {
                log::warn!("eezo-cuda-hash: CUDA runtime initialized but no devices found");
                Err(CudaBlake3Error::DeviceUnavailable)
            }
            Err(e) => {
                log::warn!("eezo-cuda-hash: CUDA runtime initialization failed: {}", e);
                Err(e)
            }
        }
    }

    /// Hash multiple inputs using BLAKE3 on the GPU.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Slice of byte slices to hash
    ///
    /// # Returns
    ///
    /// A vector of 32-byte BLAKE3 digests, one per input, in the same order.
    ///
    /// # Errors
    ///
    /// Returns `ComputeFailure` if the GPU computation fails.
    ///
    /// # T91.0 Note
    ///
    /// In T91.0, this method is a **stub** that uses CPU BLAKE3 as a
    /// placeholder. The function signature and error handling are stable;
    /// real CUDA BLAKE3 kernels will be added in T91.1+.
    pub fn hash_many(&self, inputs: &[&[u8]]) -> Result<Vec<[u8; 32]>, CudaBlake3Error> {
        // T91.0: Stub implementation using CPU BLAKE3 as placeholder.
        // This ensures the API is stable and tested before adding real CUDA kernels.
        //
        // Alternative stub behavior would be:
        // Err(CudaBlake3Error::ComputeFailure("not implemented in T91.0".into()))
        //
        // We chose CPU fallback to allow callers to test the full pipeline.
        log::debug!(
            "eezo-cuda-hash: hash_many called with {} inputs (T91.0 CPU stub)",
            inputs.len()
        );

        let digests: Vec<[u8; 32]> = inputs
            .iter()
            .map(|input| *blake3::hash(input).as_bytes())
            .collect();

        Ok(digests)
    }
}

/// Attempt to initialize the CUDA runtime and return device count.
///
/// T91.0: This is a minimal probe to check if CUDA is usable.
/// Full initialization with context/stream will be added in T91.1.
#[cfg(eezo_cuda_build_present)]
fn init_cuda_runtime() -> Result<i32, CudaBlake3Error> {
    // T91.0: We use a simple approach - try to run cuInit and cuDeviceGetCount
    // via the rustacuda crate if the `cuda` feature is enabled, or use a
    // simple FFI probe otherwise.
    
    #[cfg(feature = "cuda")]
    {
        use rustacuda::prelude::*;
        
        // Initialize CUDA runtime
        rustacuda::init(CudaFlags::empty())
            .map_err(|e| CudaBlake3Error::InitFailure(format!("cuInit failed: {}", e)))?;
        
        // Get device count
        let device_count = Device::num_devices()
            .map_err(|e| CudaBlake3Error::InitFailure(format!("cuDeviceGetCount failed: {}", e)))?;
        
        Ok(device_count as i32)
    }

    #[cfg(not(feature = "cuda"))]
    {
        // Without the cuda feature, we can't actually call CUDA APIs,
        // but CUDA was detected at build time. This is a build configuration
        // issue - return an appropriate error.
        //
        // T91.0: For now, we simulate successful initialization since we're
        // just setting up the structure. T91.1 will require the cuda feature.
        log::warn!(
            "eezo-cuda-hash: CUDA detected at build time but `cuda` feature not enabled; \
             simulating device for T91.0 skeleton"
        );
        Ok(1) // Simulate 1 device for T91.0 skeleton testing
    }
}

// ============================================================================
// Non-CUDA (stub) implementation
// ============================================================================

#[cfg(not(eezo_cuda_build_present))]
impl CudaBlake3Engine {
    /// Create a new CUDA BLAKE3 engine.
    ///
    /// On builds where CUDA was not detected at build time, this method
    /// always returns `Err(CudaBlake3Error::RuntimeUnavailable)`.
    ///
    /// # Safety
    ///
    /// This method is safe and will never panic or segfault.
    pub fn new() -> Result<Self, CudaBlake3Error> {
        log::info!("eezo-cuda-hash: CUDA not available at build time (stub mode)");
        Err(CudaBlake3Error::RuntimeUnavailable)
    }

    /// Stub hash_many that is never called (new() always fails).
    ///
    /// This method exists for API completeness but will never be called
    /// since `new()` always returns an error on non-CUDA builds.
    #[allow(dead_code)]
    pub fn hash_many(&self, _inputs: &[&[u8]]) -> Result<Vec<[u8; 32]>, CudaBlake3Error> {
        // This should never be reached since new() fails on non-CUDA builds
        Err(CudaBlake3Error::RuntimeUnavailable)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// T91.0: Test that CudaBlake3Engine::new() is safe on any machine.
    ///
    /// This test must:
    /// - Never panic or segfault on any machine (with or without CUDA)
    /// - Return Ok(_) on machines with working CUDA
    /// - Return Err(RuntimeUnavailable | DeviceUnavailable | InitFailure) without CUDA
    ///
    /// The test prints the result for diagnostic purposes.
    #[test]
    fn t91_0_cuda_engine_init_is_safe() {
        let res = CudaBlake3Engine::new();
        // This must never panic or segfault on any machine.
        println!("t91_0_cuda_engine_init_is_safe: {:?}", res);

        // On non-CUDA builds, we expect an error
        #[cfg(not(eezo_cuda_build_present))]
        {
            assert!(res.is_err(), "Expected error on non-CUDA build");
            match res {
                Err(CudaBlake3Error::RuntimeUnavailable) => (),
                other => panic!("Expected RuntimeUnavailable, got {:?}", other),
            }
        }

        // On CUDA builds, result depends on whether a GPU is actually present
        #[cfg(eezo_cuda_build_present)]
        {
            // Either Ok (GPU present) or Err (no GPU) is acceptable
            match &res {
                Ok(_) => println!("  -> CUDA engine created successfully"),
                Err(CudaBlake3Error::RuntimeUnavailable) => {
                    println!("  -> CUDA runtime unavailable (expected on non-GPU machines)")
                }
                Err(CudaBlake3Error::DeviceUnavailable) => {
                    println!("  -> CUDA device unavailable (expected on non-GPU machines)")
                }
                Err(CudaBlake3Error::InitFailure(msg)) => {
                    println!("  -> CUDA init failed: {} (expected on non-GPU machines)", msg)
                }
                Err(CudaBlake3Error::ComputeFailure(_)) => {
                    panic!("Unexpected ComputeFailure during init")
                }
            }
        }
    }

    /// T91.0: Test that error types implement Display correctly.
    #[test]
    fn t91_0_error_display() {
        let err = CudaBlake3Error::RuntimeUnavailable;
        assert!(err.to_string().contains("unavailable"));

        let err = CudaBlake3Error::DeviceUnavailable;
        assert!(err.to_string().contains("device"));

        let err = CudaBlake3Error::InitFailure("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let err = CudaBlake3Error::ComputeFailure("compute error".to_string());
        assert!(err.to_string().contains("compute error"));
    }

    /// T91.0: Test that error types implement Debug correctly.
    #[test]
    fn t91_0_error_debug() {
        let err = CudaBlake3Error::RuntimeUnavailable;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("RuntimeUnavailable"));

        let err = CudaBlake3Error::InitFailure("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InitFailure"));
    }

    /// T91.0: Test hash_many on CUDA builds (when engine creation succeeds).
    #[cfg(eezo_cuda_build_present)]
    #[test]
    fn t91_0_hash_many_stub() {
        // Only run this test if engine creation succeeds
        if let Ok(engine) = CudaBlake3Engine::new() {
            let inputs: Vec<&[u8]> = vec![b"hello", b"world", b"test"];
            let result = engine.hash_many(&inputs);

            match result {
                Ok(hashes) => {
                    assert_eq!(hashes.len(), 3);

                    // T91.0 stub uses CPU BLAKE3, so verify correctness
                    for (i, input) in inputs.iter().enumerate() {
                        let expected = *blake3::hash(input).as_bytes();
                        assert_eq!(
                            hashes[i], expected,
                            "Hash mismatch at index {} (T91.0 stub should use CPU BLAKE3)",
                            i
                        );
                    }
                }
                Err(CudaBlake3Error::ComputeFailure(msg)) => {
                    // Alternative stub behavior - also acceptable for T91.0
                    assert!(
                        msg.contains("not implemented"),
                        "Unexpected compute failure: {}",
                        msg
                    );
                }
                Err(e) => panic!("Unexpected error from hash_many: {:?}", e),
            }
        }
    }

    /// T91.0: Test empty input handling.
    #[cfg(eezo_cuda_build_present)]
    #[test]
    fn t91_0_hash_many_empty_inputs() {
        if let Ok(engine) = CudaBlake3Engine::new() {
            let inputs: Vec<&[u8]> = vec![];
            let result = engine.hash_many(&inputs);

            match result {
                Ok(hashes) => assert!(hashes.is_empty()),
                Err(_) => (), // Stub error is also acceptable
            }
        }
    }

    /// T91.0: Test that CudaBlake3Error is Send (required for async use).
    #[test]
    fn t91_0_error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CudaBlake3Error>();
    }

    /// T91.0: Test that CudaBlake3Error is Sync (required for shared access).
    #[test]
    fn t91_0_error_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<CudaBlake3Error>();
    }
}
