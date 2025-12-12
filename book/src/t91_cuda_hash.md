# T91 — CUDA BLAKE3 Engine

This document describes the T91 milestones: introducing a CUDA-based BLAKE3 hashing engine for EEZO.

## Motivation

After T90.x established GPU hashing plumbing using wgpu/WGSL, we discovered that on some platforms (e.g., WSL2 with NVIDIA GPUs), Vulkan-based wgpu cannot see hardware devices even when CUDA works perfectly (verified via `nvidia-smi`).

To provide a robust GPU hashing option that works on more platforms, we're adding a CUDA-based BLAKE3 engine that does not depend on Vulkan.

## T91.0: CUDA BLAKE3 Plumbing (Completed)

T91.0 introduced the foundational structure:

- **New crate**: `eezo-cuda-hash` dedicated to CUDA BLAKE3 hashing
- **Build plumbing**: Detects CUDA toolchain at build time
- **Clean API**: `CudaBlake3Engine` and `CudaBlake3Error` types
- **Safe behavior**: Never panics or segfaults on any machine

## T91.1: CUDA BLAKE3 Batch Hashing (Current)

T91.1 adds real CUDA BLAKE3 batch hashing with CPU cross-check:

- **Real `hash_many()` implementation**: Performs CUDA-accelerated BLAKE3 hashing when CUDA is available
- **CPU cross-check tests**: Verifies CUDA output matches CPU BLAKE3 for diverse inputs
- **Error handling**: Returns `ComputeFailure(msg)` on CUDA-side errors
- **CPU remains canonical**: CUDA output is validated against CPU BLAKE3 in tests

### What T91.1 Does NOT Do

- Integrate with eezo-node or eezo-prover (deferred to T91.2+)
- Modify consensus-critical code paths
- Change block/header/tx formats

## Architecture

### New Crate: eezo-cuda-hash

Location: `crates/eezo-cuda-hash/`

This crate provides a standalone CUDA BLAKE3 engine that:

1. Detects CUDA toolchain at build time via `build.rs`
2. Emits `eezo_cuda_build_present` cfg when CUDA is available
3. Compiles real CUDA init code or stub based on cfg
4. Provides a clean Rust API for callers

### Build Behavior

The `build.rs` script detects CUDA by looking for `nvcc`:

1. Check if `nvcc` is in PATH
2. Check `CUDA_PATH` environment variable
3. Check common CUDA installation paths
4. Try running `nvcc --version`

If CUDA is detected, it emits:
```
cargo:rustc-cfg=eezo_cuda_build_present
```

### Rust API

```rust
use eezo_cuda_hash::{CudaBlake3Engine, CudaBlake3Error};

/// Error type for CUDA BLAKE3 operations.
#[derive(Debug, thiserror::Error)]
pub enum CudaBlake3Error {
    /// CUDA runtime is not available
    RuntimeUnavailable,
    
    /// CUDA runtime present but no GPU device found
    DeviceUnavailable,
    
    /// CUDA initialization failed
    InitFailure(String),
    
    /// CUDA kernel execution failed
    ComputeFailure(String),
}

/// CUDA BLAKE3 hashing engine.
pub struct CudaBlake3Engine { /* opaque */ }

impl CudaBlake3Engine {
    /// Create a new CUDA BLAKE3 engine.
    /// Returns error if CUDA is unavailable.
    pub fn new() -> Result<Self, CudaBlake3Error>;
    
    /// Hash multiple inputs using BLAKE3 on the GPU.
    /// Returns Vec<[u8; 32]> with one digest per input.
    /// Returns ComputeFailure on GPU errors.
    pub fn hash_many(&self, inputs: &[&[u8]]) -> Result<Vec<[u8; 32]>, CudaBlake3Error>;
}
```

## Configuration

### Building the Crate

```bash
# Build without CUDA (always works)
cargo build -p eezo-cuda-hash

# Build with CUDA feature (requires CUDA toolkit)
cargo build -p eezo-cuda-hash --features cuda
```

### Runtime Behavior

| Build-time CUDA | Runtime Result |
|-----------------|----------------|
| Not detected | `new()` returns `Err(RuntimeUnavailable)` |
| Detected, no GPU | `new()` returns `Err(DeviceUnavailable)` |
| Detected, GPU OK | `new()` returns `Ok(engine)` |

## Testing

### Running Tests

```bash
# Run tests (safe on any machine)
cargo test -p eezo-cuda-hash

# Run T91.1 cross-check test specifically
cargo test -p eezo-cuda-hash t91_1_cuda_hash_matches_cpu_for_varied_inputs -- --nocapture

# Expected output on non-CUDA machine:
# CUDA not available, skipping T91.1 test

# Expected output on CUDA machine:
# T91.1: CUDA engine initialized, running cross-check tests...
# T91.1: All 5 hashes match CPU BLAKE3 reference
```

### T91.0 Test Guarantees

The `t91_0_cuda_engine_init_is_safe` test:

1. Calls `CudaBlake3Engine::new()`
2. Never panics or segfaults on any machine
3. Prints result for diagnostics
4. Passes regardless of CUDA availability

### T91.1 CPU Cross-Check Tests

The `t91_1_cuda_hash_matches_cpu_for_varied_inputs` test:

1. Attempts to initialize `CudaBlake3Engine`
2. On non-CUDA machines: Skips with message (does not fail)
3. On CUDA machines: Tests with diverse inputs:
   - Empty message
   - Short ASCII string ("hello world")
   - Single zero byte
   - 1KB of 0x01 bytes
   - Large message (32KB)
4. Cross-checks each CUDA hash against CPU BLAKE3
5. Passes with zero mismatches on CUDA-capable machines

Additional T91.1 tests:
- `t91_1_cuda_hash_edge_cases`: Empty, identical, and alternating messages
- `t91_1_cuda_hash_large_batch`: 100 messages of varying sizes

## Safety Properties

### Never Panics

`CudaBlake3Engine::new()` never panics:

- On non-CUDA builds: Returns `Err(RuntimeUnavailable)` immediately
- On CUDA builds without GPU: Returns `Err(DeviceUnavailable)`
- On CUDA init failure: Returns `Err(InitFailure(msg))`

`hash_many()` never panics:

- On CUDA kernel failure: Returns `Err(ComputeFailure(msg))`
- On empty input: Returns `Ok(Vec::new())`

### Never Segfaults

All CUDA operations are wrapped in safe Rust code:

- CUDA driver loading is handled by rustacuda
- Device enumeration is error-checked
- Context creation is error-checked
- Memory operations are error-checked

### CPU Remains Canonical

CPU BLAKE3 remains the canonical/authoritative implementation:

- No consensus-critical code changes
- CUDA output is cross-checked against CPU BLAKE3 in tests
- Integration into eezo-node/eezo-prover will come in T91.2+

## Future Work

| Milestone | Scope |
|-----------|-------|
| T91.0 | ✅ CUDA plumbing, build detection, API skeleton |
| T91.1 | ✅ CUDA BLAKE3 batch hashing + CPU cross-check tests |
| T91.2 | Integration with eezo-prover |
| T91.3 | Integration with eezo-node (shadow mode) |
| T91.4 | Performance optimization |

## Acceptance Criteria

### T91.0 (Completed)

1. ✅ New `eezo-cuda-hash` crate exists in workspace
2. ✅ `cargo build --all` works with and without CUDA
3. ✅ `CudaBlake3Engine::new()` never panics or segfaults
4. ✅ On non-CUDA machines: Returns appropriate error
5. ✅ On CUDA-capable machines: Returns `Ok(_)` or appropriate error
6. ✅ Tests pass on any machine
7. ✅ No consensus-critical code changes
8. ✅ Documentation added to the book

### T91.1 (Current)

1. ✅ `hash_many()` performs real CUDA BLAKE3 batch hashing
2. ✅ On CUDA failure: Returns `ComputeFailure(msg)`
3. ✅ CPU cross-check test `t91_1_cuda_hash_matches_cpu_for_varied_inputs`
4. ✅ Test skips on non-CUDA machines (does not fail)
5. ✅ Test passes with zero mismatches on CUDA machines
6. ✅ No changes to eezo-node or eezo-prover
7. ✅ Documentation updated

## Files Changed

- `Cargo.toml`: Added `crates/eezo-cuda-hash` to workspace members
- `crates/eezo-cuda-hash/Cargo.toml`: New crate manifest
- `crates/eezo-cuda-hash/build.rs`: CUDA detection build script
- `crates/eezo-cuda-hash/src/lib.rs`: Engine API and implementation
- `crates/eezo-cuda-hash/README.md`: Crate documentation
- `book/src/t91_cuda_hash.md`: This documentation file