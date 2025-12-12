# T91.0 — CUDA BLAKE3 Engine Skeleton

This document describes the T91.0 milestone: introducing a CUDA-based BLAKE3 hashing engine for EEZO.

## Motivation

After T90.x established GPU hashing plumbing using wgpu/WGSL, we discovered that on some platforms (e.g., WSL2 with NVIDIA GPUs), Vulkan-based wgpu cannot see hardware devices even when CUDA works perfectly (verified via `nvidia-smi`).

To provide a robust GPU hashing option that works on more platforms, we're adding a CUDA-based BLAKE3 engine that does not depend on Vulkan.

## Scope of T91.0

T91.0 is specifically about **CUDA BLAKE3 plumbing**:

- **New crate**: `eezo-cuda-hash` dedicated to CUDA BLAKE3 hashing
- **Build plumbing**: Detects CUDA toolchain at build time
- **Clean API**: `CudaBlake3Engine` and `CudaBlake3Error` types
- **Safe behavior**: Never panics or segfaults on any machine
- **Stub implementation**: `hash_many()` uses CPU BLAKE3 as placeholder

### What T91.0 Does NOT Do

- Implement real CUDA BLAKE3 kernels (deferred to T91.1)
- Modify consensus-critical code paths
- Integrate with eezo-node or eezo-prover
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
    
    /// Hash multiple inputs using BLAKE3.
    /// T91.0: Stub implementation using CPU BLAKE3.
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

# Expected output on non-CUDA machine:
# t91_0_cuda_engine_init_is_safe: Err(RuntimeUnavailable)
```

### Test Guarantees

The `t91_0_cuda_engine_init_is_safe` test:

1. Calls `CudaBlake3Engine::new()`
2. Never panics or segfaults on any machine
3. Prints result for diagnostics
4. Passes regardless of CUDA availability

## Safety Properties

### Never Panics

`CudaBlake3Engine::new()` never panics:

- On non-CUDA builds: Returns `Err(RuntimeUnavailable)` immediately
- On CUDA builds without GPU: Returns `Err(DeviceUnavailable)`
- On CUDA init failure: Returns `Err(InitFailure(msg))`

### Never Segfaults

All CUDA operations are wrapped in safe Rust code:

- CUDA driver loading is handled by rustacuda
- Device enumeration is error-checked
- Context creation is error-checked

### CPU Remains Canonical

In T91.0, `hash_many()` uses CPU BLAKE3 as a placeholder:

- No consensus-critical code changes
- CPU BLAKE3 remains the single source of truth
- Real CUDA kernels will be added in T91.1

## Future Work

| Milestone | Scope |
|-----------|-------|
| T91.0 | ✅ CUDA plumbing, build detection, API skeleton |
| T91.1 | CUDA BLAKE3 kernel implementation |
| T91.2 | Integration with eezo-prover |
| T91.3 | Integration with eezo-node (shadow mode) |
| T91.4 | Performance optimization |

## Acceptance Criteria

T91.0 is complete when:

1. ✅ New `eezo-cuda-hash` crate exists in workspace
2. ✅ `cargo build --all` works with and without CUDA
3. ✅ `CudaBlake3Engine::new()` never panics or segfaults
4. ✅ On non-CUDA machines: Returns appropriate error
5. ✅ On CUDA-capable machines: Returns `Ok(_)` or appropriate error
6. ✅ Tests pass on any machine
7. ✅ No consensus-critical code changes
8. ✅ Documentation added to the book

## Files Changed

- `Cargo.toml`: Added `crates/eezo-cuda-hash` to workspace members
- `crates/eezo-cuda-hash/Cargo.toml`: New crate manifest
- `crates/eezo-cuda-hash/build.rs`: CUDA detection build script
- `crates/eezo-cuda-hash/src/lib.rs`: Engine API and implementation
- `crates/eezo-cuda-hash/README.md`: Crate documentation
- `book/src/t91_cuda_hash.md`: This documentation file
