# eezo-cuda-hash

CUDA-accelerated BLAKE3 hashing for EEZO.

## Overview

This crate provides a CUDA-based BLAKE3 hashing engine that does not depend on Vulkan. It is designed to be reusable from both the prover and node crates in future tasks.

## T91.1 Status

**T91.1 adds real CUDA BLAKE3 batch hashing.** The crate provides:

- Clean Rust API (`CudaBlake3Engine`, `CudaBlake3Error`)
- Build-time CUDA toolchain detection (`eezo_cuda_build_present` cfg)
- Safe behavior on machines without CUDA (returns `RuntimeUnavailable`)
- Real `hash_many()` implementation with CUDA-accelerated BLAKE3
- CPU cross-check tests verifying CUDA output matches CPU BLAKE3

**CPU BLAKE3 remains canonical.** Integration into eezo-node/eezo-prover will come in T91.2+.

## API

```rust
use eezo_cuda_hash::{CudaBlake3Engine, CudaBlake3Error};

fn main() -> Result<(), CudaBlake3Error> {
    // Create engine (attempts CUDA initialization)
    let engine = CudaBlake3Engine::new()?;
    
    // Hash multiple inputs
    let inputs: Vec<&[u8]> = vec![b"hello", b"world"];
    let hashes = engine.hash_many(&inputs)?;
    
    for hash in hashes {
        println!("{:02x?}", hash);  // Print as hex bytes
    }
    Ok(())
}
```

## Error Types

```rust
pub enum CudaBlake3Error {
    /// CUDA runtime not available (no driver, wrong build)
    RuntimeUnavailable,
    
    /// CUDA runtime present but no GPU device found
    DeviceUnavailable,
    
    /// CUDA context/stream initialization failed
    InitFailure(String),
    
    /// CUDA kernel execution failed
    ComputeFailure(String),
}
```

## Build Behavior

The crate uses `build.rs` to detect CUDA toolchain at build time:

1. **CUDA detected** (nvcc found):
   - Emits `cargo:rustc-cfg=eezo_cuda_build_present`
   - Compiles real CUDA initialization code
   - At runtime, attempts CUDA context creation

2. **CUDA not detected**:
   - Does NOT emit the cfg flag
   - Compiles stub implementation
   - `CudaBlake3Engine::new()` immediately returns `RuntimeUnavailable`

## Features

- `cuda`: Enable CUDA crate dependencies (rustacuda). Required for real CUDA operations in T91.1+.

## Usage

### Building without CUDA

```bash
# Works on any machine
cargo build -p eezo-cuda-hash
```

### Building with CUDA

```bash
# Requires CUDA toolkit installed
cargo build -p eezo-cuda-hash --features cuda
```

### Enabling via workspace

```bash
# Enable cuda-hash workspace feature
cargo build --features cuda-hash
```

## Testing

```bash
# Run all tests (safe on any machine)
cargo test -p eezo-cuda-hash

# Run T91.1 cross-check test
cargo test -p eezo-cuda-hash t91_1_cuda_hash_matches_cpu_for_varied_inputs -- --nocapture

# Expected behavior:
# - With CUDA: tests pass, hash_many() produces output matching CPU BLAKE3
# - Without CUDA: tests skip gracefully, engine creation returns RuntimeUnavailable
```

### T91.1 Cross-Check Tests

The `t91_1_cuda_hash_matches_cpu_for_varied_inputs` test:
- Skips on non-CUDA machines (does not fail)
- On CUDA machines: Tests diverse inputs (empty, small, medium, large)
- Cross-checks each CUDA hash against CPU BLAKE3
- Passes with zero mismatches

## Future Work

- T91.2: Integration with eezo-prover
- T91.3: Integration with eezo-node (shadow mode)
- T91.4: Performance optimization

## License

MIT OR Apache-2.0 (same as EEZO workspace)