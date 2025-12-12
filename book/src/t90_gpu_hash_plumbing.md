# T90.0 — GPU Hash Plumbing for eezo-node

This document describes the T90.0 milestone: introducing GPU-backed BLAKE3 hashing plumbing for eezo-node.

## Motivation

After completing the CPU-only deep performance pass (T82–T87), we consistently see:

- ~200–250 TPS in realistic windows for single-sender spam
- 300+ TPS bursts in Scenario B (32 senders, disjoint)
- Zero conflicts, retries, and aborted txs

To push beyond this CPU plateau, we're starting the GPU track carefully with a small, safe, non-consensus milestone first.

## Scope of T90.0

T90.0 is specifically about **GPU hashing plumbing** for eezo-node:

- **GPU hashing only**: No GPU signature verification yet
- **Non-consensus**: GPU hashes are computed but not used for block/state roots
- **Correctness-focused**: GPU hashes are validated against CPU (bit-for-bit)
- **Feature-gated**: Must be explicitly enabled at compile and runtime

### What T90.0 Does NOT Do

- Change consensus rules
- Change block header format, tx format, or wire protocols
- Replace CPU hashing in any consensus-critical path
- Add GPU signature verification

## Architecture

### Reusing eezo-prover GPU BLAKE3

T90.0 reuses the existing GPU BLAKE3 implementation from `eezo-prover`:

- **Module**: `crates/eezo-prover/src/gpu_hash.rs`
- **Backend**: wgpu/WGSL compute shader pipeline
- **API**: `GpuBlake3Context`, `Blake3GpuBatch`, `Blake3GpuBackend`

The node's GPU hash module wraps this prover backend with a clean API designed for node usage.

### Key Differences from Prover

| Aspect | eezo-prover | eezo-node |
|--------|-------------|-----------|
| Use case | Batch hashing for proofs | Single/small batch for blocks |
| Env var | `EEZO_GPU_HASH_REAL` | `EEZO_GPU_HASH_ENABLED` |
| Default | Off | Off |
| Validation | None (trusted) | Always validated against CPU |

## API

### GpuHashBackend

```rust
/// Error type for GPU hash backend operations.
pub enum GpuHashBackendError {
    DeviceUnavailable(String),
    ComputeFailure(String),
    FeatureDisabled,
    RuntimeDisabled,
}

/// GPU BLAKE3 hashing backend for eezo-node.
pub struct GpuHashBackend { ... }

impl GpuHashBackend {
    /// Create a new GPU hash backend.
    /// Returns error if GPU is unavailable or disabled.
    pub fn new() -> Result<Self, GpuHashBackendError>;

    /// Hash a batch of messages using BLAKE3 on the GPU.
    pub fn blake3_batch(&self, inputs: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, GpuHashBackendError>;

    /// Hash a single message (convenience wrapper).
    pub fn blake3_single(&self, input: &[u8]) -> Result<[u8; 32], GpuHashBackendError>;
}
```

### Diagnostic Hash Comparison

```rust
/// Compare GPU and CPU hashes for a batch of inputs.
/// Always returns CPU hashes (canonical for consensus).
/// Logs errors on GPU/CPU mismatches.
pub fn hash_batch_with_gpu_check(inputs: &[Vec<u8>]) -> Vec<[u8; 32]>;
```

## Configuration

### Cargo Feature

Enable the `gpu-hash` feature when building:

```bash
cargo build -p eezo-node \
  --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,gpu-hash"
```

### Environment Variable

Set `EEZO_GPU_HASH_ENABLED=1` to enable GPU hashing at runtime:

```bash
EEZO_GPU_HASH_ENABLED=1 \
EEZO_CONSENSUS_MODE=dag-primary \
./target/debug/eezo-node --genesis genesis.min.json --datadir /tmp/eezo-t90
```

### Full Example

```bash
# Build with gpu-hash feature
cargo build -p eezo-node --release \
  --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus,gpu-hash"

# Run with GPU hashing enabled
EEZO_GPU_HASH_ENABLED=1 \
EEZO_CONSENSUS_MODE=dag-primary \
EEZO_STM_KERNEL_MODE=arena \
./target/release/eezo-node \
  --genesis genesis.min.json \
  --datadir /tmp/eezo-t90 \
  --bind 127.0.0.1:8080
```

## Metrics

All metrics are behind the `metrics` feature and use the `eezo_gpu_hash_*` prefix:

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_gpu_hash_enabled` | Gauge | 1 if GPU hash backend initialized successfully, 0 otherwise |
| `eezo_gpu_hash_jobs_total` | Counter | Total number of GPU hash batches requested |
| `eezo_gpu_hash_failures_total` | Counter | Failed GPU jobs (device unavailable, compute errors) |
| `eezo_gpu_hash_latency_seconds` | Histogram | Per-batch GPU hash wall-clock time |
| `eezo_gpu_hash_bytes_total` | Counter | Total bytes hashed via GPU |
| `eezo_gpu_hash_mismatch_total` | Counter | GPU/CPU hash mismatches detected |

### Monitoring GPU Health

```bash
# Check if GPU is enabled
curl -s localhost:9100/metrics | grep eezo_gpu_hash_enabled

# Watch for failures
curl -s localhost:9100/metrics | grep eezo_gpu_hash_failures_total

# Check mismatch rate (should be 0)
curl -s localhost:9100/metrics | grep eezo_gpu_hash_mismatch_total
```

## Safety Notes

### CPU Remains Canonical

In T90.0, **CPU is always the single source of truth for consensus**:

1. CPU hash is computed first as ground truth
2. GPU hash (if enabled) runs in parallel
3. GPU/CPU comparison is performed
4. Mismatches are logged and counted
5. **CPU hash is always returned and used**

### Graceful Degradation

The node handles GPU failures gracefully:

- If GPU feature is not compiled: Node runs CPU-only
- If `EEZO_GPU_HASH_ENABLED != 1`: Node runs CPU-only
- If GPU device unavailable: Node logs warning, runs CPU-only
- If GPU compute fails: Node logs error, uses CPU result
- If GPU/CPU mismatch: Node logs error, uses CPU result

### No Consensus Impact

T90.0 makes **no changes** to:

- Block header format
- Transaction format
- State root computation
- Wire protocol
- Consensus rules

GPU hashing is purely diagnostic/experimental in this milestone.

## Testing

### Unit Tests

```bash
# Run T90.0 tests without GPU
cargo test -p eezo-node t90_0 --test-threads=1

# Run with GPU feature (requires GPU)
cargo test -p eezo-node t90_0 --features "gpu-hash" --test-threads=1
```

### Integration Test

```bash
# Build with GPU feature
cargo build -p eezo-node --features "gpu-hash,dag-consensus"

# Run node with GPU enabled
EEZO_GPU_HASH_ENABLED=1 ./target/debug/eezo-node ...

# Verify metrics
curl -s localhost:9100/metrics | grep eezo_gpu_hash
```

## Future Work

T90.0 is the foundation for future GPU milestones:

| Milestone | Scope |
|-----------|-------|
| T90.1 | GPU signature verification (non-consensus) |
| T90.2 | Batch GPU sig verify in sigpool |
| T90.3 | GPU hashes in consensus path (with cutover) |
| T90.4 | Performance tuning and optimization |

## Acceptance Criteria

T90.0 is complete when:

1. ✅ eezo-node compiles with and without `gpu-hash` feature
2. ✅ With `EEZO_GPU_HASH_ENABLED=0`: Node behaves exactly as before
3. ✅ With `gpu-hash` feature + `EEZO_GPU_HASH_ENABLED=1`:
   - Node attempts GPU backend initialization
   - `eezo_gpu_hash_enabled` reports correct status
   - GPU hashes match CPU BLAKE3 bit-for-bit in tests
4. ✅ Consensus rules, block/header/tx formats unchanged
5. ✅ GPU failures → graceful CPU fallback with logging/metrics
6. ✅ Documentation added to the book
