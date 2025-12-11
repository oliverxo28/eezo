# T83.0 — PQ Signature Pipeline (SigPool pinned threads + micro-batching)

## Overview

T83.0 implements an enhanced signature verification pipeline for ML-DSA and other PQ 
signature schemes. The goal is to improve TPS by:

1. **Dedicated worker threads**: Signature verification runs on separate threads from 
   the STM executor, preventing contention
2. **Micro-batching**: Individual verification requests are buffered into batches 
   (default: 64) for better cache locality and reduced per-tx overhead
3. **Short-lived replay cache**: Recent signature results are cached to avoid 
   re-verifying the same signature multiple times

This is a **pure implementation optimization**:
- No skipped verification
- No change to validation rules
- No change to any external API or wire format
- Same deterministic behavior

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        SigPool                               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐ │
│  │   Job TX    │───▶│   Batcher   │───▶│  Worker Threads │ │
│  │  (Channel)  │    │ (Micro-Batch)│    │  (ML-DSA Verify)│ │
│  └─────────────┘    └─────────────┘    └─────────────────┘ │
│         │                                       │           │
│         ▼                                       ▼           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 Replay Cache (LRU)                   │   │
│  │         Key: tx_hash or blake3(pk||msg||sig)         │   │
│  │         Value: verified_ok (bool)                    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

The following environment variables control SigPool behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `EEZO_SIGPOOL_THREADS` | `num_cpus / 2` | Number of worker threads for verification |
| `EEZO_SIGPOOL_BATCH_SIZE` | `64` | Maximum batch size before dispatch |
| `EEZO_SIGPOOL_BATCH_TIMEOUT_MS` | `5` | Timeout (ms) for partial batch flush |
| `EEZO_SIGPOOL_CACHE_SIZE` | `8192` | Maximum entries in replay cache |
| `EEZO_SIGPOOL_QUEUE` | `20000` | Maximum queued verification requests |

### Recommended Settings

For high-TPS scenarios (>200 TPS):
```bash
export EEZO_SIGPOOL_THREADS=8
export EEZO_SIGPOOL_BATCH_SIZE=64
export EEZO_SIGPOOL_CACHE_SIZE=16384
```

For low-latency scenarios:
```bash
export EEZO_SIGPOOL_BATCH_SIZE=16
export EEZO_SIGPOOL_BATCH_TIMEOUT_MS=2
```

## Metrics

T83.0 adds the following Prometheus metrics (all under `eezo_sigpool_*`):

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_sigpool_queued_total` | Counter | Total verification requests received |
| `eezo_sigpool_verified_total` | Counter | Successful verifications |
| `eezo_sigpool_failed_total` | Counter | Failed verifications |
| `eezo_sigpool_active_threads` | Gauge | Active worker thread count |
| `eezo_sigpool_batches_total` | Counter | Micro-batches executed |
| `eezo_sigpool_batch_size` | Histogram | Distribution of batch sizes |
| `eezo_sigpool_cache_hits_total` | Counter | Cache hits (skipped re-verify) |
| `eezo_sigpool_cache_misses_total` | Counter | Cache misses (actual verify) |
| `eezo_sigpool_batch_latency_seconds` | Histogram | Batch verification time |

### Observing Pipeline Performance

Query cache efficiency:
```
rate(eezo_sigpool_cache_hits_total[5m]) / 
(rate(eezo_sigpool_cache_hits_total[5m]) + rate(eezo_sigpool_cache_misses_total[5m]))
```

Query batch efficiency (how full are batches?):
```
histogram_quantile(0.5, rate(eezo_sigpool_batch_size_bucket[5m]))
```

## Testing

Run the T83.0 unit tests:
```bash
cargo test -p eezo-node --lib --features "pq44-runtime,metrics" sigpool
```

Run the integration tests (requires full feature set):
```bash
cargo test -p eezo-node --features "pq44-runtime,metrics" t83
```

## Implementation Notes

### Replay Cache

The cache uses LRU eviction with a configurable capacity. Cache entries are keyed by:
- Explicit `tx_hash` if provided (most efficient)
- Or `blake3(pubkey || message || signature)` as fallback

The cache is **best-effort**: eviction doesn't change correctness, just performance.
A cache miss simply triggers actual verification.

### Micro-Batch Scheduling

Batches are dispatched when:
1. Batch reaches `EEZO_SIGPOOL_BATCH_SIZE` entries (capacity trigger)
2. `EEZO_SIGPOOL_BATCH_TIMEOUT_MS` elapses with pending entries (timeout trigger)

The timeout trigger ensures low-latency at low TPS (prevents starvation).

### Thread Affinity

Currently, workers use Tokio's multi-threaded runtime without explicit CPU pinning.
Future work (T83.1+) may add optional affinity hints for further optimization.

### Dev-Unsafe Mode

When `dev-unsafe` feature + `EEZO_DEV_ALLOW_UNSIGNED_TX=1`, signature verification
is skipped entirely (for local benchmarks only). This behavior is unchanged by T83.0.

## Future Work

- **T83.1**: GPU-accelerated signature verification (optional CUDA/OpenCL backend)
- **T83.2**: Hybrid hashing pipeline (GPU + CPU coordination)
- **T83.3**: Thread affinity and NUMA-aware allocation
