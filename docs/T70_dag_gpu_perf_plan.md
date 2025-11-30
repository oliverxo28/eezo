# T70.0 — DAG + GPU Performance Plan

> **Status**: Design Document (T70.0)  
> **Last Updated**: 2024  
> **Scope**: Performance blueprint and measurement strategy for DAG consensus + GPU acceleration

---

## 1. Baseline Constraints

### 1.1 Current Architecture

The EEZO node currently operates with the following components:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Node Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐      │
│   │   Mempool   │────▶│     DAG     │────▶│  Hotstuff   │      │
│   │  (tx recv)  │     │  (tx feed)  │     │ (consensus) │      │
│   └─────────────┘     └─────────────┘     └─────────────┘      │
│                              │                    │             │
│                              ▼                    ▼             │
│                       ┌─────────────┐     ┌─────────────┐      │
│                       │  Template   │     │  Executor   │      │
│                       │  (dry-run)  │     │  (apply)    │      │
│                       └─────────────┘     └─────────────┘      │
│                                                   │             │
│                                                   ▼             │
│                                           ┌─────────────┐      │
│                                           │ Persistence │      │
│                                           │ (RocksDB)   │      │
│                                           └─────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key Components**:
- **Hotstuff Consensus**: Current production consensus (3-phase commit)
- **DAG Runner**: Feeds transactions to consensus via `EEZO_BLOCK_TX_SOURCE=dag`
- **Parallel Executor**: CPU-based parallel execution (`crates/node/src/executor`)
- **Template Gate**: Dry-run quality check (`EEZO_DAG_TEMPLATE_POLICY`)

### 1.2 GPU Usage (Current)

The `eezo-prover` crate uses GPU for:
- BLAKE3 hashing (WGSL compute shaders)
- Proof generation (STARK/SNARK preparation)

**Not yet used in node consensus/executor path**.

### 1.3 Current Bottleneck Categories

| Category | Location | Current Impact | GPU Potential |
|----------|----------|----------------|---------------|
| a) Consensus/DAG | `consensus_runner.rs`, `dag_runner.rs` | Ordering, QC votes | Low (mostly coordination) |
| b) Executor/VM | `executor/parallel.rs` | Tx execution, state updates | Medium (batch operations) |
| c) Storage/State I/O | `persistence.rs`, RocksDB | Block writes, state reads | Low (I/O bound) |
| d) Cryptography | Signatures, hashing | Verification, Merkle roots | **High** |

---

## 2. Target Architecture Sketch

### 2.1 Future "Full DAG + GPU" Vision

```
┌─────────────────────────────────────────────────────────────────┐
│                    Future DAG + GPU Architecture                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   DATA PLANE                                                    │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐      │
│   │   Mempool   │────▶│ DAG Vertex  │────▶│  Candidate  │      │
│   │  (batched)  │     │   Builder   │     │    Sets     │      │
│   └─────────────┘     └─────────────┘     └─────────────┘      │
│                                                  │              │
│   EXECUTION PLANE                                ▼              │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐      │
│   │    GPU      │◀───▶│  Executor   │◀────│  Sequence   │      │
│   │  Hasher     │     │  (CPU+GPU)  │     │  Selector   │      │
│   └─────────────┘     └─────────────┘     └─────────────┘      │
│         │                    │                                  │
│         ▼                    ▼                                  │
│   ┌─────────────┐     ┌─────────────┐                          │
│   │   Merkle    │     │   State     │                          │
│   │   Trie GPU  │     │   Commit    │                          │
│   └─────────────┘     └─────────────┘                          │
│                                                                 │
│   CONSENSUS PLANE                                               │
│   ┌─────────────┐     ┌─────────────┐                          │
│   │  DAG Core   │────▶│  QC/Vote    │                          │
│   │  (ordering) │     │  Finality   │                          │
│   └─────────────┘     └─────────────┘                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Separation of Concerns

- **Data Plane**: Mempool → DAG vertices → candidate sets
- **Execution Plane**: Selected tx sequence → executor (CPU+GPU hybrid)
- **Hashing/Commitments**: GPU-accelerated for block roots, Merkle tries

### 2.3 Task Roadmap

| Task | Description | Scope |
|------|-------------|-------|
| **T70.x** | Perf harness, microbenchmarks, executor profiling | Measurement |
| **T71.x** | GPU hashing integration into node for Merkle/roots | GPU in node |
| **T72+** | Partial DAG consensus core (multi-node) | Consensus evolution |

---

## 3. Performance Budgeting

### 3.1 Target: 1,000–5,000 TPS (Single Node)

For a **1-second block time** with **1,000 TPS**:
- **Per-tx CPU budget**: ~1ms maximum

For **5,000 TPS**:
- **Per-tx CPU budget**: ~0.2ms maximum

### 3.2 Budget Allocation Model

| Component | 1K TPS Budget | 5K TPS Budget | Notes |
|-----------|---------------|---------------|-------|
| Executor (tx apply) | 0.5ms | 0.1ms | Parallelize, batch |
| Hashing (sig verify, roots) | 0.3ms | 0.06ms | GPU candidate |
| Storage (state read/write) | 0.15ms | 0.03ms | Cache, batch writes |
| Consensus overhead | 0.05ms | 0.01ms | Amortized per block |
| **Total per-tx** | **1.0ms** | **0.2ms** | |

### 3.3 GPU Offload Targets

Priority order for GPU acceleration:
1. **Signature batch verification** — high parallelism, well-suited for GPU
2. **Merkle root computation** — tree-parallel, already in `eezo-prover`
3. **BLAKE3 block hashing** — batch hashing for commitments

---

## 4. Measurement Strategy

### 4.1 Per-Block Metrics

| Metric | Description | Prometheus Name |
|--------|-------------|-----------------|
| DAG build latency | Time to prepare DAG candidate | `eezo_block_dag_prepare_seconds` |
| Dry-run template latency | Template evaluation time | (part of dag_prepare) |
| Executor latency | Block execution time | `eezo_block_exec_seconds` |
| Commit latency | Hotstuff commit / block apply | `eezo_block_total_latency_seconds` |
| Tx counts | Candidate, template ok/failed, committed | Existing metrics |

### 4.2 Per-Transaction Metrics (Future)

- Executor time per tx (histogram)
- Signature verification time
- State access time

### 4.3 Perf Experiment Protocol

**Environment Variables**:
```bash
EEZO_PERF_MODE=off|baseline|dag_source
EEZO_BLOCK_TX_SOURCE=mempool|dag
EEZO_DAG_TEMPLATE_POLICY=off|clean_only|tolerate_partial
```

**Experiment Steps**:
1. Start node with desired `EEZO_PERF_MODE`
2. Run spam tool (`scripts/spam_tps.sh`) for N seconds
3. Scrape `/metrics` endpoint
4. Analyze `eezo_block_*_seconds` histograms

**Correlation**:
- `eezo_perf_run_id` gauge set once at startup for experiment identification

---

## 5. Task Breakdown

### T70.1 — Executor Performance Histogram Metrics
- **Where**: `crates/node/src/executor/parallel.rs`
- **What**: Add per-tx execution time histogram
- **Success**: Can measure P50/P99 tx execution latency

### T70.2 — DAG Candidate Size vs Latency Analysis
- **Where**: `crates/node/src/dag_runner.rs`
- **What**: Instrument candidate building with size/latency correlation
- **Success**: Identify optimal candidate batch size

### T70.3 — Signature Verification Profiling
- **Where**: `crates/ledger/src/consensus_sig.rs`
- **What**: Measure batch vs single sig verify
- **Success**: Baseline for GPU comparison

### T71.0 — GPU Hashing in Node (Merkle Roots)
- **Where**: `crates/node/src/executor`, `crates/eezo-prover/src/gpu_hash.rs`
- **What**: Integrate `gpu_hash` for Merkle root computation
- **Success**: Measurable speedup on Merkle operations

### T71.1 — GPU Signature Batch Verification
- **Where**: New module in `crates/node`
- **What**: Batch ML-DSA verification on GPU
- **Success**: 2-5x throughput improvement

### T72.0 — DAG Consensus Core Design
- **Where**: Design doc, new `crates/dag-consensus`
- **What**: Multi-node DAG ordering protocol
- **Success**: Formal specification, safety proofs

---

## 6. Non-Goals for T70.0

- ❌ No new consensus algorithm implementation
- ❌ No removal of Hotstuff
- ❌ No GPU integration into node (only referenced as future work)
- ❌ No changes to prover, bridge, contracts

---

## 7. References

- T56–T69: DAG runner implementation
- `crates/eezo-prover/src/gpu_hash.rs`: Existing GPU hashing
- `crates/node/src/executor/parallel.rs`: Parallel execution model
