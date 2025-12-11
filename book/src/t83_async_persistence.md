# T83.2 — Async Persistence Pipeline + Mutable Head

This document describes the asynchronous persistence pipeline introduced in T83.2 to remove RocksDB from the TPS critical path.

## Overview

Prior to T83.2, block persistence was synchronous:
1. Execute block via STM executor
2. Apply overlay to in-memory state
3. **Synchronously write to RocksDB** (bottleneck)
4. Start next block

With T83.2, persistence is decoupled:
1. Execute block via STM executor
2. Apply overlay to in-memory state
3. Apply to **CommittedMemHead** (fast, in-memory)
4. **Enqueue** block for async RocksDB write
5. Start next block immediately

## Architecture

### CommittedMemHead

The `CommittedMemHead` is an in-memory layer that holds recently committed account state:

```rust
pub struct CommittedMemHead {
    // Recently committed accounts: (address → (height, Account))
    accounts: HashMap<Address, (u64, Account)>,
    // Recently committed supply
    supply: Option<(u64, Supply)>,
    // Highest block in memory
    head_height: u64,
    // Highest block confirmed persisted to RocksDB
    persisted_height: u64,
}
```

When the executor needs a base snapshot for Block N+1:
1. Check CommittedMemHead first (recent commits)
2. Fall back to RocksDB for older data

This ensures the executor always sees the latest state, even when RocksDB is behind.

### PersistenceWorker

A background tokio task that:
1. Receives `PersistenceMsg` from a bounded channel
2. Applies blocks to RocksDB in commit order
3. Updates `persisted_height` when writes complete
4. Periodically prunes CommittedMemHead

```rust
pub enum PersistenceMsg {
    ApplyBlock {
        height: u64,
        header: BlockHeader,
        block: Block,
        snapshot: Option<StateSnapshot>,
    },
    FlushAndShutdown,
}
```

## Design Invariants

### 1. Ordering Guarantee

Writes are applied to RocksDB in the exact order blocks are committed. The persistence worker processes messages sequentially from its channel.

### 2. Read-After-Write Consistency

Snapshots for new blocks layer CommittedMemHead on top of RocksDB:

```
┌─────────────────────────┐
│   CommittedMemHead      │  ← Most recent commits (fast reads)
├─────────────────────────┤
│   RocksDB Snapshot      │  ← Older confirmed state
└─────────────────────────┘
```

This prevents the "read-after-write gap" where a new block might read stale state because RocksDB hasn't caught up.

### 3. Crash Safety

On crash:
- Up to a few blocks may be lost from CommittedMemHead
- RocksDB contains the last confirmed state
- On restart, the node resumes from RocksDB's tip height

This is acceptable for devnet/testnet. For production, consider:
- Write-ahead log for CommittedMemHead
- Synchronous flush at checkpoints

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EEZO_PERSIST_ASYNC` | `0` (off) | Set to `1` to enable async persistence |
| `EEZO_PERSIST_QUEUE_CAP` | `1000` | Max blocks in the persistence queue |

### Metrics

When `metrics` feature is enabled:

| Metric | Type | Description |
|--------|------|-------------|
| `eezo_persist_queue_len` | Gauge | Pending blocks in queue |
| `eezo_persist_blocks_total` | Counter | Total blocks persisted |
| `eezo_persist_block_latency_seconds` | Histogram | Per-block persistence time |
| `eezo_persist_head_entries` | Gauge | Accounts in CommittedMemHead |

## How to Benchmark T83.2

### Prerequisites

Build with required features:
```bash
cargo build --release -p eezo-node --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus"
```

### Sync Mode (Baseline)

Terminal 1 - Start node:
```bash
./scripts/devnet_dag_primary.sh
```

Terminal 2 - Submit transactions:
```bash
./scripts/spam_tps.sh 5000 http://127.0.0.1:8080
```

Terminal 3 - Measure TPS:
```bash
./scripts/tps_benchmark.sh --duration 20 --warmup 10 --verbose
```

### Async Mode

Terminal 1 - Start node with async persistence:
```bash
EEZO_PERSIST_ASYNC=1 ./scripts/devnet_dag_primary.sh
```

Terminal 2 & 3 - Same as above

### Expected Results

With async persistence enabled:
- Lower block latency (persistence not blocking execution)
- Higher sustained TPS under load
- `eezo_persist_queue_len` may spike briefly under burst load
- `eezo_persist_head_entries` shows memory usage of recent state

## Implementation Details

### File Locations

- `crates/node/src/persistence_worker.rs` - CommittedMemHead and PersistenceWorker
- `crates/node/src/consensus_runner.rs` - Integration with executor loop
- `crates/node/src/metrics.rs` - Persistence metrics

### Tests

Run unit tests:
```bash
cargo test --features "pq44-runtime,metrics,checkpoints,stm-exec,dag-consensus" \
  --bin eezo-node persistence_worker
```

### Code Path

1. **Block Commit** (`consensus_runner.rs`):
   ```rust
   // Apply to in-memory head
   mem_head.apply_write_set(&write_set);
   
   // Enqueue for async persistence
   persist_handle.enqueue_block(height, header, block, snapshot).await;
   ```

2. **Worker Loop** (`persistence_worker.rs`):
   ```rust
   while let Some(msg) = receiver.recv().await {
       match msg {
           PersistenceMsg::ApplyBlock { height, header, block, snapshot } => {
               db.put_header_and_block(height, &header, &block)?;
               if let Some(snap) = snapshot {
                   db.put_snapshot(&snap)?;
               }
               mem_head.mark_persisted(height);
           }
           PersistenceMsg::FlushAndShutdown => break,
       }
   }
   ```

3. **Snapshot Read** (for next block):
   ```rust
   fn get_account(&self, addr: &Address) -> Account {
       // Try CommittedMemHead first
       if let Some(acct) = mem_head.get_account(addr) {
           return acct;
       }
       // Fall back to RocksDB
       rocksdb.get_account(addr)
   }
   ```

## Future Work

1. **Write-ahead log**: For production crash safety
2. **Adaptive batching**: Group multiple blocks per RocksDB write
3. **Background compaction**: Trigger RocksDB compaction during low activity
4. **Memory limits**: Cap CommittedMemHead size with LRU eviction

## Operator Notes

### When to Enable Async Persistence

Enable `EEZO_PERSIST_ASYNC=1` when:
- Running high-TPS workloads (devnet, testnet under load)
- Block latency is more important than immediate disk durability
- Node is a validator focused on throughput

### When to Prefer Sync Mode

Keep async disabled (default) when:
- Running archival nodes where disk durability is critical
- Operating in production with strict recovery requirements
- Debugging persistence-related issues

### Monitoring Async Persistence

Key metrics to watch:

| Metric | Normal Range | Warning Signs |
|--------|--------------|---------------|
| `eezo_persist_queue_len` | 0-10 | >100 sustained = worker falling behind |
| `eezo_persist_blocks_total` | Increasing | Flat = worker stalled |
| `eezo_persist_block_latency_seconds` | <100ms p99 | >500ms = slow disk |
| `eezo_persist_head_entries` | <10000 | >100000 = memory pressure |

If `queue_len` grows unbounded:
1. Check disk I/O metrics
2. Consider reducing block production rate
3. Verify RocksDB is not compacting heavily

### Crash Recovery

In async mode, the node may lose the last few blocks on crash:
- RocksDB contains the last confirmed state
- On restart, node resumes from RocksDB tip
- Missing blocks are re-fetched via state sync or replay

This is acceptable for devnet/testnet. For production:
- Consider enabling write-ahead logging (future work)
- Use synchronous mode for critical validators
