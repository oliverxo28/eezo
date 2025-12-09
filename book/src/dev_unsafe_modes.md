# Dev-Unsafe Modes (T77.SAFE-2)

This document describes the security hardening for development-only features that bypass signature verification.

## Overview

The EEZO codebase includes development-only features that are useful for local testing and benchmarking but would be dangerous if used in production:

1. **`skip-sig-verify` feature**: Completely bypasses all signature verification
2. **`EEZO_DEV_ALLOW_UNSIGNED_TX` environment variable**: Allows unsigned transactions

As of T77.SAFE-2, both of these are protected by a new `dev-unsafe` feature gate.

## Security Model

### Before T77.SAFE-2
- `EEZO_DEV_ALLOW_UNSIGNED_TX=1` could affect any build
- `skip-sig-verify` could be enabled independently

### After T77.SAFE-2
- `EEZO_DEV_ALLOW_UNSIGNED_TX` env var **only works** when `dev-unsafe` feature is enabled
- `skip-sig-verify` feature **requires** `dev-unsafe` feature
- Default builds, release builds, and CI builds **never** include `dev-unsafe`
- A prominent warning is logged at startup if dev-unsafe mode is active

## Feature Flag Hierarchy

```
dev-unsafe
├── enables skip-sig-verify (if requested)
└── enables EEZO_DEV_ALLOW_UNSIGNED_TX env var

skip-sig-verify
└── requires dev-unsafe (automatically enabled)
```

## How to Enable Dev-Unsafe Mode

### For Local Development Benchmarks

**Build with dev-unsafe feature:**
```bash
# Build eezo-node with dev-unsafe mode
cargo build -p eezo-node --features dev-unsafe

# Run with unsigned tx support for benchmarking
EEZO_DEV_ALLOW_UNSIGNED_TX=1 ./target/debug/eezo-node
```

### For Tests That Need Dev Mode

**In Cargo.toml test configuration:**
```toml
[[test]]
name = "my_unsigned_tx_test"
required-features = ["dev-unsafe"]
```

**In test code:**
```rust
#[cfg(feature = "dev-unsafe")]
#[test]
fn test_unsigned_transactions() {
    std::env::set_var("EEZO_DEV_ALLOW_UNSIGNED_TX", "1");
    // ... test code that uses unsigned transactions
    std::env::remove_var("EEZO_DEV_ALLOW_UNSIGNED_TX");
}
```

## Commands for Running Nodes

### Safe Production Node (default)

```bash
# Default build - no unsafe features
cargo build -p eezo-node --release

# Run - EEZO_DEV_ALLOW_UNSIGNED_TX has NO effect
EEZO_DEV_ALLOW_UNSIGNED_TX=1 ./target/release/eezo-node  # Still rejects unsigned tx!
```

### Dev-Unsafe Node (local testing only)

```bash
# Dev-unsafe build - NEVER use in production
cargo build -p eezo-node --features dev-unsafe

# Run with unsigned tx allowed
EEZO_DEV_ALLOW_UNSIGNED_TX=1 ./target/debug/eezo-node

# You will see this warning at startup:
# [WARN] ===============================================================================
# [WARN] [DEV-UNSAFE] This build has dev-unsafe mode ENABLED.
# [WARN] [DEV-UNSAFE] Signature verification bypass is available.
# [WARN] [DEV-UNSAFE] NEVER use this build in production, testnet, or mainnet!
# [WARN] ===============================================================================
```

## CI/CD Safety

The default feature set in all crates does **not** include `dev-unsafe`:

- `eezo-crypto`: `default = ["mldsa", "mlkem"]`
- `eezo-ledger`: `default = ["pq44-runtime", "checkpoints"]`
- `eezo-node`: `default = ["pq44-runtime", "metrics", "eth-ssz", "checkpoints"]`

CI workflows run:
- `cargo build --workspace` → safe (no dev-unsafe)
- `cargo test --workspace` → safe (no dev-unsafe)
- `cargo build --release` → safe (no dev-unsafe)

## Compile-Time Safety

The `skip-sig-verify` feature includes a compile-time assertion:

```rust
#[cfg(all(feature = "skip-sig-verify", not(feature = "dev-unsafe")))]
compile_error!(
    "skip-sig-verify feature requires dev-unsafe feature. \
     NEVER enable these features in production/testnet/mainnet builds!"
);
```

If someone tries to enable `skip-sig-verify` without `dev-unsafe`, the build will fail with a clear error message.

## Runtime Safety

Even if someone manages to set `EEZO_DEV_ALLOW_UNSIGNED_TX=1` on a production build:

```rust
pub fn allow_unsigned_tx() -> bool {
    #[cfg(not(feature = "dev-unsafe"))]
    {
        false  // Always false without dev-unsafe, regardless of env var
    }
    // ...
}
```

The function returns `false` at compile time if `dev-unsafe` is not enabled.

## Files Modified

- `crates/crypto/Cargo.toml`: Added `dev-unsafe` feature, made `skip-sig-verify` require it
- `crates/crypto/src/sig/mod.rs`: Added compile-time assertion
- `crates/ledger/Cargo.toml`: Added `dev-unsafe` feature, forwarded to crypto
- `crates/ledger/src/dev_unsafe.rs`: Centralized dev-unsafe gate module
- `crates/ledger/src/lib.rs`: Exported dev_unsafe module
- `crates/ledger/src/tx.rs`: Updated to use centralized gate
- `crates/ledger/src/mempool.rs`: Updated to use centralized gate
- `crates/node/Cargo.toml`: Added `dev-unsafe` feature
- `crates/node/src/main.rs`: Added startup warning

## Summary

| Scenario | `dev-unsafe` feature | `EEZO_DEV_ALLOW_UNSIGNED_TX` | Unsigned tx accepted? |
|----------|---------------------|------------------------------|----------------------|
| Production build | ❌ No | `=1` | ❌ **No** |
| Production build | ❌ No | not set | ❌ No |
| Dev-unsafe build | ✅ Yes | `=1` | ✅ Yes |
| Dev-unsafe build | ✅ Yes | not set | ❌ No |

**Key takeaway**: Production/release/testnet/mainnet builds should **never** include the `dev-unsafe` feature. It is only for local development benchmarks.

---

## T78.7: Benchmark vs Devnet-Safe Build Profiles

T78.7 introduces two explicit build profiles for clarity:

### 1. Benchmark Build (Dev-Unsafe)

Use this for **local TPS testing** and **development benchmarks**. This build:
- Includes `dev-unsafe` feature
- Allows `EEZO_DEV_ALLOW_UNSIGNED_TX=1` to accept unsigned transactions
- Shows prominent DEV-UNSAFE warnings in logs
- Should **NEVER** be deployed to any network

**Build command:**
```bash
# Benchmark build with dev-unsafe for local spam testing
cargo build -p eezo-node --features "pq44-runtime,checkpoints,metrics,dev-unsafe,stm-exec,dag-consensus"
```

**Run command:**
```bash
export EEZO_DEV_ALLOW_UNSIGNED_TX=1
export EEZO_CONSENSUS_MODE=dag-primary
export EEZO_DAG_ORDERING_ENABLED=1
./target/debug/eezo-node
```

### 2. Devnet-Safe Build

Use this for **official devnet deployments**. This build:
- Does **NOT** include `dev-unsafe` feature
- Setting `EEZO_DEV_ALLOW_UNSIGNED_TX=1` has **no effect** (with a warning log)
- Defaults to `dag-primary` consensus mode when `EEZO_CONSENSUS_MODE` is unset
- Defaults to `EEZO_DAG_ORDERING_ENABLED=1` behavior when unset
- Includes STM executor and DAG consensus
- HotStuff shadow checker only available with `hotstuff-shadow` feature

**Build command (minimal devnet-safe):**
```bash
# Devnet-safe build (no unsigned tx support)
cargo build -p eezo-node --features "pq44-runtime,checkpoints,metrics,stm-exec,dag-consensus"
```

**Build command (using devnet-safe meta-feature):**
```bash
# Using the devnet-safe feature which bundles recommended features
cargo build -p eezo-node --features "devnet-safe"
```

**Build command (with HotStuff shadow checker):**
```bash
# Devnet-safe with shadow HotStuff for observability
cargo build -p eezo-node --features "devnet-safe,hotstuff-shadow"
```

**Run command:**
```bash
# No env vars needed - defaults are correct for dag-primary
./target/release/eezo-node
```

### Feature Comparison

| Feature | Benchmark Build | Devnet-Safe Build |
|---------|-----------------|-------------------|
| `dev-unsafe` | ✅ Included | ❌ NOT included |
| `dag-consensus` | ✅ Included | ✅ Included |
| `stm-exec` | ✅ Included | ✅ Included |
| `hotstuff-shadow` | Optional | Optional |
| Default consensus mode | Hotstuff | DagPrimary |
| Unsigned tx accepted? | Only with env var | **Never** |
| Suitable for network? | ❌ No | ✅ Yes |

### EEZO_DEV_ALLOW_UNSIGNED_TX Behavior by Build

| Build Profile | Env Var Set | Effect |
|--------------|-------------|--------|
| Dev-unsafe build | `=1` | Unsigned txs accepted |
| Dev-unsafe build | not set | Unsigned txs rejected |
| Devnet-safe build | `=1` | **No effect** + warning log |
| Devnet-safe build | not set | Unsigned txs rejected |

The warning log in devnet-safe builds looks like:
```
[T78.8] EEZO_DEV_ALLOW_UNSIGNED_TX is set but this is a SAFE BUILD.
[T78.8] The env var has NO EFFECT. Unsigned txs will be REJECTED.
```

---

## T78.8: Build Profiles Matrix

This section provides a comprehensive matrix of EEZO build profiles for different deployment scenarios.

### Profiles Summary

| Profile | Features | Example Use | Unsigned TX Allowed? | Default Consensus Mode | DAG Ordering Default |
|---------|----------|-------------|---------------------|----------------------|---------------------|
| **dev-unsafe** | `dev-unsafe` + others | Local TPS benchmarks | Yes (env-gated) | configurable | configurable |
| **devnet-safe** | `devnet-safe` | Official devnet | **No** | dag-primary | true |
| **generic** | without dev-unsafe | General/CI builds | **No** | hotstuff | false |
| **testnet** (future) | TBD | Public testnet | **No** | dag-primary | true |
| **mainnet** (future) | TBD | Production | **No** | dag-primary | true |

### Build Commands

#### Devnet-Safe Build (Recommended for Devnet Deployments)

This is the recommended build profile for day-to-day devnet deployments:

```bash
# Option 1: Using the devnet-safe meta-feature (recommended)
cargo build --release -p eezo-node --features "devnet-safe"

# Option 2: With explicit features
cargo build --release -p eezo-node \
  --features "pq44-runtime,persistence,checkpoints,metrics,stm-exec,dag-consensus,devnet-safe"

# Option 3: With HotStuff shadow checker for additional observability
cargo build --release -p eezo-node --features "devnet-safe,hotstuff-shadow"
```

**Behavior in devnet-safe build:**
- `EEZO_CONSENSUS_MODE` defaults to `dag-primary` when unset
- `EEZO_DAG_ORDERING_ENABLED` defaults to `true` when unset
- `EEZO_DEV_ALLOW_UNSIGNED_TX` has **no effect** (warning logged if set)
- Shadow HotStuff checker available with `hotstuff-shadow` feature

**Run command (minimal config needed):**
```bash
# Defaults are already correct for dag-primary
./target/release/eezo-node
```

#### Dev-Unsafe Build (Local TPS Benchmarks Only)

This build profile is for local development and benchmarking only. **NEVER deploy to any network.**

```bash
# Build with dev-unsafe feature
cargo build -p eezo-node \
  --features "pq44-runtime,persistence,checkpoints,metrics,stm-exec,dag-consensus,dev-unsafe"
```

**Behavior in dev-unsafe build:**
- `EEZO_DEV_ALLOW_UNSIGNED_TX=1` enables unsigned tx acceptance
- Prominent `[DEV-UNSAFE]` warnings printed at startup
- All signature verification can be bypassed
- Should only be used for local spam testing

**Run command:**
```bash
export EEZO_DEV_ALLOW_UNSIGNED_TX=1
export EEZO_CONSENSUS_MODE=dag-primary
export EEZO_DAG_ORDERING_ENABLED=1
./target/debug/eezo-node
```

### Verification Commands

To verify which build profile you are running:

```bash
# Check the startup log for build profile
./target/release/eezo-node 2>&1 | grep "T78.8"
# Expected: [T78.8] Build profile: devnet-safe

# Check consensus mode metric
curl -s http://localhost:3030/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 3  (3 = dag-primary)
```

### Safety Guarantees

| Feature | dev-unsafe | devnet-safe | generic |
|---------|-----------|-------------|---------|
| `EEZO_DEV_ALLOW_UNSIGNED_TX` works | ✅ Yes | ❌ No | ❌ No |
| Unsigned tx accepted | ✅ With env var | ❌ Never | ❌ Never |
| Signature bypass available | ✅ Yes | ❌ No | ❌ No |
| Safe for devnet | ❌ No | ✅ Yes | ⚠️ Limited |
| Safe for testnet/mainnet | ❌ No | ✅ Yes | ✅ Yes |

### Key Takeaways

1. **Default devnet deployments** should use `--features devnet-safe`
2. **Never deploy** a `dev-unsafe` build to any network
3. **If you see `[DEV-UNSAFE]` warnings** in your logs, you have the wrong build for network deployment
4. **Setting `EEZO_DEV_ALLOW_UNSIGNED_TX=1`** on a devnet-safe build will:
   - Log a loud warning at startup
   - Have **no effect** on transaction processing
   - Unsigned transactions will still be rejected

---

## T78.9: Official Devnet Profile (devnet-safe + dag-primary)

T78.9 locks in `devnet-safe + dag-primary + dag-ordering-enabled` as the **official devnet profile**, while clearly separating it from the local-only `dev-unsafe` profile.

### Profiles Summary

| Profile | Use Case | Unsigned TX? | Default Consensus | DAG Ordering |
|---------|----------|-------------|-------------------|--------------|
| **devnet-safe** (Official) | Devnet deployments | ❌ Never | dag-primary | true |
| **dev-unsafe** | Local TPS benchmarks | ✅ With env var | configurable | configurable |
| **generic** | CI/general builds | ❌ Never | hotstuff | false |

### Official Devnet Profile: devnet-safe

This is the **recommended profile for all devnet deployments**. It provides:

- **DAG-primary consensus** as default (when `EEZO_CONSENSUS_MODE` is unset)
- **DAG ordering enabled** by default (when `EEZO_DAG_ORDERING_ENABLED` is unset)
- **No unsigned transaction support** (even if `EEZO_DEV_ALLOW_UNSIGNED_TX=1` is set)
- Shadow HotStuff checker available with `hotstuff-shadow` feature
- STM executor and DAG consensus included

**Build Command (devnet-safe):**
```bash
# Option 1: Using the devnet-safe meta-feature (recommended)
cargo build --release -p eezo-node \
  --features "devnet-safe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"

# Option 2: With HotStuff shadow checker for additional observability
cargo build --release -p eezo-node --features "devnet-safe,hotstuff-shadow"
```

**Run Command (devnet-safe):**
```bash
# Use the official launcher script
./scripts/devnet_dag_primary.sh

# Or run directly (minimal config needed - defaults are correct)
./target/release/eezo-node --genesis genesis.min.json --datadir /tmp/eezo-devnet
```

### Local-Only Benchmark Profile: dev-unsafe

This profile is for **local TPS testing and development benchmarks only**. It should **NEVER** be deployed to any network.

**Build Command (dev-unsafe):**
```bash
# Build with dev-unsafe feature for local benchmarking
cargo build -p eezo-node \
  --features "dev-unsafe,metrics,pq44-runtime,checkpoints,stm-exec,dag-consensus"
```

**Run Command (dev-unsafe):**
```bash
# Enable unsigned tx for spam testing
export EEZO_DEV_ALLOW_UNSIGNED_TX=1
export EEZO_CONSENSUS_MODE=dag-primary
export EEZO_DAG_ORDERING_ENABLED=1
./target/debug/eezo-node --genesis genesis.min.json --datadir /tmp/eezo-bench
```

**Warning Signs**: If you see `[DEV-UNSAFE]` warnings in your logs, you have a dev-unsafe build. This is correct for local benchmarks but **wrong for network deployments**.

### Quick Reference: Which Profile to Use?

| Scenario | Profile | Build Features |
|----------|---------|----------------|
| Official devnet deployment | **devnet-safe** | `devnet-safe,metrics,...` |
| Local TPS benchmark (unsigned tx) | **dev-unsafe** | `dev-unsafe,metrics,...` |
| CI/testing (signed tx only) | **generic** | `pq44-runtime,metrics,...` |
| Testnet/Mainnet (future) | **devnet-safe** or custom | No dev-unsafe |

### T78.9 Environment Variable Defaults

When running with the devnet-safe feature:

| Variable | Devnet-Safe Default | Dev-Unsafe Default |
|----------|--------------------|--------------------|
| `EEZO_CONSENSUS_MODE` | `dag-primary` | (unset = hotstuff) |
| `EEZO_DAG_ORDERING_ENABLED` | `true` | `false` |
| `EEZO_DEV_ALLOW_UNSIGNED_TX` | **No effect** | Works when `=1` |

### Official Devnet Run Commands

**Start a fresh devnet-safe DAG-primary node:**
```bash
./scripts/devnet_dag_primary.sh
```

**Test with transactions (requires funded account):**
```bash
# Terminal 2: Generate keys and fund account
./target/release/ml_dsa_keygen
export EEZO_TX_FROM=0x<your_address>
curl -X POST http://127.0.0.1:8080/faucet \
  -H "Content-Type: application/json" \
  -d '{"to":"'$EEZO_TX_FROM'","amount":"1000000000000"}'
```

**Run canary SLO check:**
```bash
# Terminal 3: Check metrics and SLOs
./scripts/t78_dag_primary_canary_check.sh http://127.0.0.1:9898/metrics --tps-window=5
```

**Expected metrics for devnet-safe:**
- `eezo_consensus_mode_active = 3` (dag-primary)
- `eezo_dag_primary_shadow_checks_total > 0` and increasing
- `eezo_dag_primary_shadow_mismatch_total = 0`
- No `[DEV-UNSAFE]` warnings in node logs