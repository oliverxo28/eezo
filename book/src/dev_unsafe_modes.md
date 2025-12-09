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
[T78.7] EEZO_DEV_ALLOW_UNSIGNED_TX is set but dev-unsafe feature is NOT compiled.
[T78.7] The env var has NO EFFECT in this build. Unsigned txs will be REJECTED.
```