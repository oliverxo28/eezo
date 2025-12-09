# T78.8: Devnet-Safe Profile & Guardrails — Summary

This document summarizes the changes implemented for T78.8.

## Overview

T78.8 enhances the devnet-safe build profile with clear guardrails and documentation to ensure developers cannot accidentally run "unsafe" behavior on what they think is a devnet-safe build.

## What Changed

### Code Changes

1. **`crates/ledger/src/dev_unsafe.rs`**
   - Added `env_var_unsigned_tx_is_set()` function to detect if the env var is set (regardless of feature)
   - Added `should_warn_unsigned_tx_env_var_ignored()` function for safe build guardrails
   - Added `build_profile_name()` function for startup logging
   - Enhanced `log_startup_warning()` to always log the build profile
   - Updated T78.8 tests for new guardrail functions

2. **`crates/ledger/Cargo.toml`**
   - Added `devnet-safe` feature for build profile detection

3. **`crates/node/Cargo.toml`**
   - Updated `devnet-safe` feature to forward to `eezo-ledger/devnet-safe`

### Documentation Changes

1. **`book/src/dev_unsafe_modes.md`**
   - Added comprehensive **Build Profiles Matrix** (T78.8 section)
   - Updated warning log examples to reflect new T78.8 messages
   - Added build commands and verification steps

2. **`book/src/t78_dag_only_devnet.md`**
   - Added T78.8 section describing new features
   - Added reference to the profiles matrix

## Build Commands

### Devnet-Safe Build (Recommended for Devnet Deployments)

```bash
# Option 1: Using the devnet-safe meta-feature (recommended)
cargo build --release -p eezo-node --features "devnet-safe"

# Option 2: With explicit features
cargo build --release -p eezo-node \
  --features "pq44-runtime,persistence,checkpoints,metrics,stm-exec,dag-consensus,devnet-safe"

# Option 3: With HotStuff shadow checker
cargo build --release -p eezo-node --features "devnet-safe,hotstuff-shadow"
```

### Dev-Unsafe Build (Local TPS Benchmarks Only)

```bash
cargo build -p eezo-node \
  --features "pq44-runtime,persistence,checkpoints,metrics,stm-exec,dag-consensus,dev-unsafe"
```

## Verification

### 1. Check Build Profile at Startup

```bash
# Devnet-safe build
./target/release/eezo-node 2>&1 | grep "T78.8"
# Expected:
# [T78.8] Build profile: devnet-safe
# [T78.8] Safe build profile active. Unsigned transactions are disabled.
```

### 2. Verify Consensus Mode Defaults (devnet-safe)

```bash
# No env vars needed - defaults to dag-primary
curl -s http://localhost:3030/metrics | grep eezo_consensus_mode_active
# Expected: eezo_consensus_mode_active 3  (3 = dag-primary)
```

### 3. Verify Env Var Warning (devnet-safe)

```bash
# Set the env var on a devnet-safe build
EEZO_DEV_ALLOW_UNSIGNED_TX=1 ./target/release/eezo-node 2>&1 | grep "T78.8"
# Expected:
# [T78.8] EEZO_DEV_ALLOW_UNSIGNED_TX is set but this is a SAFE BUILD.
# [T78.8] The env var has NO EFFECT. Unsigned txs will be REJECTED.
```

### 4. Run Unit Tests

```bash
# Test dev_unsafe module
cargo test -p eezo-ledger --features "pq44-runtime,checkpoints" -- dev_unsafe

# Test with devnet-safe feature
cargo test -p eezo-ledger --features "pq44-runtime,checkpoints,devnet-safe" -- dev_unsafe

# Test consensus mode parsing (node tests)
cargo test -p eezo-node --features "pq44-runtime,checkpoints,metrics,devnet-safe" -- consensus_mode_tests
```

## Behavior Summary

| Build Profile | `EEZO_DEV_ALLOW_UNSIGNED_TX=1` Set | Unsigned TX Allowed? | Startup Message |
|---------------|-----------------------------------|---------------------|-----------------|
| devnet-safe | No | ❌ No | `Safe build profile active` |
| devnet-safe | Yes | ❌ No | `EEZO_DEV_ALLOW_UNSIGNED_TX is set but this is a SAFE BUILD` |
| dev-unsafe | No | ❌ No | `[DEV-UNSAFE] This build has dev-unsafe mode ENABLED` |
| dev-unsafe | Yes | ✅ Yes | `[DEV-UNSAFE] Unsigned transactions WILL BE ACCEPTED` |

## Test Adjustments

No existing tests from T78.7 needed adjustment. New tests added:

- `test_env_var_unsigned_tx_is_set` - tests env var detection
- `test_should_warn_unsigned_tx_env_var_ignored_safe_build` - tests guardrail in safe builds
- `test_should_warn_unsigned_tx_env_var_ignored_dev_unsafe_build` - tests guardrail in unsafe builds
- `test_build_profile_name` - tests build profile name detection
- `test_devnet_safe_unsigned_tx_never_allowed` - critical security test for devnet-safe

## Key Takeaways

1. **Devnet-safe is the default devnet build**: Use `--features devnet-safe` for day-to-day devnet deployments
2. **Strong guardrails**: Setting `EEZO_DEV_ALLOW_UNSIGNED_TX=1` on a devnet-safe build logs a loud warning but has no effect
3. **Clear startup logging**: The build profile is always logged at startup for clarity
4. **No regressions**: All existing T77/T78 SAFE tests continue to pass
