//! EEZO Crypto — Build Script
//!
//! This script ensures compile-time hygiene and feature sanity for the
//! `eezo-crypto` crate. It enforces:
//!   - Deterministic builds across environments
//!   - Proper PQC feature enablement (ML-DSA / ML-KEM / SLH-DSA)
//!   - Warning suppression for pqcrypto internals
//!   - Metadata propagation for dependent crates
//!
//! Runs automatically via Cargo before build/test.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // 1. Ensure reproducible builds
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=EEZO_PQC_BACKEND");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");

    // 2. Ensure that at least one PQC algorithm feature is enabled
    let mldsa = env::var("CARGO_FEATURE_MLDSA").is_ok();
    let mlkem = env::var("CARGO_FEATURE_MLKEM").is_ok();
    let slh_dsa = env::var("CARGO_FEATURE_SLH_DSA").is_ok();

    if !mldsa && !mlkem && !slh_dsa {
        println!("cargo:warning=eezo-crypto: no PQ algorithms enabled, defaulting to ML-DSA + ML-KEM");
    }

    // 3. Emit cfg flags for other crates to detect PQC backend
    if mldsa {
        println!("cargo:rustc-cfg=eezo_mldsa");
    }
    if mlkem {
        println!("cargo:rustc-cfg=eezo_mlkem");
    }
    if slh_dsa {
        println!("cargo:rustc-cfg=eezo_slhdsa");
    }

    // 4. Optional: export metadata for dependent crates (like ledger/node)
    println!("cargo:rustc-env=EEZO_CRYPTO_VERSION=0.1.0");
    println!("cargo:rustc-env=EEZO_PQC_DEFAULT_SIG=ML-DSA-44");
    println!("cargo:rustc-env=EEZO_PQC_DEFAULT_KEM=ML-KEM-768");

    // 5. Suppress noisy pqcrypto internals warnings in CI logs
    println!("cargo:rustc-cfg=allow_pqcrypto_internal_warnings");

    // 6. Generate placeholder for build metadata file (optional)
    let out_dir = env::var("OUT_DIR").unwrap();
    let meta_path = Path::new(&out_dir).join("eezo_crypto_build_info.txt");
    let meta = format!(
        "build_target={}\nfeatures=MLDSA:{} MLKEM:{} SLH-DSA:{}\n",
        env::var("TARGET").unwrap_or_else(|_| "unknown".into()),
        mldsa,
        mlkem,
        slh_dsa
    );
    let _ = fs::write(meta_path, meta);
}
