//! consensus_verify benchmark (temporarily disabled).
//!
//! This stub exists so that:
//!   `cargo clippy -p eezo-ledger --all-targets --all-features`
//! can run cleanly without pulling in an outdated Criterion benchmark
//! that was written against older consensus_sig / cert_store APIs.
//!
//! If we want to restore this benchmark later, we will reimplement it
//! against the current `consensus_sig::verify_batch` and cert-store
//! traits in a dedicated task.

fn main() {
    // no-op: benchmark disabled for now.
}