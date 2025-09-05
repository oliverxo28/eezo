pub mod consensus;
pub mod consensus_sig;
pub mod cert_store;
pub mod evidence;
pub mod tx;
pub mod mempool;
pub mod verify_cache; // Add this line
pub mod config;

pub use config::{VerifyConfig, BatchVerifyCfg};
pub use verify_cache::VerifyCache; // Add this line

#[cfg(feature = "metrics")]
pub mod metrics;

#[cfg(not(feature = "metrics"))]
pub mod metrics_shim;

// Re-export a unified `metrics` only when the real metrics module is NOT built.
#[cfg(not(feature = "metrics"))]
pub use self::metrics_shim as metrics;

#[cfg(feature = "pq44-runtime")]
pub mod pq44_runtime;