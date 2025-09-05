pub mod consensus;
pub mod consensus_sig;
pub mod cert_store;
pub mod evidence;
pub mod tx;
pub mod mempool;
pub mod verify_cache;
pub mod config;

pub use config::{VerifyConfig, BatchVerifyCfg};
pub use verify_cache::VerifyCache;

// Re-export for benches / external callers
pub use consensus::validate_consensus_batch;

#[cfg(feature = "metrics")]
pub mod metrics;

#[cfg(not(feature = "metrics"))]
pub mod metrics_shim;

// When metrics feature is off, expose a unified `metrics` via the shim
#[cfg(not(feature = "metrics"))]
pub use self::metrics_shim as metrics;

#[cfg(feature = "pq44-runtime")]
pub mod pq44_runtime;
