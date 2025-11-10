use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct VerifyConfig {
    pub parallel_verify: bool,      // gate rayon path at runtime
    pub batch_size_hint: usize,     // upstream uses this to decide when to flush
    pub sig_lru_size: usize,        // placeholder for future cache
    pub rate_limit_per_peer: usize, // placeholder for token-bucket
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            parallel_verify: true,
            batch_size_hint: 256,
            sig_lru_size: 4096,
            rate_limit_per_peer: 1000,
        }
    }
}

// Add BatchVerifyCfg for T5.1
#[derive(Clone, Debug)]
pub struct BatchVerifyCfg {
    pub threshold: usize,      // batch kicks in at/after this size
    pub parallel: bool,        // uses Rayon if compiled with the feature
    pub max_batch: usize,      // chunk very large groups
    pub cache_enabled: bool,   // T5.3 (ignored in T5.1)
    pub cache_capacity: usize, // T5.3 (ignored in T5.1)
}

impl Default for BatchVerifyCfg {
    fn default() -> Self {
        Self {
            threshold: 64,
            parallel: true,
            max_batch: 4096,
            cache_enabled: true,
            cache_capacity: 100_000,
        }
    }
}

/// Hard cap for total EEZO supply (native + bridged - burns)
#[derive(Clone, Copy, Debug)]
pub struct SupplyCapCfg {
    pub hard_cap: u128, // e.g., 1_000_000_000 * 10u128.pow(9) (if 9 decimals)
}

impl Default for SupplyCapCfg {
    fn default() -> Self {
        Self {
            hard_cap: 1_000_000_000_000_000_000u128,
        } // placeholder; tune later
    }
}

/// Simple fee config (we’ll firm this up in T6.3)
#[derive(Clone, Copy, Debug)]
pub struct FeeCfg {
    pub flat_fee: u128, // flat fee in the smallest unit; refine later
}

impl Default for FeeCfg {
    fn default() -> Self {
        Self {
            flat_fee: 1_000u128,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PersistenceCfg {
    pub db_path: PathBuf,
    pub snapshot_interval: u64,
    pub enable_compression: bool,
    pub cache_size_mb: usize,
}

impl Default for PersistenceCfg {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("./data/eezo-db"),
            snapshot_interval: 1000,
            enable_compression: true,
            cache_size_mb: 128,
        }
    }
}
