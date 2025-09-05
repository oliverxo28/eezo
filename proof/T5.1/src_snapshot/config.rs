// crates/ledger/src/config.rs

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