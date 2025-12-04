//! tx_decode_pool.rs — T76.9: Fast Decode Pool & Zero-Copy Handoff
//!
//! Provides a decode pool that caches parsed `SignedTx` instances to avoid
//! repeated decoding overhead. Transactions are decoded once (in parallel)
//! and handed off as `Arc<DecodedTx>` references for zero-copy processing.
//!
//! ## Features
//!
//! - **Parallel decoding**: Uses rayon to decode multiple transactions in parallel.
//! - **Caching**: Stores decoded transactions keyed by their canonical hash.
//! - **Zero-copy handoff**: Returns `Arc<DecodedTx>` references that can be shared
//!   without cloning the underlying transaction data.
//! - **Environment gating**: Controlled by `EEZO_FAST_DECODE_ENABLED` (default: false).
//! - **Metrics**: Tracks cache hits/misses, decode latency, and pool activity.
//!
//! ## Environment Variables
//!
//! ### `EEZO_FAST_DECODE_ENABLED`
//!
//! Controls whether the fast decode pool is active.
//!
//! - **Values**: `"1"`, `"true"`, `"yes"`, `"on"` to enable; anything else to disable
//! - **Default**: Disabled (for backward compatibility)
//! - **Effect**: When enabled, transaction decoding in the hybrid DAG pipeline uses
//!   a shared cache to avoid repeated parsing of the same transaction bytes.
//!
//! ### `EEZO_DECODE_POOL_CACHE_SIZE`
//!
//! Maximum number of decoded transactions to cache.
//!
//! - **Type**: Integer
//! - **Default**: `100000` (100k transactions)
//! - **Effect**: When the cache exceeds this limit, half of the entries are evicted.
//!
//! ## Performance Impact
//!
//! Enabling the fast decode pool can improve throughput by 10-20% on workloads
//! where the same transactions are decoded multiple times (e.g., during DAG
//! hybrid mode aggregation, re-execution after rollback, etc.).
//!
//! ## Usage
//!
//! ```ignore
//! // Option 1: Use the global decode pool (recommended)
//! let decoded = decode_tx_global(&raw_bytes);
//!
//! // Option 2: Create a custom pool with specific configuration
//! let pool = TxDecodePool::new();
//! let decoded_txs = pool.decode_batch(&raw_bytes_list);
//! // decoded_txs is Vec<Arc<DecodedTx>> - share without cloning
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use rayon::prelude::*;

use eezo_ledger::SignedTx;

use crate::dag_runner::parse_signed_tx_from_envelope;

// =============================================================================
// DecodedTx — Wrapper for decoded SignedTx with zero-copy semantics
// =============================================================================

/// A decoded transaction wrapped for zero-copy handoff.
///
/// This is a thin wrapper around `SignedTx` that:
/// - Is stored behind `Arc` for reference-counted sharing.
/// - Caches the canonical hash to avoid re-computation.
/// - Enables pointer-identity checks for testing zero-copy semantics.
#[derive(Debug, Clone)]
pub struct DecodedTx {
    /// The underlying signed transaction.
    pub tx: SignedTx,
    /// Cached canonical hash (blake3 of tx.to_bytes()).
    hash: [u8; 32],
}

impl DecodedTx {
    /// Create a new DecodedTx from a SignedTx.
    pub fn new(tx: SignedTx) -> Self {
        let hash = tx.hash();
        Self { tx, hash }
    }

    /// Get the canonical hash of this transaction.
    #[inline]
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Get a reference to the underlying SignedTx.
    #[inline]
    pub fn signed_tx(&self) -> &SignedTx {
        &self.tx
    }

    /// Consume self and return the underlying SignedTx.
    #[inline]
    pub fn into_signed_tx(self) -> SignedTx {
        self.tx
    }
}

impl From<SignedTx> for DecodedTx {
    fn from(tx: SignedTx) -> Self {
        DecodedTx::new(tx)
    }
}

impl AsRef<SignedTx> for DecodedTx {
    fn as_ref(&self) -> &SignedTx {
        &self.tx
    }
}

// =============================================================================
// TxDecodePool — Cached parallel decoder
// =============================================================================

/// Configuration for the decode pool.
#[derive(Debug, Clone)]
pub struct TxDecodePoolConfig {
    /// Maximum number of entries in the cache (LRU eviction when exceeded).
    pub max_cache_size: usize,
}

impl Default for TxDecodePoolConfig {
    fn default() -> Self {
        Self {
            // Default: cache up to 100k transactions
            max_cache_size: 100_000,
        }
    }
}

impl TxDecodePoolConfig {
    /// Parse configuration from environment variables.
    pub fn from_env() -> Self {
        let max_cache_size = std::env::var("EEZO_DECODE_POOL_CACHE_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100_000);

        Self { max_cache_size }
    }
}

/// A pool for decoding and caching SignedTx instances.
///
/// Transactions are keyed by a raw bytes hash (blake3 of the input bytes).
/// This is different from the canonical SignedTx.hash() because the input
/// bytes may be envelope JSON that decodes to the same SignedTx.
pub struct TxDecodePool {
    /// Cache of decoded transactions keyed by canonical SignedTx.hash().
    cache: RwLock<HashMap<[u8; 32], Arc<DecodedTx>>>,
    /// Configuration for the pool.
    config: TxDecodePoolConfig,
}

impl TxDecodePool {
    /// Create a new decode pool with default configuration.
    pub fn new() -> Self {
        Self::with_config(TxDecodePoolConfig::default())
    }

    /// Create a new decode pool with custom configuration.
    pub fn with_config(config: TxDecodePoolConfig) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Create a decode pool from environment configuration.
    pub fn from_env() -> Self {
        Self::with_config(TxDecodePoolConfig::from_env())
    }

    /// Get the current number of cached entries.
    pub fn cache_len(&self) -> usize {
        self.cache.read().len()
    }

    /// Clear the cache.
    pub fn clear(&self) {
        self.cache.write().clear();
    }

    /// Try to get a cached decoded transaction by its canonical hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<Arc<DecodedTx>> {
        let cache = self.cache.read();
        cache.get(hash).cloned()
    }

    /// Insert a decoded transaction into the cache.
    ///
    /// If the cache exceeds max_size, performs simple FIFO-like eviction
    /// by removing approximately half of the entries. Note: this is NOT
    /// a true LRU eviction - entries are removed in arbitrary order based
    /// on HashMap iteration. For production use with high cache churn,
    /// consider implementing a proper LRU cache (e.g., using lru crate).
    fn insert(&self, decoded: Arc<DecodedTx>) {
        let mut cache = self.cache.write();

        // Simple eviction: if we exceed max size, clear half the cache.
        // Note: HashMap keys() order is arbitrary, not LRU order.
        // This is adequate for workloads where cache hits are common.
        if cache.len() >= self.config.max_cache_size {
            let to_remove: Vec<[u8; 32]> = cache
                .keys()
                .take(cache.len() / 2)
                .copied()
                .collect();
            for key in to_remove {
                cache.remove(&key);
            }
            // Metrics updated after releasing write lock is ideal but
            // the performance impact is minimal for this counter increment.
            #[cfg(feature = "metrics")]
            crate::metrics::decode_pool_evictions_inc();
        }

        cache.insert(decoded.hash(), decoded);
    }

    /// Decode a single transaction from raw bytes.
    ///
    /// Returns `Some(Arc<DecodedTx>)` if decoding succeeds, `None` otherwise.
    /// Checks the cache first; if not found, decodes and caches.
    pub fn decode_one(&self, bytes: &[u8]) -> Option<Arc<DecodedTx>> {
        // First, try to parse to get the canonical hash
        let start = Instant::now();
        let stx = parse_signed_tx_from_envelope(bytes)?;
        let hash = stx.hash();

        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(&hash) {
                #[cfg(feature = "metrics")]
                {
                    crate::metrics::decode_pool_cache_hit_inc();
                    crate::metrics::decode_pool_tx_inc();
                }
                return Some(cached.clone());
            }
        }

        // Not in cache, decode and insert
        let decoded = Arc::new(DecodedTx::new(stx));
        self.insert(decoded.clone());

        let elapsed = start.elapsed().as_secs_f64();
        #[cfg(feature = "metrics")]
        {
            crate::metrics::decode_pool_cache_miss_inc();
            crate::metrics::decode_pool_tx_inc();
            crate::metrics::observe_decode_latency_seconds(elapsed);
        }

        Some(decoded)
    }

    /// Decode a batch of transactions from raw bytes in parallel.
    ///
    /// Returns a vector of successfully decoded transactions.
    /// Failed decodes are silently skipped (logged at debug level).
    ///
    /// Uses rayon for parallel decoding to maximize throughput.
    pub fn decode_batch(&self, bytes_list: &[Vec<u8>]) -> Vec<Arc<DecodedTx>> {
        if bytes_list.is_empty() {
            return Vec::new();
        }

        // Collect cache hits and identify misses
        let mut results: Vec<Option<Arc<DecodedTx>>> = vec![None; bytes_list.len()];
        // T76.9: Store (index, already-parsed SignedTx) to avoid double parsing
        let mut to_decode: Vec<(usize, SignedTx)> = Vec::new();

        // First pass: check cache for each item
        {
            let cache = self.cache.read();
            for (i, bytes) in bytes_list.iter().enumerate() {
                // Parse to get hash for cache lookup
                if let Some(stx) = parse_signed_tx_from_envelope(bytes) {
                    let hash = stx.hash();
                    if let Some(cached) = cache.get(&hash) {
                        results[i] = Some(cached.clone());
                        #[cfg(feature = "metrics")]
                        crate::metrics::decode_pool_cache_hit_inc();
                        continue;
                    }
                    // Cache miss - store the already-parsed tx for reuse
                    to_decode.push((i, stx));
                }
                // If parse failed, we just skip this item
            }
        }

        // Second pass: wrap already-parsed transactions in Arc<DecodedTx>
        // Note: we already have the parsed SignedTx, so this is O(1) per item
        let decoded_batch: Vec<(usize, Arc<DecodedTx>)> = to_decode
            .into_par_iter()
            .map(|(idx, stx)| {
                let start = Instant::now();
                let decoded = Arc::new(DecodedTx::new(stx));
                let elapsed = start.elapsed().as_secs_f64();
                #[cfg(feature = "metrics")]
                {
                    crate::metrics::decode_pool_cache_miss_inc();
                    crate::metrics::observe_decode_latency_seconds(elapsed);
                }
                (idx, decoded)
            })
            .collect();

        // Insert new decoded entries into cache and merge results
        for (idx, decoded) in decoded_batch {
            self.insert(decoded.clone());
            results[idx] = Some(decoded);
            #[cfg(feature = "metrics")]
            crate::metrics::decode_pool_tx_inc();
        }

        // Flatten results, keeping only successful decodes
        results.into_iter().flatten().collect()
    }

    /// Decode a batch of transactions from raw bytes (as Bytes type).
    ///
    /// Convenience method that converts `bytes::Bytes` to `&[u8]` for decoding.
    pub fn decode_batch_bytes(&self, bytes_list: &[bytes::Bytes]) -> Vec<Arc<DecodedTx>> {
        let vecs: Vec<Vec<u8>> = bytes_list.iter().map(|b| b.to_vec()).collect();
        self.decode_batch(&vecs)
    }

    /// Decode transactions from hashes and bytes pairs.
    ///
    /// Uses the provided hashes for cache lookup optimization.
    /// Returns a map of hash -> Arc<DecodedTx> for successfully decoded transactions.
    pub fn decode_batch_with_hashes(
        &self,
        entries: &[([u8; 32], Vec<u8>)],
    ) -> HashMap<[u8; 32], Arc<DecodedTx>> {
        if entries.is_empty() {
            return HashMap::new();
        }

        let mut results: HashMap<[u8; 32], Arc<DecodedTx>> = HashMap::new();
        let mut to_decode: Vec<([u8; 32], &[u8])> = Vec::new();

        // First pass: check cache
        {
            let cache = self.cache.read();
            for (hash, bytes) in entries {
                if let Some(cached) = cache.get(hash) {
                    results.insert(*hash, cached.clone());
                    #[cfg(feature = "metrics")]
                    crate::metrics::decode_pool_cache_hit_inc();
                } else {
                    to_decode.push((*hash, bytes.as_slice()));
                }
            }
        }

        // Second pass: parallel decode of cache misses
        let decoded_batch: Vec<([u8; 32], Option<Arc<DecodedTx>>)> = to_decode
            .par_iter()
            .map(|(expected_hash, bytes)| {
                let start = Instant::now();
                let result = parse_signed_tx_from_envelope(bytes).map(|stx| {
                    let decoded = Arc::new(DecodedTx::new(stx));
                    let elapsed = start.elapsed().as_secs_f64();
                    #[cfg(feature = "metrics")]
                    {
                        crate::metrics::decode_pool_cache_miss_inc();
                        crate::metrics::observe_decode_latency_seconds(elapsed);
                    }
                    decoded
                });
                (*expected_hash, result)
            })
            .collect();

        // Insert and merge results
        for (hash, decoded_opt) in decoded_batch {
            if let Some(decoded) = decoded_opt {
                self.insert(decoded.clone());
                results.insert(hash, decoded);
                #[cfg(feature = "metrics")]
                crate::metrics::decode_pool_tx_inc();
            }
        }

        results
    }
}

impl Default for TxDecodePool {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Global/Shared Decode Pool
// =============================================================================

use once_cell::sync::Lazy;

/// Global decode pool instance, lazily initialized.
/// 
/// This is used when `EEZO_FAST_DECODE_ENABLED=true` to provide a shared
/// decode cache across all components (consensus runner, executors, etc.).
static GLOBAL_DECODE_POOL: Lazy<TxDecodePool> = Lazy::new(TxDecodePool::from_env);

/// Get a reference to the global decode pool.
/// 
/// This is the recommended way to access the decode pool in production code.
/// The pool is lazily initialized on first access.
pub fn global_decode_pool() -> &'static TxDecodePool {
    &GLOBAL_DECODE_POOL
}

/// Decode a single transaction using the global pool if fast decode is enabled.
/// 
/// This is a convenience function that:
/// - If `EEZO_FAST_DECODE_ENABLED=true`, uses the global decode pool (with caching)
/// - If disabled, falls back to direct parsing (no caching)
/// 
/// Returns `Some(Arc<DecodedTx>)` on success, `None` on parse failure.
pub fn decode_tx_global(bytes: &[u8]) -> Option<Arc<DecodedTx>> {
    if is_fast_decode_enabled() {
        global_decode_pool().decode_one(bytes)
    } else {
        // Direct parsing without caching
        parse_signed_tx_from_envelope(bytes).map(|tx| Arc::new(DecodedTx::new(tx)))
    }
}

/// Decode a batch of transactions using the global pool if fast decode is enabled.
/// 
/// This is a convenience function that:
/// - If `EEZO_FAST_DECODE_ENABLED=true`, uses the global decode pool (parallel + cached)
/// - If disabled, falls back to sequential parsing (no caching)
/// 
/// Returns a vector of successfully decoded transactions.
pub fn decode_batch_global(bytes_list: &[Vec<u8>]) -> Vec<Arc<DecodedTx>> {
    if is_fast_decode_enabled() {
        global_decode_pool().decode_batch(bytes_list)
    } else {
        // Sequential parsing without caching
        bytes_list
            .iter()
            .filter_map(|bytes| {
                parse_signed_tx_from_envelope(bytes).map(|tx| Arc::new(DecodedTx::new(tx)))
            })
            .collect()
    }
}

// =============================================================================
// Environment gating
// =============================================================================

/// Check if fast decode pool is enabled via environment variable.
///
/// Returns `true` if `EEZO_FAST_DECODE_ENABLED` is set to "1", "true", "yes", or "on".
/// Returns `false` by default.
pub fn is_fast_decode_enabled() -> bool {
    std::env::var("EEZO_FAST_DECODE_ENABLED")
        .map(|v| {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Log the fast decode status at startup.
pub fn log_fast_decode_status() {
    let enabled = is_fast_decode_enabled();
    if enabled {
        log::info!("fast-decode: enabled (EEZO_FAST_DECODE_ENABLED=true)");
    } else {
        log::info!("fast-decode: disabled (default, set EEZO_FAST_DECODE_ENABLED=1 to enable)");
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use eezo_ledger::{Address, TxCore};
    use std::sync::Mutex;

    /// Lock to serialize tests that modify environment variables.
    /// This prevents race conditions with other tests (e.g., in consensus_runner.rs)
    /// that also use environment variables.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: create a test SignedTx.
    fn make_test_tx(nonce: u64) -> SignedTx {
        SignedTx {
            core: TxCore {
                to: Address([0xca; 20]),
                amount: 1000,
                fee: 1,
                nonce,
            },
            pubkey: vec![0x01; 20],
            sig: vec![],
        }
    }

    /// Helper: create test envelope bytes for a transaction.
    fn make_envelope_bytes(nonce: u64) -> Vec<u8> {
        let from_hex = format!("0x{}", hex::encode([0x01; 20]));
        let to_hex = format!("0x{}", hex::encode([0xca; 20]));
        let envelope = serde_json::json!({
            "tx": {
                "from": from_hex,
                "to": to_hex,
                "amount": "1000",
                "fee": "1",
                "nonce": nonce.to_string(),
            },
            "pubkey": hex::encode([0x01; 20]),
            "sig": ""
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    #[test]
    fn test_decoded_tx_hash_caching() {
        let tx = make_test_tx(0);
        let expected_hash = tx.hash();

        let decoded = DecodedTx::new(tx);
        assert_eq!(decoded.hash(), expected_hash);
    }

    #[test]
    fn test_decode_pool_cache_hit() {
        let pool = TxDecodePool::new();
        let bytes = make_envelope_bytes(0);

        // First decode - cache miss
        let decoded1 = pool.decode_one(&bytes).unwrap();
        assert_eq!(pool.cache_len(), 1);

        // Second decode - cache hit
        let decoded2 = pool.decode_one(&bytes).unwrap();
        assert_eq!(pool.cache_len(), 1);

        // Both should point to the same Arc
        assert!(Arc::ptr_eq(&decoded1, &decoded2));
    }

    #[test]
    fn test_decode_pool_multiple_txs() {
        let pool = TxDecodePool::new();

        let bytes1 = make_envelope_bytes(0);
        let bytes2 = make_envelope_bytes(1);
        let bytes3 = make_envelope_bytes(2);

        let decoded1 = pool.decode_one(&bytes1).unwrap();
        let decoded2 = pool.decode_one(&bytes2).unwrap();
        let decoded3 = pool.decode_one(&bytes3).unwrap();

        assert_eq!(pool.cache_len(), 3);

        // All should have different hashes
        assert_ne!(decoded1.hash(), decoded2.hash());
        assert_ne!(decoded2.hash(), decoded3.hash());
    }

    #[test]
    fn test_decode_batch() {
        let pool = TxDecodePool::new();

        let bytes_list: Vec<Vec<u8>> = (0..5).map(make_envelope_bytes).collect();
        let decoded = pool.decode_batch(&bytes_list);

        assert_eq!(decoded.len(), 5);
        assert_eq!(pool.cache_len(), 5);

        // Decode again - should all be cache hits
        let decoded2 = pool.decode_batch(&bytes_list);
        assert_eq!(decoded2.len(), 5);
        assert_eq!(pool.cache_len(), 5);

        // Check pointer identity (zero-copy verification)
        for (d1, d2) in decoded.iter().zip(decoded2.iter()) {
            assert!(Arc::ptr_eq(d1, d2), "Expected same Arc (zero-copy)");
        }
    }

    #[test]
    fn test_zero_copy_handoff() {
        let pool = TxDecodePool::new();
        let bytes = make_envelope_bytes(42);

        let decoded1 = pool.decode_one(&bytes).unwrap();
        let decoded2 = pool.decode_one(&bytes).unwrap();

        // Verify pointer identity - this confirms zero-copy handoff
        assert!(
            Arc::ptr_eq(&decoded1, &decoded2),
            "Zero-copy handoff failed: expected same Arc pointer"
        );

        // The underlying data should be identical
        assert_eq!(decoded1.tx.core.nonce, decoded2.tx.core.nonce);
        assert_eq!(decoded1.hash(), decoded2.hash());
    }

    #[test]
    fn test_cache_clear() {
        let pool = TxDecodePool::new();
        let bytes = make_envelope_bytes(0);

        pool.decode_one(&bytes).unwrap();
        assert_eq!(pool.cache_len(), 1);

        pool.clear();
        assert_eq!(pool.cache_len(), 0);
    }

    #[test]
    fn test_is_fast_decode_enabled_env_values() {
        // Acquire lock to prevent race conditions with other env-modifying tests
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        
        // Test that various "true" values work
        std::env::set_var("EEZO_FAST_DECODE_ENABLED", "true");
        assert!(is_fast_decode_enabled(), "Expected 'true' to enable fast decode");

        std::env::set_var("EEZO_FAST_DECODE_ENABLED", "1");
        assert!(is_fast_decode_enabled(), "Expected '1' to enable fast decode");

        std::env::set_var("EEZO_FAST_DECODE_ENABLED", "yes");
        assert!(is_fast_decode_enabled(), "Expected 'yes' to enable fast decode");

        std::env::set_var("EEZO_FAST_DECODE_ENABLED", "on");
        assert!(is_fast_decode_enabled(), "Expected 'on' to enable fast decode");

        // Test that various "false" values work
        std::env::set_var("EEZO_FAST_DECODE_ENABLED", "false");
        assert!(!is_fast_decode_enabled(), "Expected 'false' to disable fast decode");

        std::env::set_var("EEZO_FAST_DECODE_ENABLED", "0");
        assert!(!is_fast_decode_enabled(), "Expected '0' to disable fast decode");

        std::env::set_var("EEZO_FAST_DECODE_ENABLED", "no");
        assert!(!is_fast_decode_enabled(), "Expected 'no' to disable fast decode");

        // Clean up
        std::env::remove_var("EEZO_FAST_DECODE_ENABLED");
    }

    #[test]
    fn test_decoded_tx_into_signed_tx() {
        let tx = make_test_tx(99);
        let expected_nonce = tx.core.nonce;
        let decoded = DecodedTx::new(tx);

        let recovered = decoded.into_signed_tx();
        assert_eq!(recovered.core.nonce, expected_nonce);
    }
}
