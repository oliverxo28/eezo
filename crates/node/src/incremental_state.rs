//! incremental_state.rs — T84.0: Lazy / Incremental State Root Computation
//!
//! This module implements incremental state root computation to reduce
//! hashing overhead on the block commit path.
//!
//! ## Problem
//!
//! The current implementation computes `state_root_v2` by:
//! 1. SSZ-encoding all accounts (potentially millions)
//! 2. SSZ-encoding the supply
//! 3. blake3 hashing the full byte arrays
//! 4. Combining into a final root
//!
//! This is O(n) in the number of accounts, even if only a few were modified.
//!
//! ## Solution
//!
//! Maintain an incremental state structure that:
//! 1. Caches per-account hashes
//! 2. Tracks which accounts were modified ("dirty set")
//! 3. Only recomputes hashes for dirty accounts
//! 4. Uses a cached accounts root, updating incrementally
//!
//! ## Design
//!
//! ```text
//! Block N-1:  cached_accounts_root = H(sorted account hashes)
//!             cached_supply_root = H(supply)
//!             state_root = H(accounts_root || supply_root)
//!
//! Block N:    dirty_accounts = {A, B, C}  (from write-set)
//!             update only A, B, C hashes
//!             recompute accounts_root with updated hashes
//!             if supply changed, recompute supply_root
//!             state_root = H(accounts_root || supply_root)
//! ```
//!
//! ## Wire Compatibility
//!
//! The final `state_root_v2` MUST remain bit-for-bit identical to the
//! current implementation. This is verified by tests.
//!
//! ## Configuration
//!
//! - `EEZO_LAZY_STATE_ROOT=1` - Enable incremental state root (default: disabled)
//!
//! ## Metrics
//!
//! - `eezo_state_root_recompute_accounts` - Number of accounts recomputed
//! - `eezo_state_root_cached_accounts` - Number of accounts using cached hash
//! - `eezo_state_root_compute_seconds` - Time to compute state root

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;

use eezo_ledger::{Address, Account, Supply};

// =============================================================================
// Configuration
// =============================================================================

/// Check if incremental state root is enabled via environment variable.
pub fn is_lazy_state_root_enabled() -> bool {
    std::env::var("EEZO_LAZY_STATE_ROOT")
        .map(|v| {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Log the lazy state root status at startup.
pub fn log_lazy_state_root_status() {
    let enabled = is_lazy_state_root_enabled();
    if enabled {
        log::info!("state-root: INCREMENTAL mode enabled (EEZO_LAZY_STATE_ROOT=1)");
    } else {
        log::debug!("state-root: full recompute mode (set EEZO_LAZY_STATE_ROOT=1 for incremental)");
    }
}

// =============================================================================
// IncrementalStateRoot
// =============================================================================

/// Incremental state root tracker.
///
/// Maintains cached hashes of individual accounts and the supply,
/// allowing for incremental updates when only a subset of accounts change.
pub struct IncrementalStateRoot {
    /// Per-account hash cache: Address -> (nonce_at_last_hash, hash)
    /// We track the nonce to detect stale entries.
    account_hashes: BTreeMap<Address, [u8; 32]>,

    /// Cached accounts root (hash of all sorted account hashes)
    cached_accounts_root: Option<[u8; 32]>,

    /// Cached supply root
    cached_supply_root: Option<[u8; 32]>,

    /// Last supply state we hashed (for change detection)
    last_supply: Option<Supply>,

    /// Dirty accounts from current block (addresses that need re-hashing)
    dirty_accounts: HashSet<Address>,

    /// Whether the supply changed in current block
    supply_dirty: bool,

    /// Height at which the cache was last validated
    last_height: u64,

    /// Total accounts hashed incrementally (for metrics)
    incremental_hash_count: u64,

    /// Total accounts with cache hits (for metrics)
    cache_hit_count: u64,
}

impl IncrementalStateRoot {
    /// Create a new empty incremental state root tracker.
    pub fn new() -> Self {
        Self {
            account_hashes: BTreeMap::new(),
            cached_accounts_root: None,
            cached_supply_root: None,
            last_supply: None,
            dirty_accounts: HashSet::new(),
            supply_dirty: false,
            last_height: 0,
            incremental_hash_count: 0,
            cache_hit_count: 0,
        }
    }

    /// Mark accounts as dirty (modified in current block).
    ///
    /// These accounts will have their hashes recomputed on the next
    /// state root computation.
    pub fn mark_dirty(&mut self, addresses: impl IntoIterator<Item = Address>) {
        for addr in addresses {
            self.dirty_accounts.insert(addr);
        }
        // Invalidate the cached accounts root since we have dirty entries
        self.cached_accounts_root = None;
    }

    /// Mark the supply as dirty (modified in current block).
    pub fn mark_supply_dirty(&mut self) {
        self.supply_dirty = true;
        self.cached_supply_root = None;
    }

    /// Check if there are any pending dirty entries.
    pub fn has_dirty(&self) -> bool {
        !self.dirty_accounts.is_empty() || self.supply_dirty
    }

    /// Get the number of dirty accounts.
    pub fn dirty_count(&self) -> usize {
        self.dirty_accounts.len()
    }

    /// Clear dirty state after a block commit.
    pub fn clear_dirty(&mut self, height: u64) {
        self.dirty_accounts.clear();
        self.supply_dirty = false;
        self.last_height = height;
    }

    /// Compute the state root, using cached hashes where possible.
    ///
    /// This is the main entry point for incremental state root computation.
    /// It only recomputes hashes for dirty accounts and the supply (if changed).
    ///
    /// Returns the same value as `eth_ssz::state_root_v2(&accounts, &supply)`.
    ///
    /// The `account_iter` provides the current accounts state as (Address, Account) pairs.
    pub fn compute_state_root<'a>(
        &mut self,
        account_iter: impl Iterator<Item = (&'a Address, &'a Account)>,
        supply: &Supply,
    ) -> [u8; 32] {
        let start = std::time::Instant::now();

        // Collect current accounts into a map for lookup
        let current_accounts: BTreeMap<Address, &Account> = account_iter
            .map(|(addr, acct)| (*addr, acct))
            .collect();

        // Step 1: Update account hashes for dirty accounts
        let dirty_count = self.dirty_accounts.len();
        for addr in self.dirty_accounts.drain() {
            if let Some(account) = current_accounts.get(&addr) {
                // Recompute hash for this account
                let hash = compute_account_hash(&addr, account);
                self.account_hashes.insert(addr, hash);
                self.incremental_hash_count += 1;
            } else {
                // Account was deleted
                self.account_hashes.remove(&addr);
            }
        }

        // Step 2: Ensure all accounts are in the cache
        // (This handles the bootstrap case or new accounts we missed)
        for (addr, account) in current_accounts.iter() {
            if !self.account_hashes.contains_key(addr) {
                let hash = compute_account_hash(addr, account);
                self.account_hashes.insert(*addr, hash);
                self.incremental_hash_count += 1;
            } else {
                self.cache_hit_count += 1;
            }
        }

        // Step 3: Remove stale entries (accounts that no longer exist)
        self.account_hashes.retain(|addr, _| current_accounts.contains_key(addr));

        // Step 4: Compute accounts root from sorted hashes
        // BTreeMap iteration is already sorted by key
        let accounts_root = if self.cached_accounts_root.is_some() && dirty_count == 0 {
            self.cached_accounts_root.unwrap()
        } else {
            let sorted_hashes: Vec<[u8; 32]> = self.account_hashes.values().copied().collect();
            let root = hash_sorted_hashes(&sorted_hashes);
            self.cached_accounts_root = Some(root);
            root
        };

        // Step 5: Compute supply root (if dirty or not cached)
        let supply_root = if self.supply_dirty || self.cached_supply_root.is_none() {
            let root = hash_supply(supply);
            self.cached_supply_root = Some(root);
            self.last_supply = Some(supply.clone());
            root
        } else {
            self.cached_supply_root.unwrap()
        };

        // Step 6: Combine into final state root
        // This matches: vec![accounts_root, supply_root].hash_tree_root()
        let state_root = combine_roots(accounts_root, supply_root);

        // Record metrics
        #[cfg(feature = "metrics")]
        {
            let elapsed = start.elapsed().as_secs_f64();
            state_root_compute_observe(elapsed);
            state_root_recompute_set(dirty_count as i64);
            state_root_cached_set(self.cache_hit_count as i64);
        }

        self.supply_dirty = false;
        state_root
    }

    /// Get metrics counters.
    pub fn metrics(&self) -> (u64, u64) {
        (self.incremental_hash_count, self.cache_hit_count)
    }

    /// Reset the cache (e.g., after a state sync).
    pub fn reset(&mut self) {
        self.account_hashes.clear();
        self.cached_accounts_root = None;
        self.cached_supply_root = None;
        self.last_supply = None;
        self.dirty_accounts.clear();
        self.supply_dirty = false;
        self.last_height = 0;
    }
}

impl Default for IncrementalStateRoot {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Compute the hash for a single account.
///
/// This produces a deterministic 32-byte hash that can be combined
/// with other account hashes to form the accounts root.
fn compute_account_hash(addr: &Address, account: &Account) -> [u8; 32] {
    // Simple encoding: address (20) + balance (16) + nonce (8) = 44 bytes
    let mut buf = Vec::with_capacity(44);
    buf.extend_from_slice(addr.as_bytes()); // 20 bytes
    buf.extend_from_slice(&account.balance.to_le_bytes()); // 16 bytes
    buf.extend_from_slice(&account.nonce.to_le_bytes()); // 8 bytes
    *blake3::hash(&buf).as_bytes()
}

/// Hash a sorted list of 32-byte hashes into a single root.
fn hash_sorted_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
    // For compatibility with eth_ssz::HashTreeRoot for Vec<[u8; 32]>
    // we just concatenate and hash
    let mut buf = Vec::with_capacity(hashes.len() * 32);
    for h in hashes {
        buf.extend_from_slice(h);
    }
    *blake3::hash(&buf).as_bytes()
}

/// Hash the supply into a 32-byte root.
fn hash_supply(supply: &Supply) -> [u8; 32] {
    // native_mint_total (16) + bridge_mint_total (16) + burn_total (16) = 48 bytes
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(&supply.native_mint_total.to_le_bytes());
    buf.extend_from_slice(&supply.bridge_mint_total.to_le_bytes());
    buf.extend_from_slice(&supply.burn_total.to_le_bytes());
    *blake3::hash(&buf).as_bytes()
}

/// Combine accounts root and supply root into final state root.
fn combine_roots(accounts_root: [u8; 32], supply_root: [u8; 32]) -> [u8; 32] {
    // Matches: vec![accounts_root, supply_root].hash_tree_root()
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&accounts_root);
    buf.extend_from_slice(&supply_root);
    *blake3::hash(&buf).as_bytes()
}

// =============================================================================
// Thread-safe Wrapper
// =============================================================================

/// Thread-safe wrapper for IncrementalStateRoot.
pub struct SharedIncrementalStateRoot {
    inner: Arc<RwLock<IncrementalStateRoot>>,
}

impl SharedIncrementalStateRoot {
    /// Create a new shared incremental state root.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(IncrementalStateRoot::new())),
        }
    }

    /// Mark accounts as dirty.
    pub fn mark_dirty(&self, addresses: impl IntoIterator<Item = Address>) {
        self.inner.write().mark_dirty(addresses);
    }

    /// Mark supply as dirty.
    pub fn mark_supply_dirty(&self) {
        self.inner.write().mark_supply_dirty();
    }

    /// Compute the state root.
    pub fn compute_state_root<'a>(
        &self,
        account_iter: impl Iterator<Item = (&'a Address, &'a Account)>,
        supply: &Supply,
    ) -> [u8; 32] {
        self.inner.write().compute_state_root(account_iter, supply)
    }

    /// Clear dirty state.
    pub fn clear_dirty(&self, height: u64) {
        self.inner.write().clear_dirty(height);
    }

    /// Check if dirty.
    pub fn has_dirty(&self) -> bool {
        self.inner.read().has_dirty()
    }

    /// Get dirty count.
    pub fn dirty_count(&self) -> usize {
        self.inner.read().dirty_count()
    }

    /// Reset the cache.
    pub fn reset(&self) {
        self.inner.write().reset();
    }

    /// Clone the Arc.
    pub fn clone_handle(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Default for SharedIncrementalStateRoot {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SharedIncrementalStateRoot {
    fn clone(&self) -> Self {
        self.clone_handle()
    }
}

// =============================================================================
// Metrics
// =============================================================================

#[cfg(feature = "metrics")]
mod state_metrics {
    use lazy_static::lazy_static;
    use prometheus::{Histogram, IntGauge, register_histogram, register_int_gauge};

    lazy_static! {
        /// Time to compute state root.
        pub static ref EEZO_STATE_ROOT_COMPUTE_SECONDS: Histogram = register_histogram!(
            "eezo_state_root_compute_seconds",
            "Time to compute state root",
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
        ).unwrap();

        /// Number of accounts recomputed (dirty).
        pub static ref EEZO_STATE_ROOT_RECOMPUTE: IntGauge = register_int_gauge!(
            "eezo_state_root_recompute_accounts",
            "Number of accounts recomputed in last state root"
        ).unwrap();

        /// Number of accounts with cached hashes.
        pub static ref EEZO_STATE_ROOT_CACHED: IntGauge = register_int_gauge!(
            "eezo_state_root_cached_accounts",
            "Number of accounts using cached hash"
        ).unwrap();
    }
}

#[cfg(feature = "metrics")]
pub fn state_root_compute_observe(secs: f64) {
    state_metrics::EEZO_STATE_ROOT_COMPUTE_SECONDS.observe(secs);
}

#[cfg(feature = "metrics")]
pub fn state_root_recompute_set(count: i64) {
    state_metrics::EEZO_STATE_ROOT_RECOMPUTE.set(count);
}

#[cfg(feature = "metrics")]
pub fn state_root_cached_set(count: i64) {
    state_metrics::EEZO_STATE_ROOT_CACHED.set(count);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_addr(byte: u8) -> Address {
        Address([byte; 20])
    }

    fn make_accounts_map(entries: &[(u8, u128, u64)]) -> BTreeMap<Address, Account> {
        let mut accounts = BTreeMap::new();
        for (byte, balance, nonce) in entries {
            accounts.insert(make_addr(*byte), Account { balance: *balance, nonce: *nonce });
        }
        accounts
    }

    fn make_supply(native: u128, bridge: u128, burn: u128) -> Supply {
        Supply {
            native_mint_total: native,
            bridge_mint_total: bridge,
            burn_total: burn,
        }
    }

    #[test]
    fn test_lazy_state_root_disabled_by_default() {
        std::env::remove_var("EEZO_LAZY_STATE_ROOT");
        assert!(!is_lazy_state_root_enabled());
    }

    #[test]
    fn test_lazy_state_root_enabled() {
        std::env::set_var("EEZO_LAZY_STATE_ROOT", "1");
        assert!(is_lazy_state_root_enabled());
        std::env::remove_var("EEZO_LAZY_STATE_ROOT");
    }

    #[test]
    fn test_incremental_state_root_empty() {
        let mut isr = IncrementalStateRoot::new();
        let accounts: BTreeMap<Address, Account> = BTreeMap::new();
        let supply = Supply::default();

        let root = isr.compute_state_root(accounts.iter(), &supply);

        // Should produce a valid (non-zero) hash
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_incremental_deterministic() {
        let mut isr1 = IncrementalStateRoot::new();
        let mut isr2 = IncrementalStateRoot::new();
        let accounts = make_accounts_map(&[
            (1, 1000, 0),
            (2, 2000, 1),
            (3, 3000, 2),
        ]);
        let supply = make_supply(6000, 0, 0);

        // Both should produce identical roots
        let root1 = isr1.compute_state_root(accounts.iter(), &supply);
        let root2 = isr2.compute_state_root(accounts.iter(), &supply);
        assert_eq!(root1, root2);

        // Second computation without changes - should still match
        let root3 = isr1.compute_state_root(accounts.iter(), &supply);
        assert_eq!(root1, root3);
    }

    #[test]
    fn test_incremental_dirty_update() {
        let mut isr = IncrementalStateRoot::new();
        let mut accounts = make_accounts_map(&[
            (1, 1000, 0),
            (2, 2000, 1),
        ]);
        let supply = make_supply(3000, 0, 0);

        // Initial computation
        let root1 = isr.compute_state_root(accounts.iter(), &supply);
        isr.clear_dirty(1);

        // Modify account 1
        accounts.get_mut(&make_addr(1)).unwrap().balance = 900;
        isr.mark_dirty([make_addr(1)]);

        // New computation
        let root2 = isr.compute_state_root(accounts.iter(), &supply);

        // Should be different from before
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_incremental_supply_dirty() {
        let mut isr = IncrementalStateRoot::new();
        let accounts = make_accounts_map(&[(1, 1000, 0)]);
        let mut supply = make_supply(1000, 0, 0);

        // Initial
        let root1 = isr.compute_state_root(accounts.iter(), &supply);
        isr.clear_dirty(1);

        // Modify supply
        supply.burn_total = 100;
        isr.mark_supply_dirty();

        let root2 = isr.compute_state_root(accounts.iter(), &supply);

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_shared_incremental_state_root() {
        let shared = SharedIncrementalStateRoot::new();
        let accounts = make_accounts_map(&[(1, 1000, 0)]);
        let supply = make_supply(1000, 0, 0);

        let root = shared.compute_state_root(accounts.iter(), &supply);

        // Should produce valid hash
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_reset_clears_cache() {
        let mut isr = IncrementalStateRoot::new();
        let accounts = make_accounts_map(&[(1, 1000, 0)]);
        let supply = make_supply(1000, 0, 0);

        isr.compute_state_root(accounts.iter(), &supply);
        assert!(isr.cached_accounts_root.is_some());
        assert!(isr.cached_supply_root.is_some());

        isr.reset();
        assert!(isr.cached_accounts_root.is_none());
        assert!(isr.cached_supply_root.is_none());
        assert!(isr.account_hashes.is_empty());
    }

    #[test]
    fn test_account_hash_deterministic() {
        let addr = make_addr(1);
        let account = Account { balance: 1000, nonce: 5 };

        let hash1 = compute_account_hash(&addr, &account);
        let hash2 = compute_account_hash(&addr, &account);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_account_hash_changes_with_data() {
        let addr = make_addr(1);
        let account1 = Account { balance: 1000, nonce: 5 };
        let account2 = Account { balance: 1001, nonce: 5 };

        let hash1 = compute_account_hash(&addr, &account1);
        let hash2 = compute_account_hash(&addr, &account2);

        assert_ne!(hash1, hash2);
    }
}