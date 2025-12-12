//! stm_arena.rs — T87.4: Arena-Indexed Account Storage for STM Executor
//!
//! This module provides `AccountArena`, a cache-friendly data structure for
//! efficient account access during block execution. Instead of repeated HashMap
//! lookups by Address, accounts are stored contiguously in a Vec and accessed
//! by index.
//!
//! ## Design Goals
//!
//! 1. **Cache Locality**: All touched accounts are contiguous in memory
//! 2. **O(1) Access**: Vec indexing is faster than HashMap lookup
//! 3. **Determinism**: Same inputs always produce same arena layout
//! 4. **Compatibility**: Can be converted back to BlockWriteSet for persistence
//!
//! ## Usage
//!
//! ```ignore
//! // At block start:
//! let arena = AccountArena::new();
//! 
//! // Ensure all touched accounts are in the arena:
//! let sender_idx = arena.ensure_account(&sender, &base_accounts);
//! let receiver_idx = arena.ensure_account(&receiver, &base_accounts);
//!
//! // During execution:
//! let sender_acc = arena.account(sender_idx);
//! // ... compute new state ...
//! *arena.account_mut(sender_idx) = new_sender;
//!
//! // At block commit:
//! arena.apply_to_accounts(&mut accounts);
//! ```
//!
//! ## Thread Safety
//!
//! `AccountArena` is NOT thread-safe. In the STM executor, each wave creates
//! a snapshot of the arena for speculative execution, then applies committed
//! changes sequentially.

use std::collections::HashMap;
use crate::{Account, Accounts, Address, Supply};

/// Reserved index for tracking fee accumulation (not a real account).
pub const SUPPLY_INDEX: u32 = 0;

/// A contiguous, cache-friendly collection of accounts for a single block.
///
/// All accounts that may be touched during block execution are loaded once
/// at block start. Transactions access accounts by index (u32) rather than
/// by Address, avoiding repeated HashMap lookups in the hot path.
///
/// ## Index Layout
///
/// - Index 0: Reserved for "supply" pseudo-entry (tracks accumulated fees)
/// - Index 1+: Real accounts, in order of first access
///
/// ## Invariants
///
/// - Once an address is assigned an index, that mapping never changes
/// - The Vec may grow during block execution as new accounts are touched
/// - All modifications are local until `apply_to_accounts()` is called
#[derive(Debug, Clone)]
pub struct AccountArena {
    /// Contiguous storage for all touched accounts.
    /// Index 0 is reserved for supply tracking (unused Account slot).
    accounts: Vec<Account>,
    
    /// Maps Address → index in the accounts vector.
    /// Only used during arena construction and for address resolution.
    index_map: HashMap<Address, u32>,
    
    /// Total fees accumulated during block execution.
    /// Applied to Supply at block commit.
    total_fees: u128,
    
    /// Tracks which indices were modified during execution.
    /// Used for efficient write-back to base state.
    modified: Vec<bool>,
}

impl Default for AccountArena {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountArena {
    /// Create a new empty arena.
    ///
    /// The arena starts with a single reserved entry at index 0 for supply tracking.
    pub fn new() -> Self {
        Self {
            // Start with one entry (supply placeholder at index 0)
            accounts: vec![Account::default()],
            index_map: HashMap::new(),
            total_fees: 0,
            modified: vec![false], // Supply slot not modified initially
        }
    }

    /// Create a new arena with pre-allocated capacity.
    ///
    /// Use this when you know approximately how many accounts will be touched.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut accounts = Vec::with_capacity(capacity.saturating_add(1));
        accounts.push(Account::default()); // Supply placeholder
        
        let mut modified = Vec::with_capacity(capacity.saturating_add(1));
        modified.push(false);
        
        Self {
            accounts,
            index_map: HashMap::with_capacity(capacity),
            total_fees: 0,
            modified,
        }
    }

    /// Get the number of accounts in the arena (excluding supply slot).
    #[inline]
    pub fn len(&self) -> usize {
        self.accounts.len().saturating_sub(1)
    }

    /// Check if the arena is empty (no real accounts, only supply slot).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the total fees accumulated in this arena.
    #[inline]
    pub fn total_fees(&self) -> u128 {
        self.total_fees
    }

    /// Record a fee burn (accumulated for later application to Supply).
    #[inline]
    pub fn record_fee(&mut self, fee: u128) {
        self.total_fees = self.total_fees.saturating_add(fee);
    }

    /// Ensure an account exists in the arena, loading from base if needed.
    ///
    /// Returns the index of the account in the arena.
    /// If the account is not yet in the arena, it is loaded from `base` and added.
    pub fn ensure_account(&mut self, addr: &Address, base: &Accounts) -> u32 {
        if let Some(&idx) = self.index_map.get(addr) {
            return idx;
        }
        
        // Load from base state
        let account = base.get(addr);
        let idx = self.accounts.len() as u32;
        
        self.accounts.push(account);
        self.modified.push(false);
        self.index_map.insert(*addr, idx);
        
        idx
    }

    /// Get the index for an address, if it exists in the arena.
    #[inline]
    pub fn index_of(&self, addr: &Address) -> Option<u32> {
        self.index_map.get(addr).copied()
    }

    /// Get a reference to the account at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is out of bounds or is the reserved supply index (0).
    #[inline]
    pub fn account(&self, idx: u32) -> &Account {
        debug_assert!(idx > 0, "Cannot access supply slot as account");
        &self.accounts[idx as usize]
    }

    /// Get a mutable reference to the account at the given index.
    ///
    /// This also marks the account as modified for efficient write-back.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is out of bounds or is the reserved supply index (0).
    #[inline]
    pub fn account_mut(&mut self, idx: u32) -> &mut Account {
        debug_assert!(idx > 0, "Cannot modify supply slot as account");
        let idx_usize = idx as usize;
        self.modified[idx_usize] = true;
        &mut self.accounts[idx_usize]
    }

    /// Set an account at the given index, marking it as modified.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is out of bounds or is the reserved supply index (0).
    #[inline]
    pub fn set_account(&mut self, idx: u32, account: Account) {
        debug_assert!(idx > 0, "Cannot set supply slot as account");
        let idx_usize = idx as usize;
        self.accounts[idx_usize] = account;
        self.modified[idx_usize] = true;
    }

    /// Get the address for a given index, if any.
    ///
    /// This is O(n) and should only be used for debugging/testing.
    pub fn address_of(&self, idx: u32) -> Option<Address> {
        for (&addr, &i) in &self.index_map {
            if i == idx {
                return Some(addr);
            }
        }
        None
    }

    /// Apply all modified accounts back to the base state and update supply.
    ///
    /// This is called at block commit to persist the arena changes.
    pub fn apply_to_state(&self, accounts: &mut Accounts, supply: &mut Supply) {
        // Apply modified accounts
        for (&addr, &idx) in &self.index_map {
            let idx_usize = idx as usize;
            if self.modified[idx_usize] {
                accounts.put(addr, self.accounts[idx_usize].clone());
            }
        }
        
        // Apply accumulated fees
        if self.total_fees > 0 {
            supply.apply_burn(self.total_fees);
        }
    }

    /// Export modified accounts as an iterator of (Address, Account) pairs.
    ///
    /// Useful for generating a BlockWriteSet or delta.
    pub fn modified_accounts(&self) -> impl Iterator<Item = (Address, &Account)> + '_ {
        self.index_map.iter().filter_map(|(&addr, &idx)| {
            let idx_usize = idx as usize;
            if self.modified[idx_usize] {
                Some((addr, &self.accounts[idx_usize]))
            } else {
                None
            }
        })
    }

    /// Get the count of modified accounts.
    pub fn modified_count(&self) -> usize {
        // Skip index 0 (supply slot)
        self.modified.iter().skip(1).filter(|&&m| m).count()
    }

    /// Clone the arena for speculative execution.
    ///
    /// This creates a snapshot that can be used for parallel speculative execution.
    /// The clone shares the index_map by cloning it, which is acceptable since
    /// indices are stable once assigned.
    pub fn snapshot(&self) -> Self {
        Self {
            accounts: self.accounts.clone(),
            index_map: self.index_map.clone(),
            total_fees: self.total_fees,
            modified: self.modified.clone(),
        }
    }

    /// Merge speculative results back into this arena.
    ///
    /// For each modified account in `speculative`, copy its state to this arena.
    /// This is used after a speculative execution wave completes successfully.
    ///
    /// # Panics
    ///
    /// Panics if `speculative` has a different index layout (should never happen
    /// if derived from this arena via `snapshot()`).
    pub fn merge_speculative(&mut self, speculative: &AccountArena) {
        debug_assert_eq!(
            self.accounts.len(),
            speculative.accounts.len(),
            "Arena size mismatch during merge"
        );
        
        for (idx, &is_modified) in speculative.modified.iter().enumerate() {
            if is_modified && idx > 0 {
                self.accounts[idx] = speculative.accounts[idx].clone();
                self.modified[idx] = true;
            }
        }
        
        self.total_fees = speculative.total_fees;
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_address(byte: u8) -> Address {
        Address([byte; 20])
    }

    fn make_account(balance: u128, nonce: u64) -> Account {
        Account { balance, nonce }
    }

    #[test]
    fn test_arena_new_empty() {
        let arena = AccountArena::new();
        assert!(arena.is_empty());
        assert_eq!(arena.len(), 0);
        assert_eq!(arena.total_fees(), 0);
    }

    #[test]
    fn test_arena_with_capacity() {
        let arena = AccountArena::with_capacity(100);
        assert!(arena.is_empty());
        assert!(arena.accounts.capacity() >= 101); // +1 for supply slot
    }

    #[test]
    fn test_arena_ensure_account_loads_from_base() {
        let addr = make_address(0x42);
        let mut base = Accounts::default();
        base.put(addr, make_account(1000, 5));

        let mut arena = AccountArena::new();
        let idx = arena.ensure_account(&addr, &base);

        assert_eq!(idx, 1); // First real account after supply slot
        assert_eq!(arena.len(), 1);

        let acc = arena.account(idx);
        assert_eq!(acc.balance, 1000);
        assert_eq!(acc.nonce, 5);
    }

    #[test]
    fn test_arena_ensure_account_returns_cached_index() {
        let addr = make_address(0x42);
        let base = Accounts::default();

        let mut arena = AccountArena::new();
        let idx1 = arena.ensure_account(&addr, &base);
        let idx2 = arena.ensure_account(&addr, &base);

        assert_eq!(idx1, idx2);
        assert_eq!(arena.len(), 1);
    }

    #[test]
    fn test_arena_multiple_accounts() {
        let addr1 = make_address(0x01);
        let addr2 = make_address(0x02);
        let addr3 = make_address(0x03);
        let base = Accounts::default();

        let mut arena = AccountArena::new();
        let idx1 = arena.ensure_account(&addr1, &base);
        let idx2 = arena.ensure_account(&addr2, &base);
        let idx3 = arena.ensure_account(&addr3, &base);

        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
        assert_eq!(idx3, 3);
        assert_eq!(arena.len(), 3);
    }

    #[test]
    fn test_arena_index_of() {
        let addr = make_address(0x42);
        let base = Accounts::default();

        let mut arena = AccountArena::new();
        
        // Before ensure
        assert!(arena.index_of(&addr).is_none());
        
        let idx = arena.ensure_account(&addr, &base);
        
        // After ensure
        assert_eq!(arena.index_of(&addr), Some(idx));
    }

    #[test]
    fn test_arena_account_mut_marks_modified() {
        let addr = make_address(0x42);
        let base = Accounts::default();

        let mut arena = AccountArena::new();
        let idx = arena.ensure_account(&addr, &base);

        assert_eq!(arena.modified_count(), 0);

        // Modify account
        let acc = arena.account_mut(idx);
        acc.balance = 999;

        assert_eq!(arena.modified_count(), 1);
    }

    #[test]
    fn test_arena_set_account_marks_modified() {
        let addr = make_address(0x42);
        let base = Accounts::default();

        let mut arena = AccountArena::new();
        let idx = arena.ensure_account(&addr, &base);

        assert_eq!(arena.modified_count(), 0);

        arena.set_account(idx, make_account(500, 1));

        assert_eq!(arena.modified_count(), 1);
        assert_eq!(arena.account(idx).balance, 500);
    }

    #[test]
    fn test_arena_record_fee() {
        let mut arena = AccountArena::new();

        arena.record_fee(10);
        arena.record_fee(25);
        arena.record_fee(5);

        assert_eq!(arena.total_fees(), 40);
    }

    #[test]
    fn test_arena_apply_to_state() {
        let addr1 = make_address(0x01);
        let addr2 = make_address(0x02);

        let mut base = Accounts::default();
        base.put(addr1, make_account(1000, 0));
        base.put(addr2, make_account(500, 0));

        let mut arena = AccountArena::new();
        let idx1 = arena.ensure_account(&addr1, &base);
        let idx2 = arena.ensure_account(&addr2, &base);

        // Modify addr1, leave addr2 unchanged
        arena.account_mut(idx1).balance = 800;
        arena.record_fee(10);

        // Apply to state
        let mut accounts = Accounts::default();
        let mut supply = Supply::default();
        arena.apply_to_state(&mut accounts, &mut supply);

        // Check addr1 was updated
        let acc1 = accounts.get(&addr1);
        assert_eq!(acc1.balance, 800);

        // Check addr2 was NOT updated (unmodified in arena)
        // Since we applied to empty accounts, addr2 won't exist
        assert_eq!(arena.modified_count(), 1);

        // Check supply was updated
        assert_eq!(supply.burn_total, 10);
    }

    #[test]
    fn test_arena_modified_accounts_iterator() {
        let addr1 = make_address(0x01);
        let addr2 = make_address(0x02);
        let base = Accounts::default();

        let mut arena = AccountArena::new();
        let idx1 = arena.ensure_account(&addr1, &base);
        let _idx2 = arena.ensure_account(&addr2, &base);

        // Only modify addr1
        arena.account_mut(idx1).balance = 999;

        let modified: Vec<_> = arena.modified_accounts().collect();
        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].0, addr1);
        assert_eq!(modified[0].1.balance, 999);
    }

    #[test]
    fn test_arena_snapshot_and_merge() {
        let addr = make_address(0x42);
        let base = Accounts::default();

        let mut arena = AccountArena::new();
        let idx = arena.ensure_account(&addr, &base);
        arena.set_account(idx, make_account(1000, 0));

        // Take snapshot for speculative execution
        let mut spec = arena.snapshot();
        
        // Modify in speculative copy
        spec.account_mut(idx).balance = 800;
        spec.record_fee(10);

        // Original unchanged
        assert_eq!(arena.account(idx).balance, 1000);
        assert_eq!(arena.total_fees(), 0);

        // Merge speculative changes
        arena.merge_speculative(&spec);

        // Now original reflects changes
        assert_eq!(arena.account(idx).balance, 800);
        assert_eq!(arena.total_fees(), 10);
    }

    #[test]
    fn test_arena_address_of() {
        let addr = make_address(0x42);
        let base = Accounts::default();

        let mut arena = AccountArena::new();
        let idx = arena.ensure_account(&addr, &base);

        assert_eq!(arena.address_of(idx), Some(addr));
        assert_eq!(arena.address_of(999), None);
    }

    #[test]
    fn test_arena_deterministic_index_assignment() {
        // Same sequence of ensures should produce same indices
        let addrs: Vec<Address> = (0..10).map(|i| make_address(i)).collect();
        let base = Accounts::default();

        let mut arena1 = AccountArena::new();
        let mut arena2 = AccountArena::new();

        for addr in &addrs {
            arena1.ensure_account(addr, &base);
            arena2.ensure_account(addr, &base);
        }

        for addr in &addrs {
            assert_eq!(arena1.index_of(addr), arena2.index_of(addr));
        }
    }
}
