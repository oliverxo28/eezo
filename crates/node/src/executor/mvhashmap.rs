//! executor/mvhashmap.rs — Multi-version hashmap for Block-STM.
//!
//! T73.1: Scaffolding for the MVCC storage layer used by the STM executor.
//! This module provides a minimal multi-version concurrent hashmap that
//! supports speculative reads/writes and version tracking.
//!
//! Full conflict detection and version resolution logic will be added in T73.2+.

use dashmap::DashMap;
use std::hash::Hash;

/// Versioned value in the MVHashMap.
///
/// Each entry is either:
/// - `Committed`: A finalized value at a specific commit version.
/// - `Speculative`: A tentative write by a transaction being executed.
#[derive(Clone, Debug)]
pub enum Versioned<V> {
    /// Finalized value at a specific commit version.
    Committed {
        /// The commit version (typically tx index or block height).
        ver: u64,
        /// The committed value.
        v: V,
    },
    /// Tentative write by a transaction being executed speculatively.
    Speculative {
        /// The tx index that owns this speculative write.
        owner: u32,
        /// The attempt number (for retry tracking).
        attempt: u16,
        /// The speculative value.
        v: V,
    },
}

/// Multi-version hashmap for Block-STM execution.
///
/// This data structure enables optimistic concurrency:
/// - Transactions can speculatively read/write without locking.
/// - Conflicts are detected at commit time.
/// - Deterministic resolution: lower-index tx always wins.
///
/// T73.1: Basic scaffolding. Full conflict detection in T73.2+.
#[derive(Debug)]
pub struct MVHashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    inner: DashMap<K, Versioned<V>>,
}

impl<K, V> Default for MVHashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> MVHashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Create a new empty MVHashMap.
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Read last committed value for a key.
    ///
    /// Returns `None` if the key doesn't exist or only has speculative writes.
    ///
    /// T73.1: Placeholder implementation that ignores snapshot/version constraints.
    /// Full version-aware reads will be implemented in T73.2+.
    pub fn read_committed(&self, k: &K) -> Option<V> {
        self.inner.get(k).and_then(|v| match v.clone() {
            Versioned::Committed { v, .. } => Some(v),
            Versioned::Speculative { .. } => None,
        })
    }

    /// Stage a speculative write for a key.
    ///
    /// The `owner` is the tx index, and `attempt` tracks retry count.
    ///
    /// T73.1: Placeholder implementation. Conflict detection in T73.2+.
    pub fn write_spec(&self, k: K, owner: u32, attempt: u16, v: V) {
        self.inner
            .insert(k, Versioned::Speculative { owner, attempt, v });
    }

    /// Read any value (committed or speculative) for a key.
    ///
    /// Returns `None` if the key doesn't exist.
    ///
    /// T73.1: Placeholder for speculative reads during execution.
    pub fn read_any(&self, k: &K) -> Option<V> {
        self.inner.get(k).map(|v| match v.clone() {
            Versioned::Committed { v, .. } => v,
            Versioned::Speculative { v, .. } => v,
        })
    }

    /// Promote a list of writes to committed at `commit_ver`.
    ///
    /// This finalizes speculative writes after successful validation.
    pub fn commit<I>(&self, writes: I, commit_ver: u64)
    where
        I: IntoIterator<Item = (K, V)>,
    {
        for (k, v) in writes {
            self.inner.insert(k, Versioned::Committed { ver: commit_ver, v });
        }
    }

    /// Clear all entries in the map.
    ///
    /// Used to reset state between blocks.
    pub fn clear(&self) {
        self.inner.clear();
    }

    /// Get the number of entries in the map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mvhashmap_basic() {
        let map: MVHashMap<String, u64> = MVHashMap::new();

        // Write speculative value
        map.write_spec("key1".to_string(), 0, 0, 100);
        assert_eq!(map.read_any(&"key1".to_string()), Some(100));
        assert_eq!(map.read_committed(&"key1".to_string()), None);

        // Commit the value
        map.commit(vec![("key1".to_string(), 100)], 1);
        assert_eq!(map.read_committed(&"key1".to_string()), Some(100));
    }

    #[test]
    fn test_mvhashmap_clear() {
        let map: MVHashMap<String, u64> = MVHashMap::new();
        map.commit(vec![("key1".to_string(), 100)], 1);
        assert!(!map.is_empty());
        map.clear();
        assert!(map.is_empty());
    }
}
