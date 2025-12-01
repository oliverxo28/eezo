//! executor/mvhashmap.rs — minimal MVCC storage scaffold for Block-STM.
//! Compiles today; we will flesh out conflict/version logic in the next step.

use dashmap::DashMap;
use std::hash::Hash;

#[derive(Clone, Debug)]
pub enum Versioned<V> {
    Committed { ver: u64, v: V },
    Speculative { owner: u32, attempt: u16, v: V },
}

#[derive(Debug, Default)]
pub struct MVHashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    inner: DashMap<K, Versioned<V>>,
}

impl<K, V> MVHashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub fn new() -> Self { Self { inner: DashMap::new() } }

    /// Read last committed value (placeholder; ignores snapshot for now).
    pub fn read_committed(&self, k: &K) -> Option<V> {
        self.inner.get(k).and_then(|v| match v.clone() {
            Versioned::Committed { v, .. } => Some(v),
            _ => None,
        })
    }

    /// Stage a speculative write (placeholder).
    pub fn write_spec(&self, k: K, owner: u32, attempt: u16, v: V) {
        self.inner.insert(k, Versioned::Speculative { owner, attempt, v });
    }

    /// Promote a list of writes to committed at `commit_ver`.
    pub fn commit<I>(&self, writes: I, commit_ver: u64)
    where
        I: IntoIterator<Item = (K, V)>,
    {
        for (k, v) in writes {
            self.inner.insert(k, Versioned::Committed { ver: commit_ver, v });
        }
    }
}
