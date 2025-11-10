use once_cell::sync::Lazy;
use std::collections::HashSet;
use parking_lot::Mutex;

/// number of shards (power-of-two works well) used for cheap contention-free replay checks
pub const REPLAY_SHARD_COUNT: usize = 64;

pub struct ShardedReplay {
    shards: Vec<Mutex<HashSet<u64>>>,
}

pub struct ShardHandle<'a> {
    set: &'a Mutex<HashSet<u64>>,
}

impl ShardedReplay {
    /// construct with a specific number of shards
    pub fn new(count: usize) -> Self {
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            v.push(Mutex::new(HashSet::new()));
        }
        ShardedReplay { shards: v }
    }

    /// pick a shard based on the ticket_id
    pub fn shard(&self, ticket_id: &u64) -> ShardHandle<'_> {
        let idx = (*ticket_id as usize) % self.shards.len();
        ShardHandle { set: &self.shards[idx] }
    }
}

impl<'a> ShardHandle<'a> {
    pub fn seen(&self, ticket_id: &u64) -> bool {
        let guard = self.set.lock();
        guard.contains(ticket_id)
    }

    pub fn insert(&self, ticket_id: u64) {
        let mut guard = self.set.lock();
        guard.insert(ticket_id);
    }

    /// Atomically check if `ticket_id` was seen; if not, insert it.
    /// Returns `true` if this call performed the first insert (i.e. **not a replay**),
    /// or `false` if the id was already present (i.e. **replay detected**).
    pub fn insert_if_absent(&self, ticket_id: u64) -> bool {
        let mut guard = self.set.lock();
        if guard.contains(&ticket_id) {
            false
        } else {
            guard.insert(ticket_id);
            true
        }
    }
}

/// process-wide sharded replay filter used by handshake.rs
pub static REPLAY_SHARDS: Lazy<ShardedReplay> =
    Lazy::new(|| ShardedReplay::new(REPLAY_SHARD_COUNT));
