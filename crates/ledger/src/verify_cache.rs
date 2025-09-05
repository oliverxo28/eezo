use lru::LruCache;
use parking_lot::RwLock;
use std::num::NonZeroUsize;

pub struct VerifyCache {
    inner: RwLock<LruCache<Vec<u8>, bool>>,
}

impl VerifyCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self { inner: RwLock::new(LruCache::new(cap)) }
    }

    #[inline]
    pub fn get(&self, key: &[u8]) -> Option<bool> {
        self.inner.read().peek(key).copied()
    }

    #[inline]
    pub fn put(&self, key: Vec<u8>, val: bool) {
        self.inner.write().put(key, val);
    }
}
