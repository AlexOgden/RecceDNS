use dashmap::DashMap;
use rand::RngExt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::DEFAULT_DNS_PORT;

/// Default resolver used as fallback when all resolvers are disabled.
pub const DEFAULT_RESOLVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(
    Ipv4Addr::new(1, 1, 1, 1),
    DEFAULT_DNS_PORT,
));

/// Cleanup disabled resolvers every N selections (must be power of 2 - 1 for fast modulo).
const CLEANUP_INTERVAL_MASK: u64 = 0x3FF; // Every 1024 selects

#[derive(Debug)]
pub struct ResolverPool {
    resolvers: Vec<SocketAddr>,
    disabled: DashMap<SocketAddr, Instant>,
    index: AtomicUsize,
    select_count: AtomicU64,
    use_random: bool,
}

impl ResolverPool {
    #[must_use]
    pub fn new(resolvers: Vec<SocketAddr>, use_random: bool) -> Self {
        Self {
            resolvers,
            disabled: DashMap::new(),
            index: AtomicUsize::new(0),
            select_count: AtomicU64::new(0),
            use_random,
        }
    }

    /// Select a resolver.
    ///
    /// Returns `Some(resolver)` if one is available, or `None` if the pool is empty.
    /// If all resolvers are temporarily disabled, returns the first resolver as fallback.
    #[inline]
    pub fn select(&self) -> Option<SocketAddr> {
        if self.resolvers.is_empty() {
            return None;
        }

        // Periodic cleanup (every ~1024 selects)
        let count = self.select_count.fetch_add(1, Ordering::Relaxed);
        if count & CLEANUP_INTERVAL_MASK == 0 {
            self.cleanup_expired();
        }

        let len = self.resolvers.len();

        if self.use_random {
            self.select_random(len)
        } else {
            self.select_sequential(len)
        }
    }

    #[inline]
    fn select_sequential(&self, len: usize) -> Option<SocketAddr> {
        // Try each resolver starting from current index
        for _ in 0..len {
            // Atomic increment with wrap-around
            let idx = self.index.fetch_add(1, Ordering::Relaxed) % len;
            let resolver = self.resolvers[idx];

            if !self.is_disabled(resolver) {
                return Some(resolver);
            }
        }

        // All disabled - return first as fallback
        self.fallback()
    }

    #[inline]
    fn select_random(&self, len: usize) -> Option<SocketAddr> {
        let mut rng = rand::rng();
        let start = rng.random_range(0..len);

        // Try from random start, then scan linearly if needed
        for i in 0..len {
            let idx = (start + i) % len;
            let resolver = self.resolvers[idx];

            if !self.is_disabled(resolver) {
                return Some(resolver);
            }
        }

        self.fallback()
    }

    #[inline]
    fn is_disabled(&self, resolver: SocketAddr) -> bool {
        self.disabled
            .get(&resolver)
            .is_some_and(|expiry| *expiry > Instant::now())
    }

    #[inline]
    fn fallback(&self) -> Option<SocketAddr> {
        self.resolvers.first().copied()
    }

    /// Temporarily disable a resolver for the specified duration.
    ///
    /// Will not disable if it would leave no resolvers available.
    pub fn disable(&self, resolver: SocketAddr, duration: Duration) {
        // Don't disable the last available resolver
        let other_available = self
            .resolvers
            .iter()
            .any(|r| *r != resolver && !self.is_disabled(*r));

        if other_available {
            self.disabled.insert(resolver, Instant::now() + duration);
        }
    }

    fn cleanup_expired(&self) {
        let now = Instant::now();
        self.disabled.retain(|_, expiry| *expiry > now);
    }

    #[must_use]
    #[cfg(test)]
    pub fn available_count(&self) -> usize {
        self.resolvers
            .iter()
            .filter(|r| !self.is_disabled(**r))
            .count()
    }

    #[must_use]
    #[cfg(test)]
    pub const fn total_count(&self) -> usize {
        self.resolvers.len()
    }

    #[must_use]
    #[cfg(test)]
    pub const fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

impl Clone for ResolverPool {
    fn clone(&self) -> Self {
        Self {
            resolvers: self.resolvers.clone(),
            disabled: self.disabled.clone(),
            index: AtomicUsize::new(self.index.load(Ordering::Relaxed)),
            select_count: AtomicU64::new(self.select_count.load(Ordering::Relaxed)),
            use_random: self.use_random,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_resolvers() -> Vec<SocketAddr> {
        vec![
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 1),
                DEFAULT_DNS_PORT,
            )),
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(8, 8, 8, 8),
                DEFAULT_DNS_PORT,
            )),
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(9, 9, 9, 9),
                DEFAULT_DNS_PORT,
            )),
        ]
    }

    fn resolver(ip: &str) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(ip.parse().unwrap(), DEFAULT_DNS_PORT))
    }

    #[test]
    fn test_new_pool() {
        let pool = ResolverPool::new(test_resolvers(), false);
        assert_eq!(pool.total_count(), 3);
        assert_eq!(pool.available_count(), 3);
        assert!(!pool.is_empty());
    }

    #[test]
    fn test_empty_pool() {
        let pool = ResolverPool::new(vec![], false);
        assert!(pool.is_empty());
        assert_eq!(pool.select(), None);
    }

    #[test]
    fn test_sequential_selection() {
        let pool = ResolverPool::new(test_resolvers(), false);

        assert_eq!(pool.select(), Some(resolver("1.1.1.1")));
        assert_eq!(pool.select(), Some(resolver("8.8.8.8")));
        assert_eq!(pool.select(), Some(resolver("9.9.9.9")));
        assert_eq!(pool.select(), Some(resolver("1.1.1.1"))); // Cycles back
    }

    #[test]
    fn test_random_selection() {
        let pool = ResolverPool::new(test_resolvers(), true);

        // Should return one of the resolvers
        let result = pool.select();
        assert!(result.is_some());
        assert!(test_resolvers().contains(&result.unwrap()));
    }

    #[test]
    fn test_disable_resolver() {
        let pool = ResolverPool::new(test_resolvers(), false);

        // Disable first resolver
        pool.disable(resolver("1.1.1.1"), Duration::from_secs(10));

        // Should skip to second resolver
        assert_eq!(pool.select(), Some(resolver("8.8.8.8")));
        assert_eq!(pool.available_count(), 2);
    }

    #[test]
    fn test_disable_expiry() {
        let pool = ResolverPool::new(test_resolvers(), false);

        // Disable with very short duration
        pool.disable(resolver("1.1.1.1"), Duration::from_millis(10));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));

        // Trigger cleanup
        for _ in 0..1025 {
            let _ = pool.select();
        }

        // Should be available again
        assert_eq!(pool.available_count(), 3);
    }

    #[test]
    fn test_cannot_disable_all() {
        let resolvers = vec![resolver("1.1.1.1"), resolver("8.8.8.8")];
        let pool = ResolverPool::new(resolvers, false);

        pool.disable(resolver("1.1.1.1"), Duration::from_secs(10));
        pool.disable(resolver("8.8.8.8"), Duration::from_secs(10));

        // At least one should still be available (second disable should fail)
        assert!(pool.available_count() >= 1);
        assert!(pool.select().is_some());
    }

    #[test]
    fn test_fallback_when_all_disabled() {
        let resolvers = vec![resolver("1.1.1.1")];
        let pool = ResolverPool::new(resolvers, false);

        // Can't disable the only resolver
        pool.disable(resolver("1.1.1.1"), Duration::from_secs(10));

        // Should still return the resolver as fallback
        assert_eq!(pool.select(), Some(resolver("1.1.1.1")));
    }

    #[test]
    fn test_clone() {
        let pool = ResolverPool::new(test_resolvers(), false);
        let _ = pool.select(); // Advance index

        let cloned = pool.clone();
        assert_eq!(cloned.total_count(), pool.total_count());
    }

    #[test]
    fn test_concurrent_selection() {
        use std::sync::Arc;
        use std::thread;

        let pool = Arc::new(ResolverPool::new(test_resolvers(), false));
        let mut handles = vec![];

        // Spawn multiple threads selecting concurrently
        for _ in 0..10 {
            let pool_clone = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let result = pool_clone.select();
                    assert!(result.is_some());
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
