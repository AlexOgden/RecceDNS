use rand::RngExt;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::DEFAULT_DNS_PORT;

/// Default resolver used as fallback when all resolvers are disabled.
pub const DEFAULT_RESOLVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(
    Ipv4Addr::new(1, 1, 1, 1),
    DEFAULT_DNS_PORT,
));

/// Stack-allocated buffer that dynamically spills to heap if capacity exceeds `N`.
/// Avoids heap allocations on hot paths for pools with <= `N` resolvers.
#[derive(Debug)]
struct SmallList<T, const N: usize> {
    inline: [T; N],
    inline_len: usize,
    heap: Vec<T>,
}

impl<T: Copy + Default, const N: usize> SmallList<T, N> {
    fn with_capacity(capacity: usize) -> Self {
        if capacity <= N {
            Self {
                inline: [T::default(); N],
                inline_len: 0,
                heap: Vec::new(),
            }
        } else {
            Self {
                inline: [T::default(); N],
                inline_len: 0,
                heap: Vec::with_capacity(capacity),
            }
        }
    }

    fn push(&mut self, item: T) {
        if self.heap.capacity() == 0 {
            if self.inline_len < N {
                self.inline[self.inline_len] = item;
                self.inline_len += 1;
            } else {
                let mut heap = Vec::with_capacity(N.saturating_mul(2));
                heap.extend_from_slice(&self.inline[..self.inline_len]);
                heap.push(item);
                self.heap = heap;
            }
        } else {
            self.heap.push(item);
        }
    }

    fn as_slice(&self) -> &[T] {
        if self.heap.capacity() == 0 {
            &self.inline[..self.inline_len]
        } else {
            self.heap.as_slice()
        }
    }

    const fn len(&self) -> usize {
        if self.heap.capacity() == 0 {
            self.inline_len
        } else {
            self.heap.len()
        }
    }

    const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn clear(&mut self) {
        self.inline_len = 0;
        self.heap.clear();
    }
}

#[derive(Debug)]
pub struct ResolverEntry {
    pub addr: SocketAddr,
    pub ewma_success_permille: AtomicU32,
    pub in_flight: AtomicUsize,
    pub max_in_flight: AtomicUsize,
    pub ewma_latency_us: AtomicU64,
    pub successes: AtomicU64,
    pub failures: AtomicU64,
    pub consecutive_failures: AtomicUsize,
    pub cooldown_count: AtomicUsize,
    pub disabled_until_ms: AtomicU64,
    pub current_weight: AtomicI64,
    pub last_dispatch_us: AtomicU64,
    pub in_flight_semaphore: Arc<tokio::sync::Semaphore>,
}

impl ResolverEntry {
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            ewma_success_permille: AtomicU32::new(1000),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(ResolverPool::DEFAULT_MAX_IN_FLIGHT),
            ewma_latency_us: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            consecutive_failures: AtomicUsize::new(0),
            cooldown_count: AtomicUsize::new(0),
            disabled_until_ms: AtomicU64::new(0),
            current_weight: AtomicI64::new(0),
            last_dispatch_us: AtomicU64::new(0),
            in_flight_semaphore: Arc::new(tokio::sync::Semaphore::new(
                ResolverPool::DEFAULT_MAX_IN_FLIGHT,
            )),
        }
    }

    #[inline]
    #[must_use]
    pub fn is_disabled(&self, now_ms: u64) -> bool {
        self.disabled_until_ms.load(Ordering::Relaxed) > now_ms
    }

    #[inline]
    #[must_use]
    pub fn is_saturated(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed) >= self.max_in_flight.load(Ordering::Relaxed)
    }

    pub fn disable(&self, until_ms: u64) {
        self.disabled_until_ms.store(until_ms, Ordering::Relaxed);
        self.current_weight.store(0, Ordering::Relaxed);
    }

    #[must_use]
    pub fn calculate_weight(&self) -> u64 {
        let ewma_us = self.ewma_latency_us.load(Ordering::Relaxed);
        let latency_ms = if ewma_us == 0 {
            50
        } else {
            (ewma_us / 1000).clamp(2, 2000)
        };

        let success_permille = u64::from(
            self.ewma_success_permille
                .load(Ordering::Relaxed)
                .clamp(50, 1000),
        );
        (success_permille / latency_ms).clamp(1, 100)
    }

    #[must_use]
    pub fn rto(&self) -> Duration {
        let micros = self.ewma_latency_us.load(Ordering::Relaxed);
        if micros == 0 {
            Duration::from_millis(800)
        } else {
            let millis = micros / 1000;
            let rto_ms = (millis * 3).clamp(250, 1500);
            Duration::from_millis(rto_ms)
        }
    }

    pub fn record_success(&self, latency: Duration) {
        self.successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.cooldown_count.store(0, Ordering::Relaxed);

        let lat_us = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        let _ = self
            .ewma_latency_us
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                Some(if cur == 0 {
                    lat_us
                } else {
                    cur.saturating_mul(7).saturating_add(lat_us) / 8
                })
            });

        let _ =
            self.ewma_success_permille
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                    Some((cur * 9 + 1000) / 10)
                });
    }

    pub fn record_failure(&self, threshold: usize) -> Option<usize> {
        self.failures.fetch_add(1, Ordering::Relaxed);

        let _ =
            self.ewma_success_permille
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                    Some((cur * 9) / 10)
                });

        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= threshold {
            self.consecutive_failures.store(0, Ordering::Relaxed);
            Some(self.cooldown_count.fetch_add(1, Ordering::Relaxed))
        } else {
            None
        }
    }

    pub fn schedule_pacing(&self, now_us: u64, interval_us: u64) -> u64 {
        let mut current = self.last_dispatch_us.load(Ordering::Relaxed);
        loop {
            let scheduled = current.max(now_us);
            let next = scheduled.saturating_add(interval_us);
            match self.last_dispatch_us.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return scheduled,
                Err(actual) => current = actual,
            }
        }
    }
}

/// RAII guard representing an in-flight query permit on a resolver.
#[derive(Debug)]
pub struct ResolverPermit {
    entry: Arc<ResolverEntry>,
    _semaphore_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl ResolverPermit {
    fn new(entry: Arc<ResolverEntry>, permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        entry.in_flight.fetch_add(1, Ordering::Relaxed);
        Self {
            entry,
            _semaphore_permit: Some(permit),
        }
    }
}

impl Drop for ResolverPermit {
    fn drop(&mut self) {
        self.entry.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct ResolverPoolInner {
    entries: Box<[Arc<ResolverEntry>]>,
    addr_to_index: HashMap<SocketAddr, usize>,
    resolvers: Vec<SocketAddr>,
    select_count: AtomicU64,
    use_random: bool,
    start_instant: Instant,
}

#[derive(Clone, Debug)]
pub struct ResolverPool {
    inner: Arc<ResolverPoolInner>,
}

impl ResolverPool {
    pub const FAILURE_THRESHOLD: usize = 3;
    pub const BASE_COOLDOWN: Duration = Duration::from_secs(2);
    pub const MAX_COOLDOWN: Duration = Duration::from_secs(60);
    pub const DEFAULT_MAX_IN_FLIGHT: usize = 32;

    #[must_use]
    pub fn new(resolvers: Vec<SocketAddr>, use_random: bool) -> Self {
        let mut entries = Vec::with_capacity(resolvers.len());
        let mut addr_to_index = HashMap::with_capacity(resolvers.len());

        for (idx, &addr) in resolvers.iter().enumerate() {
            entries.push(Arc::new(ResolverEntry::new(addr)));
            addr_to_index.entry(addr).or_insert(idx);
        }

        Self {
            inner: Arc::new(ResolverPoolInner {
                entries: entries.into_boxed_slice(),
                addr_to_index,
                resolvers,
                select_count: AtomicU64::new(0),
                use_random,
                start_instant: Instant::now(),
            }),
        }
    }

    #[inline]
    fn elapsed_millis(&self) -> u64 {
        u64::try_from(self.inner.start_instant.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    #[inline]
    fn elapsed_micros(&self) -> u64 {
        u64::try_from(self.inner.start_instant.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    #[inline]
    fn find_entry(&self, resolver: SocketAddr) -> Option<&Arc<ResolverEntry>> {
        self.inner
            .addr_to_index
            .get(&resolver)
            .and_then(|&idx| self.inner.entries.get(idx))
    }

    /// Select a resolver favoring low-latency and high-success responsive resolvers.
    #[inline]
    #[must_use]
    pub fn select(&self) -> Option<SocketAddr> {
        self.select_excluding(&[])
    }

    /// Select a resolver excluding specific addresses (useful for in-query retries).
    #[must_use]
    pub fn select_excluding(&self, excluded: &[SocketAddr]) -> Option<SocketAddr> {
        if self.inner.resolvers.is_empty() {
            return None;
        }

        self.inner.select_count.fetch_add(1, Ordering::Relaxed);

        let total = self.inner.entries.len();
        let mut candidates = SmallList::<usize, 16>::with_capacity(total);
        let mut unsaturated = SmallList::<usize, 16>::with_capacity(total);

        let Some(indices) = self.collect_candidates(excluded, &mut candidates, &mut unsaturated)
        else {
            return self.fallback();
        };

        if indices.len() == 1 {
            return Some(self.inner.entries[indices[0]].addr);
        }

        if self.inner.use_random {
            self.weighted_random_select(indices)
        } else {
            self.swrr_select(indices)
        }
    }

    fn collect_candidates<'a>(
        &self,
        excluded: &[SocketAddr],
        candidates: &'a mut SmallList<usize, 16>,
        unsaturated: &'a mut SmallList<usize, 16>,
    ) -> Option<&'a [usize]> {
        let filter_excluded = !excluded.is_empty();
        self.populate_candidates(filter_excluded, excluded, candidates, unsaturated);

        if candidates.is_empty() && filter_excluded {
            self.populate_candidates(false, excluded, candidates, unsaturated);
        }

        if candidates.is_empty() {
            return None;
        }

        if unsaturated.is_empty() {
            Some(candidates.as_slice())
        } else {
            Some(unsaturated.as_slice())
        }
    }

    fn populate_candidates(
        &self,
        filter_excluded: bool,
        excluded: &[SocketAddr],
        candidates: &mut SmallList<usize, 16>,
        unsaturated: &mut SmallList<usize, 16>,
    ) {
        candidates.clear();
        unsaturated.clear();
        let now_ms = self.elapsed_millis();
        for (idx, entry) in self.inner.entries.iter().enumerate() {
            if !entry.is_disabled(now_ms) && (!filter_excluded || !excluded.contains(&entry.addr)) {
                candidates.push(idx);
                if !entry.is_saturated() {
                    unsaturated.push(idx);
                }
            }
        }
    }

    fn swrr_select(&self, candidate_indices: &[usize]) -> Option<SocketAddr> {
        let mut total_weight: i64 = 0;
        let mut best_entry: Option<&Arc<ResolverEntry>> = None;
        let mut max_current_weight = i64::MIN;

        for &idx in candidate_indices {
            let entry = &self.inner.entries[idx];
            let weight = i64::try_from(entry.calculate_weight()).unwrap_or(1);
            total_weight = total_weight.saturating_add(weight);

            let cur = entry.current_weight.fetch_add(weight, Ordering::Relaxed) + weight;
            if cur > max_current_weight {
                max_current_weight = cur;
                best_entry = Some(entry);
            }
        }

        best_entry.map_or_else(
            || self.fallback(),
            |chosen| {
                chosen
                    .current_weight
                    .fetch_sub(total_weight, Ordering::Relaxed);
                Some(chosen.addr)
            },
        )
    }

    fn weighted_random_select(&self, candidate_indices: &[usize]) -> Option<SocketAddr> {
        let mut total_weight: u64 = 0;
        let mut weights = SmallList::<u64, 16>::with_capacity(candidate_indices.len());

        for &idx in candidate_indices {
            let w = self.inner.entries[idx].calculate_weight();
            weights.push(w);
            total_weight = total_weight.saturating_add(w);
        }

        if total_weight == 0 {
            return self.fallback();
        }

        let mut rng = rand::rng();
        let target = rng.random_range(0..total_weight);
        let mut acc = 0u64;

        let weight_slice = weights.as_slice();
        for (i, &idx) in candidate_indices.iter().enumerate() {
            acc = acc.saturating_add(weight_slice[i]);
            if target < acc {
                return Some(self.inner.entries[idx].addr);
            }
        }

        candidate_indices
            .last()
            .map(|&idx| self.inner.entries[idx].addr)
    }

    #[inline]
    #[cfg(test)]
    #[must_use]
    pub fn is_disabled(&self, resolver: SocketAddr) -> bool {
        let now_ms = self.elapsed_millis();
        self.find_entry(resolver)
            .is_some_and(|e| e.is_disabled(now_ms))
    }

    #[inline]
    #[must_use]
    pub fn fallback(&self) -> Option<SocketAddr> {
        self.inner.resolvers.first().copied()
    }

    /// Temporarily disable a resolver for the specified duration.
    /// Will not disable if it would leave no resolvers available.
    pub fn disable(&self, resolver: SocketAddr, duration: Duration) {
        let now_ms = self.elapsed_millis();
        let other_available = self
            .inner
            .entries
            .iter()
            .any(|e| e.addr != resolver && !e.is_disabled(now_ms));

        if other_available && let Some(entry) = self.find_entry(resolver) {
            let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
            entry.disable(now_ms.saturating_add(duration_ms));
        }
    }

    /// Record a successful resolution with measured latency.
    /// Resets consecutive failures and progressive cooldown backoff, and updates EWMA latency and success rate.
    pub fn record_success_with_latency(&self, resolver: SocketAddr, latency: Duration) {
        if let Some(entry) = self.find_entry(resolver) {
            entry.record_success(latency);
        }
    }

    /// Record a successful resolution with a default 20ms baseline latency.
    #[cfg(test)]
    pub fn record_success(&self, resolver: SocketAddr) {
        self.record_success_with_latency(resolver, Duration::from_millis(20));
    }

    /// Record a failure for a resolver.
    /// If consecutive failures reach the threshold, triggers progressive exponential cooldown backoff.
    pub fn record_failure(&self, resolver: SocketAddr) {
        let Some(entry) = self.find_entry(resolver) else {
            return;
        };

        if let Some(streak) = entry.record_failure(Self::FAILURE_THRESHOLD) {
            let shift = u32::try_from(streak).unwrap_or(5).min(5);
            let multiplier = 1u32 << shift;
            let cooldown = (Self::BASE_COOLDOWN * multiplier).min(Self::MAX_COOLDOWN);
            self.disable(resolver, cooldown);
        }
    }

    /// Compute adaptive Retransmission Timeout (RTO) for a resolver based on EWMA latency.
    #[must_use]
    pub fn rto(&self, resolver: SocketAddr) -> Duration {
        self.find_entry(resolver)
            .map_or_else(|| Duration::from_millis(1500), |entry| entry.rto())
    }

    /// Acquire an in-flight permit for the resolver, bounding concurrent queries.
    pub async fn acquire_permit(&self, resolver: SocketAddr) -> Option<ResolverPermit> {
        let entry = self.find_entry(resolver)?;
        let semaphore_permit = entry
            .in_flight_semaphore
            .clone()
            .acquire_owned()
            .await
            .ok()?;
        Some(ResolverPermit::new(entry.clone(), semaphore_permit))
    }

    /// Non-blocking attempt to acquire an in-flight permit for the resolver.
    #[cfg(test)]
    #[must_use]
    pub fn try_acquire_permit(&self, resolver: SocketAddr) -> Option<ResolverPermit> {
        let entry = self.find_entry(resolver)?;
        let semaphore_permit = entry.in_flight_semaphore.clone().try_acquire_owned().ok()?;
        Some(ResolverPermit::new(entry.clone(), semaphore_permit))
    }

    /// Paces queries to the specified resolver ensuring minimum interval between consecutive dispatches.
    pub async fn pace_resolver(&self, resolver: SocketAddr, interval: Duration) {
        if interval.is_zero() {
            return;
        }
        let Some(entry) = self.find_entry(resolver) else {
            return;
        };

        let interval_us = u64::try_from(interval.as_micros()).unwrap_or(u64::MAX);
        let now_us = self.elapsed_micros();
        let scheduled_us = entry.schedule_pacing(now_us, interval_us);

        if scheduled_us > now_us {
            let wait_us = scheduled_us - now_us;
            tokio::time::sleep(Duration::from_micros(wait_us)).await;
        }
    }

    /// Get current in-flight query count for a resolver.
    #[cfg(test)]
    #[must_use]
    pub fn in_flight_count(&self, resolver: SocketAddr) -> usize {
        self.find_entry(resolver)
            .map_or(0, |e| e.in_flight.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    #[must_use]
    pub fn available_count(&self) -> usize {
        let now_ms = self.elapsed_millis();
        self.inner
            .entries
            .iter()
            .filter(|e| !e.is_disabled(now_ms))
            .count()
    }

    #[cfg(test)]
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.inner.resolvers.len()
    }

    #[cfg(test)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.resolvers.is_empty()
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

        let result = pool.select();
        assert!(result.is_some());
        assert!(test_resolvers().contains(&result.unwrap()));
    }

    #[test]
    fn test_disable_resolver() {
        let pool = ResolverPool::new(test_resolvers(), false);

        pool.disable(resolver("1.1.1.1"), Duration::from_secs(10));

        assert_eq!(pool.select(), Some(resolver("8.8.8.8")));
        assert_eq!(pool.available_count(), 2);
    }

    #[test]
    fn test_disable_expiry() {
        let pool = ResolverPool::new(test_resolvers(), false);

        pool.disable(resolver("1.1.1.1"), Duration::from_millis(10));

        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(pool.available_count(), 3);
        assert!(!pool.is_disabled(resolver("1.1.1.1")));
    }

    #[test]
    fn test_cannot_disable_all() {
        let resolvers = vec![resolver("1.1.1.1"), resolver("8.8.8.8")];
        let pool = ResolverPool::new(resolvers, false);

        pool.disable(resolver("1.1.1.1"), Duration::from_secs(10));
        pool.disable(resolver("8.8.8.8"), Duration::from_secs(10));

        assert!(pool.available_count() >= 1);
        assert!(pool.select().is_some());
    }

    #[test]
    fn test_fallback_when_all_disabled() {
        let resolvers = vec![resolver("1.1.1.1")];
        let pool = ResolverPool::new(resolvers, false);

        pool.disable(resolver("1.1.1.1"), Duration::from_secs(10));

        assert_eq!(pool.select(), Some(resolver("1.1.1.1")));
    }

    #[test]
    fn test_clone() {
        let pool = ResolverPool::new(test_resolvers(), false);
        let _ = pool.select();

        let cloned = pool.clone();
        assert_eq!(cloned.total_count(), pool.total_count());
    }

    #[test]
    fn test_concurrent_selection() {
        use std::sync::Arc;
        use std::thread;

        let pool = Arc::new(ResolverPool::new(test_resolvers(), false));
        let mut handles = vec![];

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

    #[test]
    fn test_record_failure_threshold() {
        let pool = ResolverPool::new(test_resolvers(), false);
        let res = resolver("1.1.1.1");

        pool.record_failure(res);
        assert!(!pool.is_disabled(res));
        pool.record_failure(res);
        assert!(!pool.is_disabled(res));

        pool.record_success(res);
        pool.record_failure(res);
        assert!(!pool.is_disabled(res));
        pool.record_failure(res);
        assert!(!pool.is_disabled(res));

        pool.record_failure(res);
        assert!(pool.is_disabled(res));
    }

    #[test]
    fn test_weighted_selection_prefers_lower_latency() {
        let pool = ResolverPool::new(vec![resolver("1.1.1.1"), resolver("8.8.8.8")], false);
        let fast = resolver("1.1.1.1");
        let slow = resolver("8.8.8.8");

        for _ in 0..10 {
            pool.record_success_with_latency(fast, Duration::from_millis(10));
            pool.record_success_with_latency(slow, Duration::from_millis(200));
        }

        let mut fast_count = 0;
        let mut slow_count = 0;
        for _ in 0..100 {
            if pool.select() == Some(fast) {
                fast_count += 1;
            } else {
                slow_count += 1;
            }
        }

        assert!(
            fast_count > slow_count * 2,
            "fast: {fast_count}, slow: {slow_count}"
        );
    }

    #[test]
    fn test_progressive_cooldown_backoff() {
        let pool = ResolverPool::new(vec![resolver("1.1.1.1"), resolver("8.8.8.8")], false);
        let res = resolver("1.1.1.1");

        for _ in 0..3 {
            pool.record_failure(res);
        }
        assert!(pool.is_disabled(res));

        if let Some(entry) = pool.find_entry(res) {
            entry.disabled_until_ms.store(0, Ordering::Relaxed);
        }
        assert!(!pool.is_disabled(res));

        for _ in 0..3 {
            pool.record_failure(res);
        }
        assert!(pool.is_disabled(res));

        pool.record_success(res);
        if let Some(entry) = pool.find_entry(res) {
            assert_eq!(entry.cooldown_count.load(Ordering::Relaxed), 0);
            assert_eq!(entry.consecutive_failures.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn test_select_excluding() {
        let pool = ResolverPool::new(test_resolvers(), false);
        let first = resolver("1.1.1.1");
        let second = resolver("8.8.8.8");

        let selected = pool.select_excluding(&[first]);
        assert!(selected.is_some());
        assert_ne!(selected, Some(first));

        let selected = pool.select_excluding(&[first, second]);
        assert_eq!(selected, Some(resolver("9.9.9.9")));

        let all = test_resolvers();
        let selected = pool.select_excluding(&all);
        assert!(selected.is_some());
    }

    #[test]
    fn test_rto_adaptive() {
        let pool = ResolverPool::new(vec![resolver("1.1.1.1")], false);
        let res = resolver("1.1.1.1");

        assert_eq!(pool.rto(res), Duration::from_millis(800));

        pool.record_success_with_latency(res, Duration::from_millis(10));
        assert_eq!(pool.rto(res), Duration::from_millis(250));

        for _ in 0..20 {
            pool.record_success_with_latency(res, Duration::from_millis(150));
        }
        let rto = pool.rto(res);
        assert!(rto >= Duration::from_millis(400) && rto <= Duration::from_millis(500));
    }

    #[tokio::test]
    async fn test_in_flight_permits() {
        let pool = ResolverPool::new(vec![resolver("1.1.1.1")], false);
        let res = resolver("1.1.1.1");

        assert_eq!(pool.in_flight_count(res), 0);
        let permit = pool.acquire_permit(res).await;
        assert!(permit.is_some());
        assert_eq!(pool.in_flight_count(res), 1);

        drop(permit);
        assert_eq!(pool.in_flight_count(res), 0);
    }

    #[tokio::test]
    async fn test_pace_resolver() {
        let pool = ResolverPool::new(vec![resolver("1.1.1.1")], false);
        let res = resolver("1.1.1.1");

        let start = Instant::now();
        pool.pace_resolver(res, Duration::from_millis(20)).await;
        pool.pace_resolver(res, Duration::from_millis(20)).await;
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(15));
    }

    #[tokio::test]
    async fn test_saturation_prioritizes_unsaturated() {
        let pool = ResolverPool::new(vec![resolver("1.1.1.1"), resolver("8.8.8.8")], false);
        let res1 = resolver("1.1.1.1");
        let res2 = resolver("8.8.8.8");

        // Artificially saturate res1 to max_in_flight
        if let Some(entry) = pool.find_entry(res1) {
            entry
                .in_flight
                .store(ResolverPool::DEFAULT_MAX_IN_FLIGHT, Ordering::Relaxed);
        }

        // res2 is unsaturated (0 in-flight), so select must pick res2
        assert_eq!(pool.select(), Some(res2));
    }

    #[test]
    fn test_pool_larger_than_64_resolvers() {
        let resolvers: Vec<SocketAddr> = (1..=70)
            .map(|i| {
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(10, 0, 0, i),
                    DEFAULT_DNS_PORT,
                ))
            })
            .collect();
        let pool = ResolverPool::new(resolvers.clone(), false);
        assert_eq!(pool.total_count(), 70);

        for _ in 0..140 {
            let res = pool.select();
            assert!(res.is_some());
            assert!(resolvers.contains(&res.unwrap()));
        }

        let first = resolvers[0];
        let res = pool.select_excluding(&[first]);
        assert!(res.is_some());
        assert_ne!(res, Some(first));
    }

    #[tokio::test]
    async fn test_pace_resolver_idle_immediate() {
        let pool = ResolverPool::new(vec![resolver("1.1.1.1")], false);
        let res = resolver("1.1.1.1");

        // First query to idle resolver must dispatch immediately without sleeping
        let start = Instant::now();
        pool.pace_resolver(res, Duration::from_millis(50)).await;
        let first_elapsed = start.elapsed();
        assert!(
            first_elapsed < Duration::from_millis(15),
            "First query should not be delayed: {first_elapsed:?}"
        );

        // Second query within interval must wait for remainder
        let start2 = Instant::now();
        pool.pace_resolver(res, Duration::from_millis(50)).await;
        let second_elapsed = start2.elapsed();
        assert!(
            second_elapsed >= Duration::from_millis(35),
            "Second query should be paced: {second_elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_in_flight_permits_saturation() {
        let pool = ResolverPool::new(vec![resolver("1.1.1.1")], false);
        let res = resolver("1.1.1.1");

        let mut permits = Vec::new();
        for _ in 0..ResolverPool::DEFAULT_MAX_IN_FLIGHT {
            let permit = pool.try_acquire_permit(res);
            assert!(permit.is_some());
            permits.push(permit);
        }

        assert_eq!(
            pool.in_flight_count(res),
            ResolverPool::DEFAULT_MAX_IN_FLIGHT
        );

        // 33rd permit must fail
        assert!(pool.try_acquire_permit(res).is_none());

        // Drop one permit, now try_acquire_permit should succeed
        drop(permits.pop());
        assert_eq!(
            pool.in_flight_count(res),
            ResolverPool::DEFAULT_MAX_IN_FLIGHT - 1
        );
        let new_permit = pool.try_acquire_permit(res);
        drop(permits);
        let has_permit = new_permit.is_some();
        drop(new_permit);
        assert!(has_permit);
    }

    #[test]
    fn test_pool_larger_than_64_resolvers_random() {
        let resolvers: Vec<SocketAddr> = (1..=70)
            .map(|i| {
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(10, 0, 0, i),
                    DEFAULT_DNS_PORT,
                ))
            })
            .collect();
        let pool = ResolverPool::new(resolvers.clone(), true);
        assert_eq!(pool.total_count(), 70);

        for _ in 0..140 {
            let res = pool.select();
            assert!(res.is_some());
            assert!(resolvers.contains(&res.unwrap()));
        }

        let first = resolvers[0];
        let res = pool.select_excluding(&[first]);
        assert!(res.is_some());
        assert_ne!(res, Some(first));
    }

    #[tokio::test]
    async fn test_high_concurrency_stress() {
        let pool = Arc::new(ResolverPool::new(
            vec![
                resolver("1.1.1.1"),
                resolver("8.8.8.8"),
                resolver("9.9.9.9"),
            ],
            false,
        ));

        let mut handles = Vec::new();
        for _ in 0..50 {
            let pool_clone = pool.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..20 {
                    let res = pool_clone.select().unwrap();
                    let permit = pool_clone.acquire_permit(res).await;
                    assert!(permit.is_some());
                    pool_clone.record_success_with_latency(res, Duration::from_millis(10));
                    drop(permit);
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(pool.in_flight_count(resolver("1.1.1.1")), 0);
        assert_eq!(pool.in_flight_count(resolver("8.8.8.8")), 0);
        assert_eq!(pool.in_flight_count(resolver("9.9.9.9")), 0);
    }

    #[test]
    fn test_small_list_operations() {
        let mut list = SmallList::<usize, 4>::with_capacity(4);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);

        list.push(10);
        list.push(20);
        assert_eq!(list.len(), 2);
        assert_eq!(list.as_slice(), &[10, 20]);

        // Push past inline capacity to test automatic heap spilling
        list.push(30);
        list.push(40);
        list.push(50);
        assert_eq!(list.len(), 5);
        assert_eq!(list.as_slice(), &[10, 20, 30, 40, 50]);

        list.clear();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);

        // Test N=16 heap spilling with 20 elements
        let mut list16 = SmallList::<usize, 16>::with_capacity(16);
        for i in 0..20 {
            list16.push(i);
        }
        assert_eq!(list16.len(), 20);
        assert_eq!(list16.as_slice(), &(0..20).collect::<Vec<_>>()[..]);
    }

    #[test]
    fn test_resolver_entry_layout() {
        use std::mem::{align_of, size_of};
        assert_eq!(align_of::<ResolverEntry>(), 8);
        assert!(size_of::<ResolverEntry>() > 0);
    }

    #[test]
    fn test_candidate_collection_single_pass() {
        let pool = ResolverPool::new(
            vec![
                resolver("1.1.1.1"),
                resolver("8.8.8.8"),
                resolver("9.9.9.9"),
            ],
            false,
        );

        let mut candidates = SmallList::<usize, 16>::with_capacity(3);
        let mut unsaturated = SmallList::<usize, 16>::with_capacity(3);
        pool.populate_candidates(false, &[], &mut candidates, &mut unsaturated);

        assert_eq!(candidates.len(), 3);
        assert_eq!(unsaturated.len(), 3);
        assert_eq!(candidates.as_slice(), &[0, 1, 2]);
        assert_eq!(unsaturated.as_slice(), &[0, 1, 2]);

        // When one is disabled
        pool.disable(resolver("8.8.8.8"), Duration::from_secs(60));
        pool.populate_candidates(false, &[], &mut candidates, &mut unsaturated);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates.as_slice(), &[0, 2]);
    }
}
