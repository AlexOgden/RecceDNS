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

#[derive(Debug)]
pub struct ResolverEntry {
    pub addr: SocketAddr,
    pub in_flight: AtomicUsize,
    pub max_in_flight: AtomicUsize,
    pub ewma_latency_us: AtomicU64,
    pub ewma_success_permille: AtomicU32,
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
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(ResolverPool::DEFAULT_MAX_IN_FLIGHT),
            ewma_latency_us: AtomicU64::new(0),
            ewma_success_permille: AtomicU32::new(1000),
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
}

/// RAII guard representing an in-flight query permit on a resolver.
#[derive(Debug)]
pub struct ResolverPermit {
    entry: Arc<ResolverEntry>,
    _semaphore_permit: Option<tokio::sync::OwnedSemaphorePermit>,
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
    #[allow(dead_code)]
    pub const DISABLE_COOLDOWN: Duration = Duration::from_secs(3);
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
    fn find_entry(&self, resolver: SocketAddr) -> Option<&Arc<ResolverEntry>> {
        self.inner
            .addr_to_index
            .get(&resolver)
            .and_then(|&idx| self.inner.entries.get(idx))
    }

    #[inline]
    fn is_entry_disabled(&self, entry: &ResolverEntry) -> bool {
        let now_ms =
            u64::try_from(self.inner.start_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
        entry.disabled_until_ms.load(Ordering::Relaxed) > now_ms
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

        if self.inner.use_random {
            self.select_random(excluded)
        } else {
            self.select_sequential(excluded)
        }
    }

    fn select_sequential(&self, excluded: &[SocketAddr]) -> Option<SocketAddr> {
        let total_entries = self.inner.entries.len();
        if total_entries <= 64 {
            let mut candidate_indices = [0usize; 64];
            let mut count = 0;
            let mut unsaturated_indices = [0usize; 64];
            let mut unsaturated_count = 0;

            for (idx, entry) in self.inner.entries.iter().enumerate() {
                if !self.is_entry_disabled(entry) && !excluded.contains(&entry.addr) {
                    candidate_indices[count] = idx;
                    count += 1;

                    if entry.in_flight.load(Ordering::Relaxed)
                        < entry.max_in_flight.load(Ordering::Relaxed)
                    {
                        unsaturated_indices[unsaturated_count] = idx;
                        unsaturated_count += 1;
                    }
                }
            }

            if count == 0 {
                for (idx, entry) in self.inner.entries.iter().enumerate() {
                    if !self.is_entry_disabled(entry) {
                        candidate_indices[count] = idx;
                        count += 1;

                        if entry.in_flight.load(Ordering::Relaxed)
                            < entry.max_in_flight.load(Ordering::Relaxed)
                        {
                            unsaturated_indices[unsaturated_count] = idx;
                            unsaturated_count += 1;
                        }
                    }
                }
            }

            if count == 0 {
                return self.fallback();
            }

            if unsaturated_count > 0 {
                if unsaturated_count == 1 {
                    return Some(self.inner.entries[unsaturated_indices[0]].addr);
                }
                self.swrr_select(&unsaturated_indices[..unsaturated_count])
            } else {
                if count == 1 {
                    return Some(self.inner.entries[candidate_indices[0]].addr);
                }
                self.swrr_select(&candidate_indices[..count])
            }
        } else {
            let mut candidates: Vec<usize> = Vec::with_capacity(total_entries);
            let mut unsaturated: Vec<usize> = Vec::with_capacity(total_entries);

            for (idx, entry) in self.inner.entries.iter().enumerate() {
                if !self.is_entry_disabled(entry) && !excluded.contains(&entry.addr) {
                    candidates.push(idx);
                    if entry.in_flight.load(Ordering::Relaxed)
                        < entry.max_in_flight.load(Ordering::Relaxed)
                    {
                        unsaturated.push(idx);
                    }
                }
            }

            if candidates.is_empty() {
                for (idx, entry) in self.inner.entries.iter().enumerate() {
                    if !self.is_entry_disabled(entry) {
                        candidates.push(idx);
                        if entry.in_flight.load(Ordering::Relaxed)
                            < entry.max_in_flight.load(Ordering::Relaxed)
                        {
                            unsaturated.push(idx);
                        }
                    }
                }
            }

            if candidates.is_empty() {
                return self.fallback();
            }

            if unsaturated.is_empty() {
                if candidates.len() == 1 {
                    return Some(self.inner.entries[candidates[0]].addr);
                }
                self.swrr_select(&candidates)
            } else {
                if unsaturated.len() == 1 {
                    return Some(self.inner.entries[unsaturated[0]].addr);
                }
                self.swrr_select(&unsaturated)
            }
        }
    }

    fn swrr_select(&self, candidate_indices: &[usize]) -> Option<SocketAddr> {
        let mut total_weight: i64 = 0;
        let mut best_entry: Option<&Arc<ResolverEntry>> = None;
        let mut max_current_weight = i64::MIN;

        for &idx in candidate_indices {
            let entry = &self.inner.entries[idx];
            let weight = i64::try_from(Self::calculate_weight(entry)).unwrap_or(1);
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

    fn select_random(&self, excluded: &[SocketAddr]) -> Option<SocketAddr> {
        let total_entries = self.inner.entries.len();
        if total_entries <= 64 {
            let mut candidate_indices = [0usize; 64];
            let mut count = 0;
            let mut unsaturated_indices = [0usize; 64];
            let mut unsaturated_count = 0;

            for (idx, entry) in self.inner.entries.iter().enumerate() {
                if !self.is_entry_disabled(entry) && !excluded.contains(&entry.addr) {
                    candidate_indices[count] = idx;
                    count += 1;

                    if entry.in_flight.load(Ordering::Relaxed)
                        < entry.max_in_flight.load(Ordering::Relaxed)
                    {
                        unsaturated_indices[unsaturated_count] = idx;
                        unsaturated_count += 1;
                    }
                }
            }

            if count == 0 {
                for (idx, entry) in self.inner.entries.iter().enumerate() {
                    if !self.is_entry_disabled(entry) {
                        candidate_indices[count] = idx;
                        count += 1;

                        if entry.in_flight.load(Ordering::Relaxed)
                            < entry.max_in_flight.load(Ordering::Relaxed)
                        {
                            unsaturated_indices[unsaturated_count] = idx;
                            unsaturated_count += 1;
                        }
                    }
                }
            }

            if count == 0 {
                return self.fallback();
            }

            if unsaturated_count > 0 {
                if unsaturated_count == 1 {
                    return Some(self.inner.entries[unsaturated_indices[0]].addr);
                }
                self.weighted_random_select(&unsaturated_indices[..unsaturated_count])
            } else {
                if count == 1 {
                    return Some(self.inner.entries[candidate_indices[0]].addr);
                }
                self.weighted_random_select(&candidate_indices[..count])
            }
        } else {
            let mut candidates: Vec<usize> = Vec::with_capacity(total_entries);
            let mut unsaturated: Vec<usize> = Vec::with_capacity(total_entries);

            for (idx, entry) in self.inner.entries.iter().enumerate() {
                if !self.is_entry_disabled(entry) && !excluded.contains(&entry.addr) {
                    candidates.push(idx);
                    if entry.in_flight.load(Ordering::Relaxed)
                        < entry.max_in_flight.load(Ordering::Relaxed)
                    {
                        unsaturated.push(idx);
                    }
                }
            }

            if candidates.is_empty() {
                for (idx, entry) in self.inner.entries.iter().enumerate() {
                    if !self.is_entry_disabled(entry) {
                        candidates.push(idx);
                        if entry.in_flight.load(Ordering::Relaxed)
                            < entry.max_in_flight.load(Ordering::Relaxed)
                        {
                            unsaturated.push(idx);
                        }
                    }
                }
            }

            if candidates.is_empty() {
                return self.fallback();
            }

            if unsaturated.is_empty() {
                if candidates.len() == 1 {
                    return Some(self.inner.entries[candidates[0]].addr);
                }
                self.weighted_random_select(&candidates)
            } else {
                if unsaturated.len() == 1 {
                    return Some(self.inner.entries[unsaturated[0]].addr);
                }
                self.weighted_random_select(&unsaturated)
            }
        }
    }

    fn weighted_random_select(&self, candidate_indices: &[usize]) -> Option<SocketAddr> {
        let mut total_weight: u64 = 0;
        let mut weights = [0u64; 64];
        let use_stack = candidate_indices.len() <= 64;
        let mut heap_weights = if use_stack {
            Vec::new()
        } else {
            Vec::with_capacity(candidate_indices.len())
        };

        for (i, &idx) in candidate_indices.iter().enumerate() {
            let w = Self::calculate_weight(&self.inner.entries[idx]);
            if use_stack {
                weights[i] = w;
            } else {
                heap_weights.push(w);
            }
            total_weight = total_weight.saturating_add(w);
        }

        if total_weight == 0 {
            return self.fallback();
        }

        let mut rng = rand::rng();
        let target = rng.random_range(0..total_weight);
        let mut acc = 0u64;

        for (i, &idx) in candidate_indices.iter().enumerate() {
            let w = if use_stack {
                weights[i]
            } else {
                heap_weights[i]
            };
            acc = acc.saturating_add(w);
            if target < acc {
                return Some(self.inner.entries[idx].addr);
            }
        }

        candidate_indices
            .last()
            .map(|&idx| self.inner.entries[idx].addr)
    }

    fn calculate_weight(entry: &ResolverEntry) -> u64 {
        let ewma_us = entry.ewma_latency_us.load(Ordering::Relaxed);
        let latency_ms = if ewma_us == 0 {
            50
        } else {
            (ewma_us / 1000).clamp(2, 2000)
        };

        let success_permille = u64::from(
            entry
                .ewma_success_permille
                .load(Ordering::Relaxed)
                .clamp(50, 1000),
        );
        (success_permille / latency_ms).clamp(1, 100)
    }

    #[inline]
    #[allow(dead_code)]
    #[must_use]
    pub fn is_disabled(&self, resolver: SocketAddr) -> bool {
        self.find_entry(resolver)
            .is_some_and(|e| self.is_entry_disabled(e))
    }

    #[inline]
    #[must_use]
    pub fn fallback(&self) -> Option<SocketAddr> {
        self.inner.resolvers.first().copied()
    }

    /// Temporarily disable a resolver for the specified duration.
    /// Will not disable if it would leave no resolvers available.
    pub fn disable(&self, resolver: SocketAddr, duration: Duration) {
        let other_available = self
            .inner
            .entries
            .iter()
            .any(|e| e.addr != resolver && !self.is_entry_disabled(e));

        if other_available && let Some(entry) = self.find_entry(resolver) {
            let now_ms =
                u64::try_from(self.inner.start_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
            let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
            entry
                .disabled_until_ms
                .store(now_ms.saturating_add(duration_ms), Ordering::Relaxed);
            entry.current_weight.store(0, Ordering::Relaxed);
        }
    }

    /// Record a successful resolution with measured latency.
    /// Resets consecutive failures and progressive cooldown backoff, and updates EWMA latency and success rate.
    pub fn record_success_with_latency(&self, resolver: SocketAddr, latency: Duration) {
        let Some(entry) = self.find_entry(resolver) else {
            return;
        };

        entry.successes.fetch_add(1, Ordering::Relaxed);
        entry.consecutive_failures.store(0, Ordering::Relaxed);
        entry.cooldown_count.store(0, Ordering::Relaxed);

        let lat_us = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        let mut cur_lat = entry.ewma_latency_us.load(Ordering::Relaxed);
        loop {
            let new_lat = if cur_lat == 0 {
                lat_us
            } else {
                cur_lat.saturating_mul(7).saturating_add(lat_us) / 8
            };
            match entry.ewma_latency_us.compare_exchange_weak(
                cur_lat,
                new_lat,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur_lat = actual,
            }
        }

        let mut cur_rate = entry.ewma_success_permille.load(Ordering::Relaxed);
        loop {
            let new_rate = (cur_rate * 9 + 1000) / 10;
            match entry.ewma_success_permille.compare_exchange_weak(
                cur_rate,
                new_rate,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur_rate = actual,
            }
        }
    }

    /// Record a successful resolution with a default 20ms baseline latency.
    #[allow(dead_code)]
    pub fn record_success(&self, resolver: SocketAddr) {
        self.record_success_with_latency(resolver, Duration::from_millis(20));
    }

    /// Record a failure for a resolver.
    /// If consecutive failures reach the threshold, triggers progressive exponential cooldown backoff.
    pub fn record_failure(&self, resolver: SocketAddr) {
        let Some(entry) = self.find_entry(resolver) else {
            return;
        };

        entry.failures.fetch_add(1, Ordering::Relaxed);

        let mut cur_rate = entry.ewma_success_permille.load(Ordering::Relaxed);
        loop {
            let new_rate = (cur_rate * 9) / 10;
            match entry.ewma_success_permille.compare_exchange_weak(
                cur_rate,
                new_rate,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur_rate = actual,
            }
        }

        let failures = entry.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= Self::FAILURE_THRESHOLD {
            entry.consecutive_failures.store(0, Ordering::Relaxed);
            let streak = entry.cooldown_count.fetch_add(1, Ordering::Relaxed);

            let shift = u32::try_from(streak).unwrap_or(5).min(5);
            let multiplier = 1u32 << shift;
            let cooldown = (Self::BASE_COOLDOWN * multiplier).min(Self::MAX_COOLDOWN);

            self.disable(resolver, cooldown);
        }
    }

    /// Compute adaptive Retransmission Timeout (RTO) for a resolver based on EWMA latency.
    #[must_use]
    pub fn rto(&self, resolver: SocketAddr) -> Duration {
        self.find_entry(resolver).map_or_else(
            || Duration::from_millis(1500),
            |entry| {
                let micros = entry.ewma_latency_us.load(Ordering::Relaxed);
                if micros == 0 {
                    Duration::from_millis(800)
                } else {
                    let millis = micros / 1000;
                    let rto_ms = (millis * 3).clamp(250, 1500);
                    Duration::from_millis(rto_ms)
                }
            },
        )
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
        entry.in_flight.fetch_add(1, Ordering::Relaxed);
        Some(ResolverPermit {
            entry: entry.clone(),
            _semaphore_permit: Some(semaphore_permit),
        })
    }

    /// Non-blocking attempt to acquire an in-flight permit for the resolver.
    #[allow(dead_code)]
    #[must_use]
    pub fn try_acquire_permit(&self, resolver: SocketAddr) -> Option<ResolverPermit> {
        let entry = self.find_entry(resolver)?;
        let semaphore_permit = entry.in_flight_semaphore.clone().try_acquire_owned().ok()?;
        entry.in_flight.fetch_add(1, Ordering::Relaxed);
        Some(ResolverPermit {
            entry: entry.clone(),
            _semaphore_permit: Some(semaphore_permit),
        })
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
        let now_us =
            u64::try_from(self.inner.start_instant.elapsed().as_micros()).unwrap_or(u64::MAX);
        let mut current = entry.last_dispatch_us.load(Ordering::Relaxed);

        let scheduled_us = loop {
            let scheduled = current.max(now_us);
            let next = scheduled.saturating_add(interval_us);
            match entry.last_dispatch_us.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break scheduled,
                Err(actual) => current = actual,
            }
        };

        if scheduled_us > now_us {
            let wait_us = scheduled_us - now_us;
            tokio::time::sleep(Duration::from_micros(wait_us)).await;
        }
    }

    /// Get current EWMA latency for a resolver.
    #[allow(dead_code)]
    #[must_use]
    pub fn get_ewma_latency(&self, resolver: SocketAddr) -> Option<Duration> {
        let entry = self.find_entry(resolver)?;
        let ewma_us = entry.ewma_latency_us.load(Ordering::Relaxed);
        if ewma_us == 0 {
            None
        } else {
            Some(Duration::from_micros(ewma_us))
        }
    }

    /// Get current success rate (0.0 to 1.0) for a resolver.
    #[allow(dead_code)]
    #[must_use]
    pub fn get_success_rate(&self, resolver: SocketAddr) -> Option<f64> {
        let entry = self.find_entry(resolver)?;
        let permille = entry.ewma_success_permille.load(Ordering::Relaxed);
        Some(f64::from(permille) / 1000.0)
    }

    /// Get current in-flight query count for a resolver.
    #[allow(dead_code)]
    #[must_use]
    pub fn in_flight_count(&self, resolver: SocketAddr) -> usize {
        self.find_entry(resolver)
            .map_or(0, |e| e.in_flight.load(Ordering::Relaxed))
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn available_count(&self) -> usize {
        self.inner
            .entries
            .iter()
            .filter(|e| !self.is_entry_disabled(e))
            .count()
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.inner.resolvers.len()
    }

    #[allow(dead_code)]
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
    #[allow(clippy::significant_drop_tightening)]
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
        assert!(new_permit.is_some());
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
}
