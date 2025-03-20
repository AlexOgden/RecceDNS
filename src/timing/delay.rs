use rand::Rng;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum Delay {
    Fixed(u64),
    Range(u64, u64),
    Adaptive(Arc<AdaptiveDelayState>),
}

/// State tracking for adaptive delay adjustments
#[derive(Debug)]
pub struct AdaptiveDelayState {
    min_delay: u64,
    max_delay: u64,
    current_delay: AtomicU64,
    success_count: AtomicUsize,
    failure_count: AtomicUsize,
    total_queries: AtomicUsize,
}

impl AdaptiveDelayState {
    const fn new(min_delay: u64, max_delay: u64) -> Self {
        Self {
            min_delay,
            max_delay,
            current_delay: AtomicU64::new(min_delay),
            success_count: AtomicUsize::new(0),
            failure_count: AtomicUsize::new(0),
            total_queries: AtomicUsize::new(0),
        }
    }

    /// Reports a successful query and adjusts delay downward
    pub fn report_success(&self) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        // Only adjust every 20 queries to avoid overreacting
        if self.total_queries.load(Ordering::Relaxed) % 25 == 0 {
            let current = self.current_delay.load(Ordering::Relaxed);
            let success_rate = self.get_success_rate();

            // Gradually decrease delay when success rate is high
            if success_rate > 0.8 {
                let new_delay = (current * 85) / 100; // 15% decrease
                let new_delay = new_delay.max(self.min_delay);
                self.current_delay.store(new_delay, Ordering::Relaxed);
            }
        }
    }

    /// Reports a failed query and adjusts delay upward
    pub fn report_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        // React more quickly to failures
        let current = self.current_delay.load(Ordering::Relaxed);

        // Exponential backoff on failure, ensuring we always increase by at least 1ms
        let new_delay = if current <= 1 {
            // For very small values, use a fixed increment
            current + 5
        } else {
            // Normal 25% increase for larger values
            (current * 5) / 4
        };

        let new_delay = new_delay.min(self.max_delay);
        self.current_delay.store(new_delay, Ordering::Relaxed);
    }

    #[allow(clippy::cast_precision_loss)]
    fn get_success_rate(&self) -> f64 {
        let success = self.success_count.load(Ordering::Relaxed) as f64;
        let total = self.total_queries.load(Ordering::Relaxed) as f64;

        if total == 0.0 {
            return 1.0; // Default to optimistic
        }

        success / total
    }
}

impl Delay {
    pub fn get_delay(&self) -> u64 {
        match self {
            Self::Fixed(value) => *value,
            Self::Range(min, max) => {
                let mut rng = rand::rng();
                rng.random_range(*min..=*max)
            }
            Self::Adaptive(state) => state.current_delay.load(Ordering::Relaxed),
        }
    }

    /// Report the success status of a query to adjust adaptive delay
    pub fn report_query_result(&self, success: bool) {
        if let Self::Adaptive(state) = self {
            if success {
                state.report_success();
            } else {
                state.report_failure();
            }
        }
    }

    /// Create a new adaptive delay with default parameters
    pub fn adaptive(min: u64, max: u64) -> Self {
        Self::Adaptive(Arc::new(AdaptiveDelayState::new(min, max)))
    }
}

impl FromStr for Delay {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with('A') {
            let parts: Vec<&str> = s.split(':').collect();
            match parts.len() {
                // Default adaptive parameters
                1 => return Ok(Self::adaptive(10, 500)),
                2 => {
                    if let Some((min, max)) = parts[1].split_once('-') {
                        let min = min
                            .parse::<u64>()
                            .map_err(|_| "Invalid min in adaptive range")?;
                        let max = max
                            .parse::<u64>()
                            .map_err(|_| "Invalid max in adaptive range")?;
                        if min > max {
                            return Err("Invalid adaptive range: min is greater than max".into());
                        }
                        return Ok(Self::adaptive(min, max));
                    }

                    return Err("Invalid adaptive format. Use 'A' or 'A:min-max'".into());
                }
                _ => return Err("Invalid adaptive format".into()),
            }
        }

        if let Some((min, max)) = s.split_once('-') {
            let min = min.parse::<u64>().map_err(|_| "Invalid number in range")?;
            let max = max.parse::<u64>().map_err(|_| "Invalid number in range")?;
            if min > max {
                return Err("Invalid range: min is greater than max".into());
            }
            Ok(Self::Range(min, max))
        } else {
            let value = s
                .parse::<u64>()
                .map_err(|_| "Invalid number for fixed delay")?;
            Ok(Self::Fixed(value))
        }
    }
}

impl fmt::Display for Delay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(value) => write!(f, "Fixed: {value}ms"),
            Self::Range(min, max) => write!(f, "Range: {min}-{max}ms"),
            Self::Adaptive(state) => {
                write!(f, "Adaptive: {}-{}ms", state.min_delay, state.max_delay)
            }
        }
    }
}
