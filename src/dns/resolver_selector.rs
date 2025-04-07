use anyhow::Result;
use dashmap::DashMap;
use rand::seq::IndexedRandom;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DEFAULT_RESOLVER: &str = "1.1.1.1";

pub trait ResolverSelector: Send + Sync {
    fn select(&mut self) -> Result<&str>;
    fn disable(&mut self, resolver: &str, duration: Duration);
}

pub enum Selector {
    Random {
        dns_resolvers: Vec<String>,
        disabled: Arc<DashMap<String, Instant>>,
    },
    Sequential {
        dns_resolvers: Vec<String>,
        current_index: AtomicUsize,
        disabled: Arc<DashMap<String, Instant>>,
    },
}

impl Selector {
    pub fn new(use_random: bool, dns_resolvers: Vec<String>) -> Self {
        let disabled = Arc::new(DashMap::new());

        if use_random {
            Self::Random {
                dns_resolvers,
                disabled,
            }
        } else {
            Self::Sequential {
                dns_resolvers,
                current_index: AtomicUsize::new(0),
                disabled,
            }
        }
    }

    fn clean_disabled(&self) {
        let now = Instant::now();

        match self {
            Self::Random { disabled, .. } | Self::Sequential { disabled, .. } => {
                disabled.retain(|_, &mut expiry| expiry > now);
            }
        }
    }
}

impl ResolverSelector for Selector {
    fn select(&mut self) -> Result<&str> {
        self.clean_disabled();

        match self {
            Self::Random {
                dns_resolvers,
                disabled,
            } => {
                let available_resolvers: Vec<&String> = dns_resolvers
                    .iter()
                    .filter(|resolver| !disabled.contains_key(*resolver))
                    .collect();

                available_resolvers
                    .choose(&mut rand::rng())
                    .map(|s| s.as_str())
                    .ok_or_else(|| anyhow::anyhow!("No available DNS resolvers"))
            }
            Self::Sequential {
                dns_resolvers,
                current_index,
                disabled,
            } => {
                if dns_resolvers.is_empty() {
                    return Err(anyhow::anyhow!("DNS Resolvers list is empty"));
                }

                let start_index = current_index.load(Ordering::SeqCst);
                loop {
                    let resolver = &dns_resolvers[current_index.load(Ordering::SeqCst)];
                    current_index.fetch_add(1, Ordering::SeqCst);
                    current_index.store(
                        current_index.load(Ordering::SeqCst) % dns_resolvers.len(),
                        Ordering::SeqCst,
                    );

                    if !disabled.contains_key(resolver) {
                        return Ok(resolver);
                    }

                    if current_index.load(Ordering::SeqCst) == start_index {
                        return Err(anyhow::anyhow!("All DNS resolvers are disabled"));
                    }
                }
            }
        }
    }

    fn disable(&mut self, resolver: &str, duration: Duration) {
        self.clean_disabled();

        match self {
            Self::Random {
                dns_resolvers,
                disabled,
            }
            | Self::Sequential {
                dns_resolvers,
                disabled,
                ..
            } => {
                let other_active_resolvers = dns_resolvers
                    .iter()
                    .any(|r| r != resolver && !disabled.contains_key(r));

                if other_active_resolvers {
                    disabled.insert(resolver.to_string(), Instant::now() + duration);
                }
            }
        }
    }
}

pub fn get_selector(random: bool, dns_resolvers: Vec<String>) -> Box<dyn ResolverSelector> {
    Box::new(Selector::new(random, dns_resolvers))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_random_selector() {
        let resolvers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        let selector = Selector::new(true, resolvers.clone());

        if let Selector::Random {
            dns_resolvers,
            disabled,
        } = selector
        {
            assert_eq!(dns_resolvers, resolvers);
            assert!(disabled.is_empty());
        } else {
            panic!("Expected Random selector");
        }
    }

    #[test]
    fn test_new_sequential_selector() {
        let resolvers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        let selector = Selector::new(false, resolvers.clone());

        if let Selector::Sequential {
            dns_resolvers,
            current_index,
            disabled,
        } = selector
        {
            assert_eq!(dns_resolvers, resolvers);
            assert_eq!(current_index.load(Ordering::SeqCst), 0);
            assert!(disabled.is_empty());
        } else {
            panic!("Expected Sequential selector");
        }
    }

    #[test]
    fn test_sequential_selector_select() {
        let resolvers = vec![
            "1.1.1.1".to_string(),
            "8.8.8.8".to_string(),
            "9.9.9.9".to_string(),
        ];
        let mut selector = Selector::new(false, resolvers);

        assert_eq!(selector.select().unwrap(), "1.1.1.1");
        assert_eq!(selector.select().unwrap(), "8.8.8.8");
        assert_eq!(selector.select().unwrap(), "9.9.9.9");
        assert_eq!(selector.select().unwrap(), "1.1.1.1"); // Cycles back
    }

    #[test]
    fn test_disable_and_expiry() {
        let resolvers = vec![
            "1.1.1.1".to_string(),
            "8.8.8.8".to_string(),
            "9.9.9.9".to_string(),
        ];
        let mut selector = Selector::new(false, resolvers);

        assert_eq!(selector.select().unwrap(), "1.1.1.1");

        // Disable 8.8.8.8 for a short time
        selector.disable("8.8.8.8", Duration::from_millis(100));

        // Should skip 8.8.8.8 and go to 9.9.9.9
        assert_eq!(selector.select().unwrap(), "9.9.9.9");

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(150));

        // Now we're back to 1.1.1.1
        assert_eq!(selector.select().unwrap(), "1.1.1.1");

        // And 8.8.8.8 should be available again
        assert_eq!(selector.select().unwrap(), "8.8.8.8");
    }

    #[test]
    fn test_empty_resolvers_list() {
        let mut random_selector = Selector::new(true, vec![]);
        let mut sequential_selector = Selector::new(false, vec![]);

        assert!(random_selector.select().is_err());
        assert!(sequential_selector.select().is_err());
    }

    #[test]
    fn test_cannot_disable_all_resolvers() {
        let resolvers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        let mut selector = Selector::new(false, resolvers);

        selector.disable("1.1.1.1", Duration::from_secs(10));
        selector.disable("8.8.8.8", Duration::from_secs(10));

        // At least one resolver should always remain available
        let result = selector.select();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_selector_factory() {
        let resolvers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];

        let mut sequential_selector = get_selector(false, resolvers.clone());
        assert_eq!(sequential_selector.select().unwrap(), "1.1.1.1");

        let mut random_selector = get_selector(true, resolvers);
        let resolver = random_selector.select().unwrap();
        assert!(resolver == "1.1.1.1" || resolver == "8.8.8.8");
    }
}
