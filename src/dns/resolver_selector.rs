use anyhow::Result;
use dashmap::DashMap;
use rand::seq::IndexedRandom;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub const DEFAULT_RESOLVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

pub trait ResolverSelector: Send + Sync {
    fn select(&mut self) -> Result<Ipv4Addr>;
    fn disable(&mut self, resolver: Ipv4Addr, duration: Duration);
}

pub enum Selector {
    Random {
        dns_resolvers: Vec<Ipv4Addr>,
        disabled: Arc<DashMap<Ipv4Addr, Instant>>,
    },
    Sequential {
        dns_resolvers: Vec<Ipv4Addr>,
        current_index: AtomicUsize,
        disabled: Arc<DashMap<Ipv4Addr, Instant>>,
    },
}

impl Selector {
    pub fn new(use_random: bool, dns_resolvers: Vec<Ipv4Addr>) -> Self {
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
    fn select(&mut self) -> Result<Ipv4Addr> {
        self.clean_disabled();

        match self {
            Self::Random {
                dns_resolvers,
                disabled,
            } => {
                let available_resolvers: Vec<&Ipv4Addr> = dns_resolvers
                    .iter()
                    .filter(|resolver| !disabled.contains_key(*resolver))
                    .collect();

                available_resolvers
                    .choose(&mut rand::rng())
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("No available DNS resolvers"))
                    .copied()
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
                    let idx = current_index.load(Ordering::SeqCst);
                    let resolver = &dns_resolvers[idx];
                    current_index.fetch_add(1, Ordering::SeqCst);
                    current_index.store(
                        current_index.load(Ordering::SeqCst) % dns_resolvers.len(),
                        Ordering::SeqCst,
                    );

                    if !disabled.contains_key(resolver) {
                        return Ok(*resolver);
                    }

                    if current_index.load(Ordering::SeqCst) == start_index {
                        return Err(anyhow::anyhow!("All DNS resolvers are disabled"));
                    }
                }
            }
        }
    }

    fn disable(&mut self, resolver: Ipv4Addr, duration: Duration) {
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
                    .any(|r| *r != resolver && !disabled.contains_key(r));

                if other_active_resolvers {
                    disabled.insert(resolver, Instant::now() + duration);
                }
            }
        }
    }
}

pub fn get_selector(random: bool, dns_resolvers: Vec<Ipv4Addr>) -> Box<dyn ResolverSelector> {
    Box::new(Selector::new(random, dns_resolvers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_random_selector() {
        let resolvers = vec![
            "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
        ];
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
        let resolvers = vec![
            "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
        ];
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
            "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
            "9.9.9.9".parse::<Ipv4Addr>().unwrap(),
        ];
        let mut selector = Selector::new(false, resolvers);

        assert_eq!(
            selector.select().unwrap(),
            "1.1.1.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            selector.select().unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            selector.select().unwrap(),
            "9.9.9.9".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            selector.select().unwrap(),
            "1.1.1.1".parse::<Ipv4Addr>().unwrap()
        ); // Cycles back
    }

    #[test]
    fn test_disable_and_expiry() {
        let resolvers = vec![
            "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
            "9.9.9.9".parse::<Ipv4Addr>().unwrap(),
        ];
        let mut selector = Selector::new(false, resolvers);

        assert_eq!(
            selector.select().unwrap(),
            "1.1.1.1".parse::<Ipv4Addr>().unwrap()
        );

        // Disable 8.8.8.8 for a short time
        selector.disable(
            "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
            Duration::from_millis(100),
        );

        // Should skip 8.8.8.8 and go to 9.9.9.9
        assert_eq!(
            selector.select().unwrap(),
            "9.9.9.9".parse::<Ipv4Addr>().unwrap()
        );

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(150));

        // Now we're back to 1.1.1.1
        assert_eq!(
            selector.select().unwrap(),
            "1.1.1.1".parse::<Ipv4Addr>().unwrap()
        );

        // And 8.8.8.8 should be available again
        assert_eq!(
            selector.select().unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap()
        );
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
        let resolvers = vec![
            "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
        ];
        let mut selector = Selector::new(false, resolvers);

        selector.disable(
            "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            Duration::from_secs(10),
        );
        selector.disable(
            "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
            Duration::from_secs(10),
        );

        // At least one resolver should always remain available
        let result = selector.select();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_selector_factory() {
        let resolvers = vec![
            "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
        ];

        let mut sequential_selector = get_selector(false, resolvers.clone());
        assert_eq!(
            sequential_selector.select().unwrap(),
            "1.1.1.1".parse::<Ipv4Addr>().unwrap()
        );

        let mut random_selector = get_selector(true, resolvers);
        let resolver = random_selector.select().unwrap();
        assert!(
            resolver == "1.1.1.1".parse::<Ipv4Addr>().unwrap()
                || resolver == "8.8.8.8".parse::<Ipv4Addr>().unwrap()
        );
    }
}
