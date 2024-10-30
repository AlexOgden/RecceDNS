use anyhow::Result;
use rand::seq::IteratorRandom;
use rand::thread_rng;

pub trait ResolverSelector {
    fn select<'a>(&mut self, dns_resolvers: &'a [&str]) -> Result<&'a str>;
}

// Selects a DNS resolver randomly from the list of DNS resolvers
pub struct Random;

impl ResolverSelector for Random {
    fn select<'a>(&mut self, dns_resolvers: &'a [&str]) -> Result<&'a str> {
        let mut random_generator = thread_rng();
        dns_resolvers
            .iter()
            .choose(&mut random_generator)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("DNS Resolvers list is empty"))
    }
}

// Selects a DNS resolver sequentially from the list of DNS resolvers
pub struct Sequential {
    current_index: usize,
}

impl Sequential {
    pub const fn new() -> Self {
        Self { current_index: 0 }
    }
}

impl ResolverSelector for Sequential {
    fn select<'a>(&mut self, dns_resolvers: &'a [&str]) -> Result<&'a str> {
        if dns_resolvers.is_empty() {
            return Err(anyhow::anyhow!("DNS Resolvers list is empty"));
        }
        let resolver = dns_resolvers[self.current_index];
        self.current_index = (self.current_index + 1) % dns_resolvers.len();
        Ok(resolver)
    }
}

// Unit Tests
#[cfg(test)]
mod test {
    use super::*;

    // Test Random Resolver Selector
    #[test]
    fn test_random_resolver_selector() {
        // Test 5 times
        for _ in 0..5 {
            let mut random = Random;
            let dns_resolvers = ["1.0.0.1", "1.1.1.1", "8.8.8.8"];
            let resolver = random.select(&dns_resolvers).unwrap();
            assert!(dns_resolvers.contains(&resolver));
        }
    }

    // Test Sequential Resolver Selector
    #[test]
    fn test_sequential_resolver_selector() {
        let mut sequential = Sequential::new();
        let dns_resolvers = ["1.1.1.1", "1.0.0.1", "8.8.8.8"];
        for resolver in &dns_resolvers {
            assert_eq!(sequential.select(&dns_resolvers).unwrap(), *resolver);
        }
    }

    // Test Random Resolver Selector with empty list
    #[test]
    fn test_random_resolver_selector_empty() {
        let mut random = Random;
        let dns_resolvers: [&str; 0] = [];
        let result = random.select(&dns_resolvers);
        assert!(result.is_err());
    }

    // Test Sequential Resolver Selector with empty list
    #[test]
    fn test_sequential_resolver_selector_empty() {
        let mut sequential = Sequential::new();
        let dns_resolvers: [&str; 0] = [];
        let result = sequential.select(&dns_resolvers);
        assert!(result.is_err());
    }

    // Test Sequential Resolver Selector wrapping around
    #[test]
    fn test_sequential_resolver_selector_wrap_around() {
        let mut sequential = Sequential::new();
        let dns_resolvers = ["1.1.1.1", "1.0.0.1", "8.8.8.8"];
        for _ in 0..dns_resolvers.len() * 2 {
            for resolver in &dns_resolvers {
                assert_eq!(sequential.select(&dns_resolvers).unwrap(), *resolver);
            }
        }
    }
}
