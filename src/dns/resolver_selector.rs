use anyhow::Result;
use rand::seq::IteratorRandom;
use rand::thread_rng;

pub trait ResolverSelector {
    fn select<'a>(&mut self, dns_resolvers: &'a [&str]) -> Result<&'a str>;
}

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
