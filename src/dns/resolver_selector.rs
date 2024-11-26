use anyhow::Result;
use rand::seq::SliceRandom;
use rand::thread_rng;

use crate::io::cli::CommandArgs;

pub trait ResolverSelector {
    fn select<'a>(&mut self, dns_resolvers: &'a [&str]) -> Result<&'a str>;
}

pub enum Selector {
    Random,
    Sequential { current_index: usize },
}

impl Selector {
    pub const fn new(use_random: bool) -> Self {
        if use_random {
            Self::Random
        } else {
            Self::Sequential { current_index: 0 }
        }
    }
}

impl ResolverSelector for Selector {
    fn select<'a>(&mut self, dns_resolvers: &'a [&str]) -> Result<&'a str> {
        match self {
            Self::Random => dns_resolvers
                .choose(&mut thread_rng())
                .copied()
                .ok_or_else(|| anyhow::anyhow!("DNS Resolvers list is empty")),
            Self::Sequential { current_index } => {
                if dns_resolvers.is_empty() {
                    return Err(anyhow::anyhow!("DNS Resolvers list is empty"));
                }
                let resolver = dns_resolvers[*current_index];
                *current_index = (*current_index + 1) % dns_resolvers.len();
                Ok(resolver)
            }
        }
    }
}

pub fn get_selector(args: &CommandArgs) -> Box<dyn ResolverSelector> {
    Box::new(Selector::new(args.use_random))
}
