use crate::io::cli::CommandArgs;
use anyhow::Result;
use rand::prelude::*;

pub trait ResolverSelector {
    fn select(&mut self) -> Result<&str>;
}

pub enum Selector {
    Random {
        dns_resolvers: Vec<String>,
    },
    Sequential {
        dns_resolvers: Vec<String>,
        current_index: usize,
    },
}

impl Selector {
    pub fn new(use_random: bool, dns_resolvers: &[&str]) -> Self {
        let resolvers = dns_resolvers.iter().map(|&s| s.to_string()).collect();
        if use_random {
            Self::Random {
                dns_resolvers: resolvers,
            }
        } else {
            Self::Sequential {
                dns_resolvers: resolvers,
                current_index: 0,
            }
        }
    }
}

impl ResolverSelector for Selector {
    fn select(&mut self) -> Result<&str> {
        match self {
            Self::Random { dns_resolvers } => dns_resolvers
                .choose(&mut thread_rng())
                .map(std::string::String::as_str)
                .ok_or_else(|| anyhow::anyhow!("DNS Resolvers list is empty")),
            Self::Sequential {
                dns_resolvers,
                current_index,
            } => {
                if dns_resolvers.is_empty() {
                    return Err(anyhow::anyhow!("DNS Resolvers list is empty"));
                }
                let resolver = &dns_resolvers[*current_index];
                *current_index = (*current_index + 1) % dns_resolvers.len();
                Ok(resolver)
            }
        }
    }
}

pub fn get_selector(args: &CommandArgs, dns_resolvers: &[&str]) -> Box<dyn ResolverSelector> {
    Box::new(Selector::new(args.use_random, dns_resolvers))
}
