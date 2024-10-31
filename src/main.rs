mod dns;
mod io;
mod modes;
mod network;

use anyhow::{ensure, Result};
use io::cli::{CommandArgs, OperationMode};
use network::net_check;

fn main() -> Result<()> {
    let args = io::cli::get_parsed_args();

    if !args.no_welcome {
        io::cli::print_ascii_art();
    }

    let dns_resolvers: Vec<&str> = args.dns_resolvers.split(',').collect();
    let dns_resolvers: Vec<&str> = validate_dns_resolvers(&args, &dns_resolvers);
    ensure!(
        !dns_resolvers.is_empty(),
        "No DNS Resolvers in list! At least one resolver must be working!"
    );

    match args.operation_mode {
        OperationMode::SubdomainEnumeration => {
            modes::subdomain_enumerator::enumerate_subdomains(&args, &dns_resolvers)
        }
        OperationMode::BasicEnumeration => {
            modes::basic_enumerator::enumerate_records(&args, &dns_resolvers)
        }
    }
}

fn validate_dns_resolvers<'a>(args: &CommandArgs, dns_resolvers: &[&'a str]) -> Vec<&'a str> {
    if args.no_dns_check {
        return dns_resolvers.to_vec();
    }

    let transport_protocol = network::types::TransportProtocol::UDP;
    let working_resolvers = net_check::check_dns_resolvers(dns_resolvers, &transport_protocol);

    let filtered_resolvers: Vec<&'a str> = dns_resolvers
        .iter()
        .copied()
        .filter(|resolver| working_resolvers.contains(resolver))
        .collect();

    filtered_resolvers
}
