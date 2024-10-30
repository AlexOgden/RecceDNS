mod dns;
mod io;
mod modes;
mod network;

use anyhow::{ensure, Result};
use colored::Colorize;
use io::cli::{CommandArgs, OperationMode};
use network::net_check;

fn main() -> Result<()> {
    let args = io::cli::get_parsed_args();

    if !args.no_welcome {
        io::cli::print_ascii_art();
    }

    let dns_resolvers = args.dns_resolvers.split(',').collect();
    let dns_resolvers = validate_dns_resolvers(&args, dns_resolvers);
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

fn validate_dns_resolvers<'a>(args: &CommandArgs, dns_resolvers: Vec<&'a str>) -> Vec<&'a str> {
    if args.no_dns_check {
        dns_resolvers
    } else {
        // Get the list of working DNS resolvers
        let transport_protocol = network::types::TransportProtocol::UDP;
        let working_resolvers: Vec<String> =
            net_check::check_dns_resolvers(&dns_resolvers, &transport_protocol);
        if working_resolvers.is_empty() {
            eprintln!(
                "{}",
                "No working DNS resolvers found! Please check your network connection.".red()
            );
            std::process::exit(1);
        }
        dns_resolvers
            .into_iter()
            .filter(|resolver| working_resolvers.contains(&(*resolver).to_string()))
            .collect()
    }
}
