mod dns;
mod io;
mod modes;
mod network;
mod timing;

use std::{net::Ipv4Addr, path::Path};

use anyhow::{Result, anyhow, ensure};
use io::{
    cli::{self, OperationMode},
    validation::filter_working_resolvers,
};
use network::types::TransportProtocol;

#[tokio::main]
async fn main() -> Result<()> {
    let cmd_args = io::cli::get_parsed_args();

    if !cmd_args.no_welcome {
        io::cli::print_ascii_art();
    }
    let dns_resolvers = initialize_dns_resolvers(&cmd_args).await?;
    log_argument_info(&cmd_args);

    match cmd_args.operation_mode {
        OperationMode::BasicEnumeration => {
            modes::basic_enumerator::enumerate_records(&cmd_args, &dns_resolvers).await
        }
        OperationMode::CertSearch => modes::cert_search::search_certificates(&cmd_args).await,
        OperationMode::SubdomainEnumeration => {
            modes::subdomain_enumerator::enumerate_subdomains(&cmd_args, &dns_resolvers).await
        }
        OperationMode::ReverseIp => modes::reverse_ip::reverse_ip(&cmd_args, &dns_resolvers).await,
        OperationMode::TldExpansion => {
            modes::tld_expander::expand_tlds(&cmd_args, &dns_resolvers).await
        }
    }
}

fn log_argument_info(cmd_args: &cli::CommandArgs) {
    if cmd_args.transport_protocol == TransportProtocol::TCP {
        log_info!("Using TCP for DNS queries");
    }

    if let Some(delay) = &cmd_args.delay {
        log_info!(format!("Using Delay: {}", delay));
    }
}

fn parse_resolvers(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn load_resolvers_from_file(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read DNS resolvers file '{}': {}", path, e))?;
    Ok(content.lines().flat_map(parse_resolvers).collect())
}

async fn initialize_dns_resolvers(cmd_args: &cli::CommandArgs) -> Result<Vec<Ipv4Addr>> {
    let no_dns_check =
        matches!(cmd_args.operation_mode, OperationMode::CertSearch) || cmd_args.no_dns_check;

    let dns_resolvers_arg = cmd_args.dns_resolvers.trim();
    let resolver_list: Vec<String> = if Path::new(dns_resolvers_arg).exists() {
        load_resolvers_from_file(dns_resolvers_arg)?
    } else {
        parse_resolvers(dns_resolvers_arg)
    };

    ensure!(
        !resolver_list.is_empty(),
        "No DNS resolvers provided! At least one resolver must be specified."
    );

    let ipv4_resolvers: Vec<Ipv4Addr> = resolver_list
        .iter()
        .map(|s| {
            s.parse::<Ipv4Addr>()
                .map_err(|_| anyhow!("Invalid IPv4 address: '{}'", s))
        })
        .collect::<Result<_, _>>()?;

    let working_resolvers =
        filter_working_resolvers(no_dns_check, &cmd_args.transport_protocol, &ipv4_resolvers).await;

    ensure!(
        !working_resolvers.is_empty(),
        "No working DNS resolvers found! At least one resolver must be operational."
    );

    Ok(working_resolvers)
}
