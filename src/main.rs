mod dns;
mod io;
mod modes;
mod network;
mod timing;

use anyhow::{ensure, Result};
use io::{
    cli::{self, OperationMode},
    validation::filter_working_dns_resolvers,
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

async fn initialize_dns_resolvers(cmd_args: &cli::CommandArgs) -> Result<Vec<&str>> {
    let no_dns_check =
        cmd_args.operation_mode == OperationMode::CertSearch || cmd_args.no_dns_check;

    let resolver_list = cmd_args.dns_resolvers.split(',').collect::<Vec<&str>>();

    let dns_resolvers =
        filter_working_dns_resolvers(no_dns_check, &cmd_args.transport_protocol, &resolver_list)
            .await;

    ensure!(
        !dns_resolvers.is_empty(),
        "No working DNS resolvers found! At least one resolver must be operational."
    );

    Ok(dns_resolvers)
}
