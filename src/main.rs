mod dns;
mod io;
mod modes;
mod network;
mod timing;

use anyhow::{ensure, Result};
use io::{cli::OperationMode, validation::filter_working_dns_resolvers};

fn main() -> Result<()> {
    let cmd_args = io::cli::get_parsed_args();

    if !cmd_args.no_welcome {
        io::cli::print_ascii_art();
    }

    let no_dns_check = match cmd_args.operation_mode {
        OperationMode::CertSearch => true,
        _ => cmd_args.no_dns_check,
    };

    let dns_resolvers = filter_working_dns_resolvers(
        no_dns_check,
        &cmd_args.transport_protocol,
        &cmd_args.dns_resolvers.split(',').collect::<Vec<&str>>(),
    );
    ensure!(
        !dns_resolvers.is_empty(),
        "No DNS Resolvers in list! At least one resolver must be working!"
    );

    match cmd_args.operation_mode {
        OperationMode::BasicEnumeration => {
            modes::basic_enumerator::enumerate_records(&cmd_args, &dns_resolvers)
        }
        OperationMode::CertSearch => modes::cert_search::search_certificates(&cmd_args),
        OperationMode::SubdomainEnumeration => {
            modes::subdomain_enumerator::enumerate_subdomains(&cmd_args, &dns_resolvers)
        }
        OperationMode::ReverseIp => modes::reverse_ip::reverse_ip(&cmd_args, &dns_resolvers),
    }
}
