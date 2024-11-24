mod dns;
mod io;
mod modes;
mod network;
mod timing;

use anyhow::{ensure, Result};
use io::{cli::OperationMode, validate::filter_working_dns_resolvers};

fn main() -> Result<()> {
    let command_args = io::cli::get_parsed_args();

    if !command_args.no_welcome {
        io::cli::print_ascii_art();
    }

    let dns_resolvers = filter_working_dns_resolvers(
        &command_args,
        &command_args.dns_resolvers.split(',').collect::<Vec<&str>>(),
    );
    ensure!(
        !dns_resolvers.is_empty(),
        "No DNS Resolvers in list! At least one resolver must be working!"
    );

    match command_args.operation_mode {
        OperationMode::BasicEnumeration => {
            modes::basic_enumerator::enumerate_records(&command_args, &dns_resolvers)
        }
        OperationMode::SubdomainEnumeration => {
            modes::subdomain_enumerator::enumerate_subdomains(&command_args, &dns_resolvers)
        }
        OperationMode::ReverseIp => modes::reverse_ip::reverse_ip(&command_args, &dns_resolvers),
    }
}
