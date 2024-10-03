mod dns;
mod io;
mod modes;

use anyhow::{ensure, Result};
use colored::Colorize;
use dns::network_check;
use io::cli::CommandArgs;

fn main() -> Result<()> {
    let args = io::cli::get_parsed_args();

    if !args.no_welcome {
        io::cli::print_ascii_art();
        io::cli::print_options(&args);
    }

    let dns_resolvers: Vec<&str> = args.dns_resolvers.split(',').collect();
    let dns_resolvers = validate_dns_resolvers(&args, dns_resolvers);
    ensure!(
        !dns_resolvers.is_empty(),
        "No DNS Resolvers in list! At least one resolver must be working!"
    );

    modes::subdomain_enumerator::enumerate_subdomains(&args, &dns_resolvers)
}

fn validate_dns_resolvers<'a>(args: &'a CommandArgs, dns_resolvers: Vec<&'a str>) -> Vec<&'a str> {
    if args.no_dns_check {
        dns_resolvers
    } else {
        match network_check::check_server_list(&dns_resolvers) {
            Ok(()) => {
                let status = format!("[{}]", "OK".green());
                println!("DNS Resolvers: {:>width$}\n", status, width = 16);
                dns_resolvers
            }
            Err(failed_servers) => {
                println!(
                    "{}: {}\n",
                    "Removed resolvers with errors".yellow(),
                    failed_servers.join(", ")
                );
                dns_resolvers
                    .into_iter()
                    .filter(|resolver| !failed_servers.contains(&(*resolver).to_string()))
                    .collect()
            }
        }
    }
}
