use colored::Colorize;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

use crate::dns::{protocol::QueryType, resolver::resolve_domain};
use crate::network::types::TransportProtocol;

const ROOT_SERVER: &str = "a.rootservers.net";

fn generate_random_domain() -> String {
    let random_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    format!("{random_string}.example.com")
}

fn check_nxdomain_hijacking(server_address: &str, transport_protocol: &TransportProtocol) -> bool {
    let random_domain = generate_random_domain();
    resolve_domain(
        server_address,
        &random_domain,
        &QueryType::A,
        transport_protocol,
    )
    .is_ok()
}

fn print_status(server_address: &str, status: &str, color: &str) {
    let colored_status = match color {
        "green" => format!("[{}]", status.green()),
        "red" => format!("[{}]", status.red()),
        _ => status.to_string(),
    };

    println!(
        "{} {:>width$}",
        server_address.bright_blue(),
        colored_status,
        width = 30 - server_address.len()
    );
}

pub fn check_dns_resolvers(
    dns_resolvers: &[&str],
    transport_protocol: &TransportProtocol,
) -> Vec<String> {
    let mut working_servers = Vec::new();
    let mut failed_servers = Vec::new();

    println!("Checking DNS Servers...");

    for &server in dns_resolvers {
        let hijacking = check_nxdomain_hijacking(server, transport_protocol);
        let normal_query = resolve_domain(server, ROOT_SERVER, &QueryType::A, transport_protocol);

        if hijacking {
            print_status(server, "FAIL", "red");
            failed_servers.push((server, "NXDOMAIN HIJACKING"));
        } else if normal_query.is_err() {
            print_status(server, "FAIL", "red");
            failed_servers.push((server, "No response"));
        } else {
            print_status(server, "OK", "green");
            working_servers.push(server.to_string());
        }
    }

    if !failed_servers.is_empty() {
        println!("DNS Resolvers:");
        for (server, reason) in failed_servers {
            println!("Removed {server} - {reason}");
        }
    }

    println!();

    working_servers
}
