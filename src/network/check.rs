use colored::Colorize;
use rand::distr::Alphanumeric;
use rand::Rng;

use crate::dns::async_resolver_pool::AsyncResolverPool;
use crate::dns::protocol::QueryType;
use crate::network::types::TransportProtocol;

const ROOT_SERVER: &str = "rootservers.net";

fn generate_random_domain() -> String {
    let random_string: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    format!("{random_string}.example.com")
}

async fn check_nxdomain_hijacking(
    resolver_pool: &AsyncResolverPool,
    server_address: &str,
    transport_protocol: &TransportProtocol,
) -> bool {
    let random_domain = generate_random_domain();
    resolver_pool
        .resolve(
            server_address,
            &random_domain,
            &QueryType::A,
            transport_protocol,
            true,
        )
        .await
        .is_ok()
}

fn print_status(server_address: &str, status: &str) {
    let colored_status = match status {
        "OK" => format!("[{}]", status.green()),
        "FAIL" => format!("[{}]", status.red()),
        _ => status.to_string(),
    };

    println!(
        "{} {:>width$}",
        server_address.bright_blue(),
        colored_status,
        width = 33 - server_address.len()
    );
}

pub async fn check_dns_resolvers<'a>(
    dns_resolvers: &[&'a str],
    transport_protocol: &TransportProtocol,
) -> Vec<&'a str> {
    let mut working_servers: Vec<&'a str> = Vec::new();
    let mut failed_servers: Vec<(&'a str, &str)> = Vec::new();

    let resolver_pool = AsyncResolverPool::new(Some(1)).await.unwrap();

    println!("Checking DNS Resolvers...");

    for &server in dns_resolvers {
        let hijacking = check_nxdomain_hijacking(&resolver_pool, server, transport_protocol).await;

        let root_server_letter = rand::rng().random_range(b'a'..b'm') as char;
        let domain = format!("{root_server_letter}.{ROOT_SERVER}");
        let normal_query = resolver_pool
            .resolve(server, &domain, &QueryType::A, transport_protocol, true)
            .await;

        if hijacking {
            print_status(server, "FAIL");
            failed_servers.push((server, "NXDOMAIN HIJACKING"));
        } else if normal_query.is_err() {
            print_status(server, "FAIL");
            failed_servers.push((server, "No response"));
        } else {
            print_status(server, "OK");
            working_servers.push(server); // Push &str directly
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
