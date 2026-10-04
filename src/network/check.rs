use colored::Colorize;
use rand::RngExt;
use rand::distr::Alphanumeric;
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::Semaphore, task::JoinSet};

use crate::dns::async_resolver::AsyncResolver;
use crate::dns::protocol::QueryType;
use crate::network::types::TransportProtocol;

const ROOT_SERVER: &str = "root-servers.net";

/// Max resolvers probed at once (each probe sends 2 queries).
/// Bounds open sockets/TCP connections and in-flight query IDs.
const MAX_CONCURRENT_CHECKS: usize = 256;

fn generate_random_domain() -> String {
    let random_string: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    format!("{random_string}.example.com")
}

async fn check_nxdomain_hijacking(
    resolver_pool: &AsyncResolver,
    server_address: SocketAddr,
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

fn print_status(server_address: SocketAddr, status: &str) {
    let colored_status = match status {
        "OK" => format!("[{}]", status.green()),
        "FAIL" => format!("[{}]", status.red()),
        _ => status.to_string(),
    };

    println!(
        "{} {:>width$}",
        server_address.to_string().bright_blue(),
        colored_status,
        width = 33 - server_address.to_string().len()
    );
}

#[derive(Clone, Copy)]
enum CheckOutcome {
    Ok,
    Hijacking,
    NoResponse,
}

impl CheckOutcome {
    const fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Hijacking => "NXDOMAIN HIJACKING",
            Self::NoResponse => "No response",
        }
    }
}

/// Runs the hijack probe and the liveness probe for a single resolver concurrently.
async fn check_resolver(
    resolver_pool: &AsyncResolver,
    server: SocketAddr,
    transport_protocol: &TransportProtocol,
) -> CheckOutcome {
    let root_server_letter = rand::rng().random_range(b'a'..=b'm') as char;
    let domain = format!("{root_server_letter}.{ROOT_SERVER}");

    let (hijacking, normal_query) = tokio::join!(
        check_nxdomain_hijacking(resolver_pool, server, transport_protocol),
        resolver_pool.resolve(server, &domain, &QueryType::A, transport_protocol, true),
    );

    if hijacking {
        CheckOutcome::Hijacking
    } else if normal_query.is_err() {
        CheckOutcome::NoResponse
    } else {
        CheckOutcome::Ok
    }
}

/// Checks all resolvers concurrently and returns the working ones in their original order.
pub async fn check_dns_resolvers(
    dns_resolvers: &[SocketAddr],
    transport_protocol: &TransportProtocol,
) -> Vec<SocketAddr> {
    let resolver_pool = match AsyncResolver::new(None).await {
        Ok(pool) => pool,
        Err(e) => {
            crate::log_error!(format!(
                "Failed to create DNS resolver for health check: {e}"
            ));
            return Vec::new();
        }
    };

    println!("Checking DNS Resolvers...");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CHECKS));
    let mut tasks = JoinSet::new();

    for (index, &server) in dns_resolvers.iter().enumerate() {
        let resolver_pool = resolver_pool.clone();
        let semaphore = Arc::clone(&semaphore);
        let transport_protocol = transport_protocol.clone();

        tasks.spawn(async move {
            // Semaphore is never closed, so acquire only fails if it is; treat as no response.
            let Ok(_permit) = semaphore.acquire_owned().await else {
                return (index, server, CheckOutcome::NoResponse);
            };
            let outcome = check_resolver(&resolver_pool, server, &transport_protocol).await;
            (index, server, outcome)
        });
    }

    let mut outcomes: Vec<Option<CheckOutcome>> = vec![None; dns_resolvers.len()];
    let mut failed_servers: Vec<(SocketAddr, &str)> = Vec::new();

    while let Some(joined) = tasks.join_next().await {
        let Ok((index, server, outcome)) = joined else {
            continue;
        };

        if matches!(outcome, CheckOutcome::Ok) {
            print_status(server, "OK");
        } else {
            print_status(server, "FAIL");
            failed_servers.push((server, outcome.reason()));
        }
        outcomes[index] = Some(outcome);
    }

    resolver_pool.shutdown();

    if !failed_servers.is_empty() {
        println!("DNS Resolvers:");
        for (server, reason) in failed_servers {
            println!("Removed {server} - {reason}");
        }
    }

    println!();

    dns_resolvers
        .iter()
        .zip(outcomes)
        .filter_map(|(&server, outcome)| {
            matches!(outcome, Some(CheckOutcome::Ok)).then_some(server)
        })
        .collect()
}

