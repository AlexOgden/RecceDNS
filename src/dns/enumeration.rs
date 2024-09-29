use anyhow::{ensure, Result};
use colored::Colorize;
use rand::seq::IteratorRandom;
use rand::thread_rng;
use std::thread;
use std::time::Duration;

use crate::dns::network_check;
use crate::dns::resolver::resolve_domain;
use crate::dns::types::{QueryResponse, ResponseType};
use crate::io::cli::CommandArgs;
use crate::io::{cli, wordlist};

pub fn enumerate_subdomains(args: &CommandArgs) -> Result<()> {
    let subdomains = wordlist::read_from_file(args.wordlist.as_str())?;
    let record_query_type = &args.query_type;

    let mut dns_resolvers: Vec<&str> = args.dns_resolvers.split(',').collect();
    validate_dns_resolvers(args, &mut dns_resolvers);
    ensure!(
        !dns_resolvers.is_empty(),
        "No DNS Resolvers in list! At least one resolver must be working!"
    );

    let total_subdomains = subdomains.len() as u64;
    let progress_bar = cli::setup_progress_bar(subdomains.len() as u64);

    let mut found_count: u32 = 0;

    for (index, subdomain) in subdomains.iter().enumerate() {
        let query_resolver = select_random_resolver(&dns_resolvers)?;

        let fqdn = if subdomain.is_empty() {
            args.target_domain.clone()
        } else {
            format!("{}.{}", subdomain, args.target_domain)
        };

        match resolve_domain(query_resolver, &fqdn, record_query_type) {
            Ok(response) => {
                let response_data_string = create_query_response_string(&response);
                print_query_result(args, subdomain, query_resolver, &response_data_string);
                found_count += 1;
            }
            Err(err) => {
                print_query_error(args, subdomain, query_resolver, &err);
            }
        }

        cli::update_progress_bar(&progress_bar, index, total_subdomains);

        if let Some(delay_ms) = args.delay {
            if delay_ms > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
        }
    }

    progress_bar.finish_and_clear();

    println!("\nDone! Found {found_count} subdomains");
    Ok(())
}

fn validate_dns_resolvers(args: &CommandArgs, dns_resolvers: &mut Vec<&str>) {
    if !args.no_dns_check {
        match network_check::check_server_list(dns_resolvers) {
            Ok(()) => {
                let status = format!("[{}]", "OK".green());
                println!("DNS Resolvers: {:>width$}\n", status, width = 16);
            }
            Err(failed_servers) => {
                println!(
                    "{}: {}\n",
                    "Removed resolvers with errors".yellow(),
                    failed_servers.join(", ")
                );
            }
        }
    }
}

fn select_random_resolver<'a>(dns_resolvers: &'a [&str]) -> Result<&'a str> {
    let mut random_generator = thread_rng();
    dns_resolvers
        .iter()
        .choose(&mut random_generator)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("DNS Resolvers list is empty"))
}

fn create_query_response_string(query_result: &[QueryResponse]) -> String {
    let query_responses: String = query_result
        .iter()
        .map(|response| {
            let query_type_formatted = response.query_type.to_string().bold();
            match &response.response_content {
                ResponseType::IPv4(ip) => format!("[{query_type_formatted} {ip}]"),
                ResponseType::IPv6(ip) => format!("[{query_type_formatted} {ip}]"),
                ResponseType::TXT(txt_data) => format!("[{query_type_formatted} {txt_data}]"),
                ResponseType::CNAME(domain) => format!("[{query_type_formatted} {domain}]"),
                ResponseType::MX(mx) => {
                    format!("[{} {} {}]", query_type_formatted, mx.priority, mx.domain)
                }
                ResponseType::SOA(soa) => format!(
                    "[{} {} {} {} {} {} {} {}]",
                    query_type_formatted,
                    soa.mname,
                    soa.rname,
                    soa.serial,
                    soa.refresh,
                    soa.retry,
                    soa.expire,
                    soa.minimum
                ),
            }
        })
        .collect::<Vec<_>>()
        .join(",");

    format!("[{query_responses}]")
}

fn print_query_result(args: &CommandArgs, subdomain: &str, resolver: &str, response: &str) {
    let domain = format!(
        "{}.{}",
        subdomain.cyan().bold(),
        args.target_domain.blue().italic()
    );

    let status = "+".green();

    if args.verbose || args.show_resolver {
        println!(
            "\r[{}] {} [resolver: {}] {}",
            status,
            domain,
            resolver.magenta(),
            response
        );
    } else {
        println!("\r[{status}] {domain} {response}");
    }
}

fn print_query_error(args: &CommandArgs, subdomain: &str, resolver: &str, err: &anyhow::Error) {
    if args.verbose {
        let domain = format!(
            "{}.{}",
            subdomain.red().bold(),
            args.target_domain.blue().italic()
        );
        if args.show_resolver {
            eprintln!(
                "\r[{}] {} [resolver: {}] {:?}",
                "-".red(),
                domain,
                resolver.magenta(),
                err
            );
        } else {
            eprintln!("\r[{}] {} {:?}", "-".red(), domain, err);
        }
    }
}
