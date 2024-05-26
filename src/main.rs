mod dns;
mod io;

use anyhow::{bail, Result};
use colored::Colorize;
use dns::network_check;
use dns::resolver::resolve_domain;
use dns::types::QueryResponse;
use io::cli::CliArgs;
use rand::seq::IteratorRandom;
use rand::thread_rng;
use std::net::UdpSocket;
use std::time::Duration;

use crate::dns::types::ResponseType;
use crate::io::{cli, wordlist};

fn main() -> Result<()> {
    let args = cli::get_parsed_args();

    if !args.no_welcome {
        cli::print_ascii_art();
        cli::print_options(&args);
    }

    let socket = setup_socket()?;
    let subdomains = wordlist::read_wordlist(args.wordlist.as_str())?;
    let record_query_type = &args.query_type;

    let mut dns_resolvers: Vec<&str> = args.dns_resolvers.split(',').collect();
    validate_dns_resolvers(&args, &mut dns_resolvers)?;
    if dns_resolvers.is_empty() {
        bail!("No DNS Resolvers in list! At least one resolver must be working!");
    }

    let total_subdomains = subdomains.len() as u64;
    let progress_bar = cli::setup_progress_bar(subdomains.len() as u64);

    let mut found_count = 0;

    match resolve_domain(
        &socket,
        dns_resolvers[0],
        &args.target_domain,
        record_query_type,
    ) {
        Ok(response) => {
            let response_data_string = create_query_response_string(&response);
            print_query_result(&args, "", dns_resolvers[0], &response_data_string);
            found_count += 1;
        }
        Err(err) => {
            print_query_error(&args, "", dns_resolvers[0], &err);
        }
    }

    for (index, subdomain) in subdomains.iter().enumerate() {
        let query_resolver = select_random_resolver(&dns_resolvers)?;

        let fqdn = format!("{}.{}", subdomain, args.target_domain);
        match resolve_domain(&socket, query_resolver, &fqdn, record_query_type) {
            Ok(response) => {
                let response_data_string = create_query_response_string(&response);
                print_query_result(&args, subdomain, dns_resolvers[0], &response_data_string);
                found_count += 1;
            }
            Err(err) => {
                print_query_error(&args, subdomain, query_resolver, &err);
            }
        }

        cli::update_progress_bar(&progress_bar, &index, &total_subdomains);
    }

    progress_bar.finish_and_clear();

    println!("\nDone! Found {} domains", found_count);
    Ok(())
}

fn setup_socket() -> Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(socket)
}

fn validate_dns_resolvers(args: &CliArgs, dns_resolvers: &mut Vec<&str>) -> Result<()> {
    if !args.no_dns_check {
        match network_check::check_server_list(dns_resolvers) {
            Ok(_) => {
                let status = format!("[{}]", "OK".green());
                println!("DNS Resolvers: {:>width$}\n", status, width = 16);
            }
            Err(failed_servers) => {
                println!(
                    "{}: {}\n",
                    "Removed DNS resolvers with errors".yellow(),
                    failed_servers.join(", ")
                );
            }
        }
    }

    Ok(())
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
    let mut query_responses = String::new();

    for (index, response) in query_result.iter().enumerate() {
        let query_type_formatted = response.query_type.to_string().bold();
        let content_string = match &response.response_content {
            ResponseType::IPv4(ip) => format!("[{} {}]", query_type_formatted, ip),
            ResponseType::IPv6(ip) => format!("[{} {}]", query_type_formatted, ip),
            ResponseType::MX(mx) => {
                format!("[{} {} {}]", query_type_formatted, mx.priority, mx.domain)
            }
            ResponseType::TXT(txt_data) => format!("[{} {}]", query_type_formatted, txt_data),
            ResponseType::CanonicalName(domain) => format!("[{} {}]", query_type_formatted, domain),
        };

        if index != 0 {
            query_responses.push(',');
        }
        query_responses.push_str(&content_string);
    }

    format!("[{}]", query_responses)
}

fn print_query_result(args: &CliArgs, subdomain: &str, resolver: &str, response: &str) {
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
        println!("\r[{}] {} {}", status, domain, response);
    }
}

fn print_query_error(args: &CliArgs, subdomain: &str, resolver: &str, err: &anyhow::Error) {
    if args.verbose {
        let domain = format!("{}.{}", subdomain.red().bold(), args.target_domain.blue());
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
