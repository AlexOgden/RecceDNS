use anyhow::{anyhow, Result};
use colored::Colorize;
use rand::Rng;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use crate::dns::error::DnsError;
use crate::dns::resolver_selector;
use crate::dns::{
    protocol::{DnsQueryResponse, DnsRecord, QueryType},
    resolver::resolve_domain,
    resolver_selector::ResolverSelector,
};
use crate::io::{cli, cli::CommandArgs, wordlist};

pub fn enumerate_subdomains(args: &CommandArgs, dns_resolvers: &[&str]) -> Result<()> {
    if handle_wildcard_domain(args, dns_resolvers)? {
        return Ok(());
    }

    let record_query_type = &args.query_type;
    let subdomains: Vec<String> = read_wordlist(&args.wordlist)?;
    let mut resolver_selector = setup_resolver_selector(args);

    let total_subdomains = subdomains.len() as u64;
    let progress_bar = cli::setup_progress_bar(subdomains.len() as u64);

    let mut found_count: u32 = 0;
    let mut failed_queries: VecDeque<String> = VecDeque::new();

    for (index, subdomain) in subdomains.iter().enumerate() {
        let query_resolver = resolver_selector.select(dns_resolvers)?;
        let fqdn = format!("{}.{}", subdomain, args.target_domain);

        match resolve_domain(
            query_resolver,
            &fqdn,
            record_query_type,
            &args.transport_protocol,
        ) {
            Ok(mut response) => {
                response.sort_by(|a, b| a.query_type.cmp(&b.query_type));

                let response_data_string = create_query_response_string(&response);
                print_query_result(args, subdomain, query_resolver, &response_data_string);
                found_count += 1;
            }
            Err(err) => {
                if !matches!(err, DnsError::NoRecordsFound) && !args.no_retry {
                    failed_queries.push_back(subdomain.clone());
                }
                print_query_error(args, subdomain, query_resolver, &err, false);
            }
        }

        cli::update_progress_bar(&progress_bar, index, total_subdomains);

        if let Some(delay_ms) = args.delay {
            if delay_ms > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
        }
    }

    // Retry failed queries
    if !failed_queries.is_empty() {
        let count = failed_queries.len();
        progress_bar.finish_and_clear();
        println!(
            "\n[{}] Retrying {} failed queries",
            "!".bright_yellow(),
            count.to_string().bold()
        );
    }
    let mut retry_failed_count: u32 = 0;
    while let Some(subdomain) = failed_queries.pop_front() {
        let query_resolver = resolver_selector.select(dns_resolvers)?;
        let fqdn = format!("{}.{}", subdomain, args.target_domain);

        match resolve_domain(
            query_resolver,
            &fqdn,
            record_query_type,
            &args.transport_protocol,
        ) {
            Ok(mut response) => {
                response.sort_by(|a, b| a.query_type.cmp(&b.query_type));

                let response_data_string = create_query_response_string(&response);
                print_query_result(args, &subdomain, query_resolver, &response_data_string);
                found_count += 1;
            }
            Err(err) => {
                if !matches!(err, DnsError::NoRecordsFound) {
                    retry_failed_count += 1;
                }
                print_query_error(args, &subdomain, query_resolver, &err, true);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    println!(
        "\n[{}] Done! Found {} subdomains",
        "~".green(),
        found_count.to_string().bold()
    );
    if retry_failed_count > 0 {
        println!("Failed to resolve {retry_failed_count} subdomains after retries");
    }
    Ok(())
}

fn setup_resolver_selector(args: &CommandArgs) -> Box<dyn ResolverSelector> {
    if args.use_random {
        Box::new(resolver_selector::Random)
    } else {
        Box::new(resolver_selector::Sequential::new())
    }
}

fn read_wordlist(wordlist_path: &Option<String>) -> Result<Vec<String>> {
    if let Some(path) = wordlist_path {
        Ok(wordlist::read_from_file(path)?)
    } else {
        Err(anyhow!(
            "Wordlist path is required for subdomain enumeration"
        ))
    }
}

fn handle_wildcard_domain(args: &CommandArgs, dns_resolvers: &[&str]) -> Result<bool> {
    let is_wildcard = check_wildcard_domain(args, dns_resolvers)?;
    if is_wildcard {
        println!(
            "[{}] Warning: Wildcard domain detected. Results may include false positives!",
            "!".yellow()
        );
        print!("[{}] Do you want to continue? (y/n): ", "?".cyan());
        io::stdout().flush()?; // Ensure the prompt is displayed before reading input
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("[{}] Aborting due to wildcard domain detection.", "!".red());
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_wildcard_domain(args: &CommandArgs, dns_resolvers: &[&str]) -> Result<bool> {
    let mut rng = rand::thread_rng();
    let max_label_length: u8 = 63;
    let attempts: u8 = 3;

    if dns_resolvers.is_empty() {
        return Err(anyhow!("No DNS resolvers available"));
    }

    let query_resolver = dns_resolvers.first().unwrap();

    for _ in 0..attempts {
        let random_length = rng.gen_range(10..=max_label_length);
        let random_subdomain: String = (0..random_length)
            .map(|_| rng.gen_range('a'..='z'))
            .collect();
        let fqdn = format!("{}.{}", random_subdomain, args.target_domain);

        if resolve_domain(
            query_resolver,
            &fqdn,
            &QueryType::A,
            &args.transport_protocol,
        )
        .is_err()
        {
            return Ok(false); // If any random subdomain fails to resolve, it's not a wildcard domain
        }
    }

    Ok(true) // All random subdomains resolved, indicating a wildcard domain
}

fn create_query_response_string(query_result: &[DnsQueryResponse]) -> String {
    let query_responses: String = query_result
        .iter()
        .map(|response| {
            let query_type_formatted = response.query_type.to_string().bold();
            match &response.response_content {
                DnsRecord::A(record) => format!("[{} {}]", query_type_formatted, record.addr),
                DnsRecord::AAAA(record) => format!("[{} {}]", query_type_formatted, record.addr),
                DnsRecord::TXT(txt_data) => format!("[{query_type_formatted} {0}]", txt_data.data),
                DnsRecord::CNAME(domain) | DnsRecord::NS(domain) => {
                    format!("[{query_type_formatted} {0}]", domain.data)
                }
                DnsRecord::MX(mx) => {
                    format!("[{} {} {}]", query_type_formatted, mx.priority, mx.domain)
                }
                DnsRecord::SOA(soa) => format!(
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
                DnsRecord::SRV(srv) => format!(
                    "[{} {} {} {} {}]",
                    query_type_formatted, srv.priority, srv.weight, srv.port, srv.target
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
        if args.no_print_records {
            println!(
                "\r\x1b[2K[{}] {} [resolver: {}]",
                status,
                domain,
                resolver.magenta()
            );
        } else {
            println!(
                "\r\x1b[2K[{}] {} [resolver: {}] {}",
                status,
                domain,
                resolver.magenta(),
                response
            );
        }
    } else if args.no_print_records {
        println!("\r\x1b[2K[{status}] {domain}");
    } else {
        println!("\r\x1b[2K[{status}] {domain} {response}");
    }
}

fn print_query_error(
    args: &CommandArgs,
    subdomain: &str,
    resolver: &str,
    error: &DnsError,
    retry: bool,
) {
    let domain = format!(
        "{}.{}",
        subdomain.red().bold(),
        args.target_domain.blue().italic()
    );

    if args.verbose || retry {
        if args.show_resolver {
            eprintln!(
                "\r\x1b[2K[{}] {} [resolver: {}] {}",
                "-".red(),
                domain,
                resolver.magenta(),
                error
            );
        } else {
            eprintln!("\r\x1b[2K[{}] {} {}", "-".red(), domain, error);
        }
    } else if !matches!(error, DnsError::NoRecordsFound) {
        // Print the error message if it's not NoRecordsFound, even if verbose is off
        eprintln!("\r\x1b[2K[{}] {} {}", "-".red(), domain, error);
    }
}
