use anyhow::{anyhow, Result};
use colored::Colorize;
use rand::Rng;
use std::collections::HashSet;
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
use std::time::Instant;

pub fn enumerate_subdomains(args: &CommandArgs, dns_resolvers: &[&str]) -> Result<()> {
    if handle_wildcard_domain(args, dns_resolvers)? {
        return Ok(());
    }

    let query_types = get_query_types(&args.query_type);
    let subdomains: Vec<String> = read_wordlist(&args.wordlist)?;
    let mut resolver_selector = setup_resolver_selector(args);

    let total_subdomains = subdomains.len() as u64;
    let progress_bar = cli::setup_progress_bar(total_subdomains);

    let mut found_count: u32 = 0;
    let mut failed_queries: HashSet<&String> = HashSet::new();

    let start_time = Instant::now();

    let mut all_record_results = HashSet::new();
    let mut response_data_vec: Vec<DnsQueryResponse> = Vec::new();

    for (index, subdomain) in subdomains.iter().enumerate() {
        let query_resolver = resolver_selector.select(dns_resolvers)?;
        let fqdn = format!("{}.{}", subdomain, args.target_domain);

        all_record_results.clear();

        for query_type in &query_types {
            match resolve_domain(query_resolver, &fqdn, query_type, &args.transport_protocol) {
                Ok(response) => {
                    all_record_results.extend(response);
                }
                Err(err) => {
                    if !matches!(err, DnsError::NoRecordsFound | DnsError::NonExistentDomain)
                        && !args.no_retry
                    {
                        failed_queries.insert(subdomain);
                    }
                    print_query_error(args, subdomain, query_resolver, &err, false);
                }
            }
        }

        if !all_record_results.is_empty() {
            response_data_vec.clear();
            response_data_vec.extend(all_record_results.drain());
            response_data_vec.sort_by(|a, b| a.query_type.cmp(&b.query_type));
            let response_data_string = create_query_response_string(&response_data_vec);
            print_query_result(args, subdomain, query_resolver, &response_data_string);
            found_count += 1;
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
    while let Some(subdomain) = failed_queries.iter().next() {
        let query_resolver = resolver_selector.select(dns_resolvers)?;
        let fqdn = format!("{}.{}", subdomain, args.target_domain);

        all_record_results.clear();

        for query_type in &query_types {
            match resolve_domain(query_resolver, &fqdn, query_type, &args.transport_protocol) {
                Ok(response) => {
                    all_record_results.extend(response);
                }
                Err(err) => {
                    if !matches!(err, DnsError::NoRecordsFound) {
                        retry_failed_count += 1;
                    }
                    print_query_error(args, subdomain, query_resolver, &err, true);
                }
            }
        }

        if !all_record_results.is_empty() {
            response_data_vec.clear();
            response_data_vec.extend(all_record_results.drain());
            response_data_vec.sort_by(|a, b| a.query_type.cmp(&b.query_type));
            let response_data_string = create_query_response_string(&response_data_vec);
            print_query_result(args, subdomain, query_resolver, &response_data_string);
            found_count += 1;
        }

        thread::sleep(Duration::from_millis(50));
    }

    let elapsed_time = start_time.elapsed();

    println!("\r\x1b[2K"); // Clear the progress bar
    println!(
        "[{}] Done! Found {} subdomains in {:.2?}",
        "~".green(),
        found_count.to_string().bold(),
        elapsed_time
    );
    if retry_failed_count > 0 {
        println!("Failed to resolve {retry_failed_count} subdomains after retries");
    }
    Ok(())
}

fn get_query_types(query_type: &QueryType) -> Vec<&QueryType> {
    let query_types: Vec<&QueryType> = match query_type {
        QueryType::Any => vec![
            &QueryType::A,
            &QueryType::AAAA,
            &QueryType::MX,
            &QueryType::TXT,
        ],
        _ => vec![query_type],
    };

    query_types
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
    if check_wildcard_domain(args, dns_resolvers)? {
        println!(
            "[{}] Warning: Wildcard domain detected. Results may include false positives!",
            "!".yellow()
        );
        print!("[{}] Do you want to continue? (y/n): ", "?".cyan());
        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");

        if !matches!(input.trim().to_lowercase().as_str(), "y") {
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

    dns_resolvers.first().map_or_else(
        || Err(anyhow!("No DNS resolvers available")),
        |query_resolver| {
            let is_wildcard = (0..attempts).any(|_| {
                let random_length = rng.gen_range(10..=max_label_length);
                let random_subdomain: String = (0..random_length)
                    .map(|_| rng.gen_range('a'..='z'))
                    .collect();
                let fqdn = format!("{}.{}", random_subdomain, args.target_domain);

                resolve_domain(
                    query_resolver,
                    &fqdn,
                    &QueryType::A,
                    &args.transport_protocol,
                )
                .is_err()
            });

            Ok(!is_wildcard) // If any random subdomain fails to resolve, it's not a wildcard domain
        },
    )
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
                DnsRecord::DNSKEY(_dnskey) => {
                    format!("[{} Enabled]", "DNSSEC".bold().bright_cyan())
                }
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
        return;
    }

    if args.no_print_records {
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

    if !args.verbose
        && !retry
        && matches!(
            error,
            DnsError::NoRecordsFound | DnsError::NonExistentDomain
        )
    {
        return;
    }

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
}
