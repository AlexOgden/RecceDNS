use anyhow::{anyhow, Result};
use colored::Colorize;
use rand::Rng;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use crate::dns::resolver_selector;
use crate::dns::{
    protocol::{DnsQueryResponse, DnsRecord, QueryType},
    resolver::resolve_domain,
    resolver_selector::ResolverSelector,
};
use crate::io::{cli, cli::CommandArgs, wordlist};

pub fn enumerate_subdomains(args: &CommandArgs, dns_resolvers: &[&str]) -> Result<()> {
    let record_query_type = &args.query_type;
    let subdomains: Vec<String>;

    if let Some(wordlist_path) = &args.wordlist {
        subdomains = wordlist::read_from_file(wordlist_path)?;
    } else {
        return Err(anyhow!(
            "Wordlist path is required for subdomain enumeration"
        ));
    }

    if handle_wildcard_domain(args, dns_resolvers)? {
        return Ok(());
    }

    let mut resolver_selector: Box<dyn ResolverSelector> = if args.use_random {
        Box::new(resolver_selector::Random)
    } else {
        Box::new(resolver_selector::Sequential::new())
    };

    let total_subdomains = subdomains.len() as u64;
    let progress_bar = cli::setup_progress_bar(subdomains.len() as u64);

    let mut found_count: u32 = 0;

    for (index, subdomain) in subdomains.iter().enumerate() {
        let query_resolver = resolver_selector.select(dns_resolvers)?;

        let fqdn = if subdomain.is_empty() {
            args.target_domain.clone()
        } else {
            format!("{}.{}", subdomain, args.target_domain)
        };

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
