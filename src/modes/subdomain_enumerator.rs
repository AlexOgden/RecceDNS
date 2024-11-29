use anyhow::{anyhow, Result};
use colored::Colorize;
use rand::Rng;
use std::collections::HashSet;
use std::io::{self, Write};
use std::sync::atomic::Ordering;
use std::{thread, time::Duration, time::Instant};

use crate::dns::{
    error::DnsError,
    protocol::{QueryType, RData, ResourceRecord},
    resolver::resolve_domain,
    resolver_selector,
    resolver_selector::ResolverSelector,
};
use crate::io::json::Output;
use crate::io::{
    cli::{self, CommandArgs},
    interrupt,
    json::DnsEnumerationOutput,
    validation::get_correct_query_types,
    wordlist,
};
use crate::timing::stats::QueryTimer;

const DEFAULT_QUERY_TYPES: &[QueryType] =
    &[QueryType::A, QueryType::AAAA, QueryType::MX, QueryType::TXT];

struct EnumerationState {
    current_query_results: HashSet<ResourceRecord>,
    all_query_responses: Vec<ResourceRecord>,
    failed_subdomains: HashSet<String>,
    found_subdomain_count: u32,
    results_output: Option<DnsEnumerationOutput>,
}

pub fn enumerate_subdomains(cmd_args: &CommandArgs, dns_resolver_list: &[&str]) -> Result<()> {
    let interrupted = interrupt::initialize_interrupt_handler()?;

    if handle_wildcard_domain(cmd_args, dns_resolver_list)? {
        return Ok(());
    }

    let query_types = get_correct_query_types(&cmd_args.query_types, DEFAULT_QUERY_TYPES);
    let subdomain_list = read_wordlist(cmd_args.wordlist.as_ref())?;
    let mut resolver_selector = resolver_selector::get_selector(cmd_args, dns_resolver_list);

    let total_subdomains = subdomain_list.len() as u64;
    let progress_bar = cli::setup_progress_bar(total_subdomains);

    let mut query_timer = QueryTimer::new(!cmd_args.no_query_stats);
    let start_time = Instant::now();

    let mut context = EnumerationState {
        current_query_results: HashSet::new(),
        all_query_responses: Vec::new(),
        failed_subdomains: HashSet::new(),
        found_subdomain_count: 0,
        results_output: cmd_args
            .json
            .as_ref()
            .map(|_| DnsEnumerationOutput::new(cmd_args.target.clone())),
    };

    for (index, subdomain) in subdomain_list.iter().enumerate() {
        if interrupted.load(Ordering::SeqCst) {
            cli::clear_line();
            println!("[{}] Interrupted by user", "!".red());
            break;
        }

        process_subdomain(
            cmd_args,
            &mut *resolver_selector,
            &query_types,
            subdomain,
            &mut query_timer,
            &mut context,
        )?;

        cli::update_progress_bar(&progress_bar, index, total_subdomains);

        if let Some(delay_ms) = &cmd_args.delay {
            if let Some(sleep_delay) = delay_ms.get_delay().checked_sub(0) {
                thread::sleep(Duration::from_millis(sleep_delay));
            }
        }
    }

    progress_bar.finish_and_clear();

    if !interrupted.load(Ordering::SeqCst) {
        retry_failed_queries(
            cmd_args,
            &mut *resolver_selector,
            &query_types,
            &mut query_timer,
            &mut context,
        )?;
    }

    let elapsed_time = start_time.elapsed();

    cli::clear_line();
    println!(
        "[{}] Done! Found {} subdomains in {:.2?}",
        "~".green(),
        context.found_subdomain_count.to_string().bold(),
        elapsed_time
    );

    if let Some(avg) = query_timer.average() {
        println!(
            "[{}] Average query time: {} ms",
            "~".green(),
            avg.to_string().bold().bright_yellow()
        );
    }

    if let (Some(output), Some(file)) = (&context.results_output, &cmd_args.json) {
        output.write_to_file(file)?;
    }

    Ok(())
}

fn process_subdomain(
    cmd_args: &CommandArgs,
    resolver_selector: &mut dyn ResolverSelector,
    query_types: &[QueryType],
    subdomain: &str,
    query_timer: &mut QueryTimer,
    context: &mut EnumerationState,
) -> Result<()> {
    let fqdn = format!("{}.{}", subdomain, cmd_args.target);
    resolve_and_handle(
        cmd_args,
        resolver_selector,
        query_types,
        &fqdn,
        query_timer,
        context,
        subdomain,
    )
}

fn retry_failed_queries(
    cmd_args: &CommandArgs,
    resolver_selector: &mut dyn ResolverSelector,
    query_types: &[QueryType],
    query_timer: &mut QueryTimer,
    context: &mut EnumerationState,
) -> Result<()> {
    if context.failed_subdomains.is_empty() {
        return Ok(());
    }

    let failed = std::mem::take(&mut context.failed_subdomains);
    println!(
        "\n[{}] Retrying {} failed queries",
        "!".bright_yellow(),
        failed.len().to_string().bold()
    );

    let retry_count = u32::try_from(failed.len()).unwrap_or(0);

    for subdomain in failed {
        let fqdn = format!("{}.{}", subdomain, cmd_args.target);
        resolve_and_handle(
            cmd_args,
            resolver_selector,
            query_types,
            &fqdn,
            query_timer,
            context,
            &subdomain,
        )?;
        thread::sleep(Duration::from_millis(50));
    }

    if retry_count > 0 {
        println!("Failed to resolve {retry_count} subdomains after retries");
    }

    Ok(())
}

fn resolve_and_handle(
    cmd_args: &CommandArgs,
    resolver_selector: &mut dyn ResolverSelector,
    query_types: &[QueryType],
    fqdn: &str,
    query_timer: &mut QueryTimer,
    context: &mut EnumerationState,
    subdomain: &str,
) -> Result<()> {
    let resolver = resolver_selector.select()?;
    context.current_query_results.clear();
    context.all_query_responses.clear();

    for query_type in query_types {
        query_timer.start();
        let result = resolve_domain(
            resolver,
            fqdn,
            query_type,
            &cmd_args.transport_protocol,
            !cmd_args.no_recursion,
        );
        query_timer.stop();

        match result {
            Ok(response) => {
                context.current_query_results.extend(response.answers);
            }
            Err(err) => {
                if !cmd_args.no_retry
                    && !matches!(err, DnsError::NoRecordsFound | DnsError::NonExistentDomain)
                {
                    context.failed_subdomains.insert(subdomain.to_string());
                }

                print_query_error(cmd_args, subdomain, resolver, &err, false);
                break;
            }
        }
    }

    if !context.current_query_results.is_empty() {
        context
            .all_query_responses
            .extend(context.current_query_results.drain());
        context
            .all_query_responses
            .sort_by_key(|r| r.data.to_qtype());

        if let Some(output) = &mut context.results_output {
            context
                .all_query_responses
                .iter()
                .for_each(|r| output.add_result(r.clone()));
        }

        let response_str = create_query_response_string(&context.all_query_responses);
        print_query_result(cmd_args, subdomain, resolver, &response_str);
        context.found_subdomain_count += 1;
    }

    Ok(())
}

fn read_wordlist(wordlist_path: Option<&String>) -> Result<Vec<String>> {
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
                let fqdn = format!("{}.{}", random_subdomain, args.target);

                resolve_domain(
                    query_resolver,
                    &fqdn,
                    &QueryType::A,
                    &args.transport_protocol,
                    true,
                )
                .is_err()
            });

            Ok(!is_wildcard) // If any random subdomain fails to resolve, it's not a wildcard domain
        },
    )
}

fn create_query_response_string(query_result: &[ResourceRecord]) -> String {
    let query_responses: String = query_result
        .iter()
        .map(|response| {
            let query_type_formatted = response.data.to_qtype().to_string().bold();
            match &response.data {
                RData::A(record) => format!("[{query_type_formatted} {record}]"),
                RData::AAAA(record) => format!("[{query_type_formatted} {record}]"),
                RData::TXT(txt_data) => format!("[{query_type_formatted} {txt_data}]"),
                RData::CNAME(domain) | RData::NS(domain) | RData::PTR(domain) => {
                    format!("[{query_type_formatted} {domain}]")
                }
                RData::MX {
                    preference,
                    exchange,
                } => {
                    format!("[{query_type_formatted} {preference} {exchange}]")
                }
                RData::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                } => format!(
                    "[{query_type_formatted} {mname} {rname} {serial} {refresh} {retry} {expire} {minimum}]"
                ),
                RData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                } => format!(
                    "[{query_type_formatted} {priority} {weight} {port} {target}]"
                ),
                RData::DNSKEY { flags, protocol, algorithm, public_key: _ } => {
                    format!("[{query_type_formatted} {flags} {protocol} {algorithm}]")
                }
                RData::Unknown { qtype, data_len } => {
                    format!("[{qtype} Unknown {data_len} bytes]")
                }
            }
        })
        .collect::<Vec<_>>()
        .join(",");

    format!("[{query_responses}]")
}

fn print_query_result(args: &CommandArgs, subdomain: &str, resolver: &str, response: &str) {
    if args.quiet {
        return;
    }

    let domain = format!(
        "{}.{}",
        subdomain.cyan().bold(),
        args.target.blue().italic()
    );
    let status = "+".green();
    let mut message = format!("\r\x1b[2K[{status}] {domain}");

    if args.verbose || args.show_resolver {
        message.push_str(&format!(" [resolver: {}]", resolver.magenta()));
    }
    if !args.no_print_records {
        message.push_str(&format!(" {response}"));
    }

    println!("{message}");
}

fn print_query_error(
    args: &CommandArgs,
    subdomain: &str,
    resolver: &str,
    error: &DnsError,
    retry: bool,
) {
    if (!args.verbose
        && !retry
        && matches!(
            error,
            DnsError::NoRecordsFound | DnsError::NonExistentDomain
        ))
        || args.quiet
    {
        return;
    }

    let domain = format!("{}.{}", subdomain.red().bold(), args.target.blue().italic());
    let status = "-".red();
    let mut message = format!("\r\x1b[2K[{status}] {domain}");

    if args.show_resolver {
        message.push_str(&format!(" [resolver: {}]", resolver.magenta()));
    }
    message.push_str(&format!(" {error}"));

    eprintln!("{message}");
}
