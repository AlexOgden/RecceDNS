use anyhow::{anyhow, Result};
use colored::Colorize;
use rand::Rng;
use std::collections::HashSet;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::dns::error::DnsError;
use crate::dns::protocol::RData;
use crate::dns::resolver_selector;
use crate::dns::{
    protocol::{QueryType, ResourceRecord},
    resolver::resolve_domain,
    resolver_selector::ResolverSelector,
};
use crate::io::json::EnumerationOutput;
use crate::io::{cli, cli::CommandArgs, wordlist};
use crate::timing::stats::QueryTimer;
use std::time::Instant;

struct EnumerationContext {
    current_query_results: HashSet<ResourceRecord>,
    all_query_responses: Vec<ResourceRecord>,
    failed_subdomains: HashSet<String>,
    found_subdomain_count: u32,
    results_output: Option<EnumerationOutput>,
}

pub fn enumerate_subdomains(command_args: &CommandArgs, dns_resolver_list: &[&str]) -> Result<()> {
    let interrupted = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let interrupted_clone = Arc::clone(&interrupted);
        move || {
            interrupted_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    })?;

    if handle_wildcard_domain(command_args, dns_resolver_list)? {
        return Ok(());
    }

    let query_types = get_query_types(&command_args.query_type);
    let subdomain_list = read_wordlist(&command_args.wordlist)?;
    let mut resolver_selector_instance = setup_resolver_selector(command_args);

    let total_subdomains = subdomain_list.len() as u64;
    let progress_bar = cli::setup_progress_bar(total_subdomains);

    let mut query_timer = QueryTimer::new(!command_args.no_query_stats);
    let start_time = Instant::now();

    let mut context = EnumerationContext {
        current_query_results: HashSet::new(),
        all_query_responses: Vec::new(),
        failed_subdomains: HashSet::new(),
        found_subdomain_count: 0,
        results_output: command_args
            .json
            .as_ref()
            .map(|_| EnumerationOutput::new(command_args.target_domain.clone())),
    };

    for (index, subdomain) in subdomain_list.iter().enumerate() {
        if interrupted.load(Ordering::SeqCst) {
            cli::clear_line();
            println!("[{}] Interrupted by user", "!".red());
            break;
        }
        process_subdomain(
            command_args,
            dns_resolver_list,
            &mut *resolver_selector_instance,
            query_types,
            subdomain,
            &mut query_timer,
            &mut context,
        )?;

        cli::update_progress_bar(&progress_bar, index, total_subdomains);

        if let Some(delay_ms) = &command_args.delay {
            let sleep_delay = delay_ms.get_delay();
            if sleep_delay > 0 {
                thread::sleep(Duration::from_millis(sleep_delay));
            }
        }
    }

    progress_bar.finish_and_clear();

    if !interrupted.load(Ordering::SeqCst) {
        retry_failed_queries(
            command_args,
            dns_resolver_list,
            &mut *resolver_selector_instance,
            query_types,
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
    if let Some(query_average_ms) = query_timer.average() {
        println!(
            "[{}] Average query time: {} ms",
            "~".green(),
            query_average_ms.to_string().bold().bright_yellow()
        );
    }

    // Write the results to the specified output file if provided
    if let (Some(output), Some(output_file)) = (&context.results_output, &command_args.json) {
        output.write_to_file(output_file)?;
    }

    Ok(())
}

fn process_subdomain(
    command_args: &CommandArgs,
    dns_resolver_list: &[&str],
    resolver_selector_instance: &mut dyn ResolverSelector,
    query_types: &[QueryType],
    subdomain: &str,
    query_timer: &mut QueryTimer,
    context: &mut EnumerationContext,
) -> Result<()> {
    let query_resolver = resolver_selector_instance.select(dns_resolver_list)?;
    let fqdn = format!("{}.{}", subdomain, command_args.target_domain);

    context.current_query_results.clear();
    context.all_query_responses.clear();

    for query_type in query_types {
        query_timer.start();
        let query_result = resolve_domain(
            query_resolver,
            &fqdn,
            query_type,
            &command_args.transport_protocol,
        );
        query_timer.stop();

        match query_result {
            Ok(response) => {
                context.current_query_results.extend(response.answers);
            }
            Err(err) => {
                if !command_args.no_retry
                    && !matches!(err, DnsError::NoRecordsFound | DnsError::NonExistentDomain)
                {
                    context.failed_subdomains.insert(subdomain.to_string());
                }
                print_query_error(command_args, subdomain, query_resolver, &err, false);
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
        let response_data_string = create_query_response_string(&context.all_query_responses);

        if let Some(output) = &mut context.results_output {
            for response in &context.all_query_responses {
                output.add_result(response.clone());
            }
        }

        print_query_result(
            command_args,
            subdomain,
            query_resolver,
            &response_data_string,
        );
        context.found_subdomain_count += 1;
    }

    Ok(())
}

fn retry_failed_queries(
    command_args: &CommandArgs,
    dns_resolver_list: &[&str],
    resolver_selector_instance: &mut dyn ResolverSelector,
    query_types: &[QueryType],
    query_timer: &mut QueryTimer,
    context: &mut EnumerationContext,
) -> Result<()> {
    if !context.failed_subdomains.is_empty() {
        let count = context.failed_subdomains.len();
        println!(
            "\n[{}] Retrying {} failed queries",
            "!".bright_yellow(),
            count.to_string().bold()
        );
    }

    let mut retry_failed_count: u32 = 0;
    let retries: Vec<String> = context.failed_subdomains.iter().cloned().collect();
    context.failed_subdomains.clear();

    for subdomain in retries {
        let query_resolver = resolver_selector_instance.select(dns_resolver_list)?;
        let fqdn = format!("{}.{}", subdomain, command_args.target_domain);

        context.current_query_results.clear();

        for query_type in query_types {
            query_timer.start();
            let query_result = resolve_domain(
                query_resolver,
                &fqdn,
                query_type,
                &command_args.transport_protocol,
            );
            query_timer.stop();

            match query_result {
                Ok(response) => {
                    context.current_query_results.extend(response.answers);
                }
                Err(err) => {
                    if !matches!(err, DnsError::NoRecordsFound | DnsError::NonExistentDomain) {
                        retry_failed_count += 1;
                        context.failed_subdomains.insert(subdomain.clone());
                    }

                    print_query_error(command_args, &subdomain, query_resolver, &err, true);

                    if matches!(err, DnsError::NonExistentDomain) {
                        break;
                    }
                }
            }
        }

        if !context.current_query_results.is_empty() {
            context.all_query_responses.clear();
            context
                .all_query_responses
                .extend(context.current_query_results.drain());
            context
                .all_query_responses
                .sort_by_key(|r| r.data.to_qtype());
            let response_data_string = create_query_response_string(&context.all_query_responses);

            if let Some(output) = &mut context.results_output {
                for response in &context.all_query_responses {
                    output.add_result(response.clone());
                }
            }

            print_query_result(
                command_args,
                &subdomain,
                query_resolver,
                &response_data_string,
            );
            context.found_subdomain_count += 1;
        }

        thread::sleep(Duration::from_millis(50));
    }

    if retry_failed_count > 0 {
        println!("Failed to resolve {retry_failed_count} subdomains after retries");
    }

    Ok(())
}

const fn get_query_types(query_type: &QueryType) -> &[QueryType] {
    match query_type {
        QueryType::ANY => &[QueryType::A, QueryType::AAAA, QueryType::MX, QueryType::TXT],
        _ => std::slice::from_ref(query_type),
    }
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

fn create_query_response_string(query_result: &[ResourceRecord]) -> String {
    let query_responses: String = query_result
        .iter()
        .map(|response| {
            let query_type_formatted = response.data.to_qtype().to_string().bold();
            match &response.data {
                RData::A(record) => format!("[{query_type_formatted} {record}]"),
                RData::AAAA(record) => format!("[{query_type_formatted} {record}]"),
                RData::TXT(txt_data) => format!("[{query_type_formatted} {txt_data}]"),
                RData::CNAME(domain) | RData::NS(domain) => {
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
                RData::DNSKEY { .. } => {
                    format!("[{} Enabled]", "DNSSEC".bold().bright_cyan())
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
        args.target_domain.blue().italic()
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

    let domain = format!(
        "{}.{}",
        subdomain.red().bold(),
        args.target_domain.blue().italic()
    );
    let status = "-".red();
    let mut message = format!("\r\x1b[2K[{status}] {domain}");

    if args.show_resolver {
        message.push_str(&format!(" [resolver: {}]", resolver.magenta()));
    }
    message.push_str(&format!(" {error}"));

    eprintln!("{message}");
}
