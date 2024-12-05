use anyhow::{anyhow, Result};
use colored::Colorize;
use rand::Rng;
use std::{
    collections::HashSet,
    io::{self, Write},
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

use crate::{
    dns::{
        error::DnsError,
        format::create_query_response_string,
        protocol::{QueryType, ResourceRecord},
        resolver::resolve_domain,
        resolver_selector::{self, ResolverSelector},
    },
    io::{
        cli::{self, CommandArgs},
        interrupt,
        json::{DnsEnumerationOutput, Output},
        validation::get_correct_query_types,
        wordlist,
    },
    log_error, log_info, log_question, log_success, log_warn,
    timing::stats::QueryTimer,
};

const DEFAULT_QUERY_TYPES: &[QueryType] =
    &[QueryType::A, QueryType::AAAA, QueryType::MX, QueryType::TXT];

struct EnumerationState {
    all_query_responses: HashSet<ResourceRecord>,
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
        all_query_responses: HashSet::new(),
        failed_subdomains: HashSet::new(),
        found_subdomain_count: 0,
        results_output: cmd_args
            .json
            .as_ref()
            .map(|_| DnsEnumerationOutput::new(cmd_args.target.clone())),
    };

    for (index, subdomain) in subdomain_list.iter().enumerate() {
        if interrupted.load(Ordering::SeqCst) {
            log_warn!("Enumeration interrupted by user");
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

    log_info!(
        format!(
            "Done! Found {} subdomains in {:.2?}",
            context.found_subdomain_count.to_string().bold(),
            elapsed_time
        ),
        true
    );

    if let Some(avg) = query_timer.average() {
        log_info!(format!(
            "Average query time: {} ms",
            avg.to_string().bold().bright_yellow()
        ));
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
    if !context.failed_subdomains.is_empty() {
        let count = context.failed_subdomains.len();

        log_warn!(
            format!("Retrying {} failed queries", count.to_string().bold()),
            true
        );
    }

    let mut retry_failed_count: u32 = 0;
    let retries: Vec<String> = context.failed_subdomains.drain().collect();

    for subdomain in retries {
        let query_resolver = resolver_selector.select()?;
        let fqdn = format!("{}.{}", subdomain, cmd_args.target);

        for query_type in query_types {
            query_timer.start();
            let query_result = resolve_domain(
                query_resolver,
                &fqdn,
                query_type,
                &cmd_args.transport_protocol,
                !&cmd_args.no_recursion,
            );
            query_timer.stop();

            match query_result {
                Ok(response) => {
                    context.all_query_responses.extend(response.answers);
                }
                Err(err) => {
                    if !matches!(err, DnsError::NoRecordsFound | DnsError::NonExistentDomain) {
                        retry_failed_count += 1;
                        context.failed_subdomains.insert(subdomain.clone());
                    }

                    print_query_error(cmd_args, &subdomain, query_resolver, &err, true);

                    if matches!(err, DnsError::NonExistentDomain) {
                        break;
                    }
                }
            }
        }

        if !context.all_query_responses.is_empty() {
            if let Some(output) = &mut context.results_output {
                for response in &context.all_query_responses {
                    output.add_result(response.clone());
                }
            }

            let response_str = create_query_response_string(&context.all_query_responses);
            print_query_result(cmd_args, &subdomain, query_resolver, &response_str);
            context.found_subdomain_count += 1;
        }

        thread::sleep(Duration::from_millis(50));
    }

    if retry_failed_count > 0 {
        log_error!(format!(
            "Failed to resolve {retry_failed_count} subdomains after retries",
            retry_failed_count = retry_failed_count.to_string().bold()
        ));
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
                context.all_query_responses.extend(response.answers);
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

    if !context.all_query_responses.is_empty() {
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
        log_warn!("Warning: Wildcard domain detected. Results may include false positives!");
        log_question!("Do you want to continue? (y/n): ");

        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");

        if !matches!(input.trim().to_lowercase().as_str(), "y") {
            log_error!("Aborting due to wildcard domain detection.");
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

fn print_query_result(args: &CommandArgs, subdomain: &str, resolver: &str, response: &str) {
    if args.quiet {
        return;
    }

    let domain = format!(
        "{}.{}",
        subdomain.cyan().bold(),
        args.target.blue().italic()
    );

    let mut message = domain;

    if args.verbose || args.show_resolver {
        message.push_str(&format!(" [resolver: {}]", resolver.magenta()));
    }
    if !args.no_print_records {
        message.push_str(&format!(" {response}"));
    }

    log_success!(message);
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
    let mut message = domain;

    if args.show_resolver {
        message.push_str(&format!(" [resolver: {}]", resolver.magenta()));
    }
    message.push_str(&format!(" {error}"));

    log_error!(message);
}
