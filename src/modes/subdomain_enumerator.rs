#![allow(clippy::future_not_send)]

use anyhow::{Result, anyhow};
use colored::Colorize;
use rand::Rng;
use std::fmt::Write;
use std::net::Ipv4Addr;
use std::{
    cmp::max,
    collections::HashSet,
    io::{self},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, time};

use crate::{
    dns::{
        async_resolver::AsyncResolver,
        error::DnsError,
        format::create_query_response_string,
        protocol::{QueryType, ResourceRecord},
        resolver_selector,
    },
    io::{
        cli::{self, CommandArgs},
        interrupt,
        json::{DnsEnumerationOutput, Output},
        logger, wordlist,
    },
    log_error, log_info, log_question, log_success, log_warn,
    network::types::TransportProtocol,
    timing::delay,
};

// A type alias for the result sent between threads.
type SubdomainResult =
    Result<(String, Ipv4Addr, HashSet<ResourceRecord>), (String, Ipv4Addr, DnsError)>;

// A type alias for the sender channel.
type SubdomainResultSender = mpsc::Sender<SubdomainResult>;

// Parameters for the worker threads.
#[derive(Clone)]
struct WorkerParams {
    connection_pool: AsyncResolver,
    tx: SubdomainResultSender,
    subdomains: Vec<String>,
    query_types: Vec<QueryType>,
    target: String,
    transport: TransportProtocol,
    dns_resolvers: Vec<Ipv4Addr>,
    use_random: bool,
    delay: Option<delay::Delay>,
}

// Default query types for subdomain enumeration if none provided.
const DEFAULT_QUERY_TYPES: &[QueryType] = &[QueryType::A, QueryType::AAAA];

#[allow(clippy::too_many_lines)]
pub async fn enumerate_subdomains(
    cmd_args: &CommandArgs,
    dns_resolver_list: &[Ipv4Addr],
) -> Result<()> {
    let interrupted = interrupt::initialize_interrupt_handler()?;

    if handle_wildcard_domain(cmd_args, dns_resolver_list).await? {
        return Ok(());
    }

    let query_types: &[QueryType] = match cmd_args.query_types.as_slice() {
        [] | [QueryType::ANY] => DEFAULT_QUERY_TYPES,
        qt => qt,
    };

    log_info!(format!(
        "Using query types: {}",
        query_types
            .iter()
            .map(|t| format!("{t:?}"))
            .collect::<Vec<String>>()
            .join(", ")
            .bold()
    ));

    // Prepare results output if JSON output is enabled.
    let mut results_output = if cmd_args.json.is_some() {
        Some(DnsEnumerationOutput::new(cmd_args.target.clone()))
    } else {
        None
    };

    let subdomain_list = read_wordlist(cmd_args.wordlist.as_ref())?;

    let num_threads = cmd_args.threads.map_or_else(
        || {
            let cpus = num_cpus::get();
            if cpus > 6 { 6 } else { max(cpus - 1, 1) }
        },
        |threads| threads,
    );

    log_info!(format!(
        "Starting subdomain enumeration with {} threads",
        num_threads.to_string().bold()
    ));

    // Split subdomain list into chunks for each thread.
    let chunk_size = subdomain_list.len().div_ceil(num_threads);
    let subdomain_chunks: Vec<Vec<String>> = if subdomain_list.len() > 10_000 {
        // For large lists, use par_chunks for better cache locality and speed.
        use rayon::prelude::*;
        subdomain_list
            .par_chunks(chunk_size)
            .map(<[String]>::to_vec)
            .collect()
    } else {
        subdomain_list
            .chunks(chunk_size)
            .map(<[String]>::to_vec)
            .collect()
    };

    // Setup progress bar.
    let total_subdomains = subdomain_list.len() as u64;
    let progress_bar = cli::setup_progress_bar(total_subdomains);

    let start_time = Instant::now();

    let buffer_size = std::cmp::min(1000, subdomain_list.len().max(1));
    let (tx, mut rx) = mpsc::channel(buffer_size);

    // Create connection pool
    let pool = AsyncResolver::new(Some(10 * num_threads)).await?;

    // Spawn worker threads.
    for chunk in subdomain_chunks {
        let worker_params = WorkerParams {
            connection_pool: pool.clone(),
            tx: tx.clone(),
            subdomains: chunk,
            query_types: query_types.to_vec(),
            target: cmd_args.target.clone(),
            transport: cmd_args.transport_protocol.clone(),
            dns_resolvers: dns_resolver_list.to_vec(),
            use_random: cmd_args.use_random,
            delay: cmd_args.delay.clone(),
        };

        tokio::spawn(process_subdomain_chunk(worker_params));
    }
    drop(tx); // Close original sender.

    // Process results from the receiver.
    let mut found_count = 0;
    let mut failed_subdomains = Vec::new();
    let mut i: u64 = 0;
    while let Some(received) = rx.recv().await {
        if interrupted.load(Ordering::SeqCst) {
            logger::clear_line();
            log_warn!("Interrupted by user");
            pool.shutdown();
            break;
        }
        match received {
            Ok((subdomain, resolver, results)) => {
                let response_str = create_query_response_string(&results);
                found_count += 1;
                print_query_result(cmd_args, &subdomain, resolver, &response_str);

                if let Some(output) = &mut results_output {
                    results.iter().for_each(|r| output.add_result(r.clone()));
                }
            }
            Err((subdomain, resolver, error)) => {
                print_query_error(cmd_args, &subdomain, resolver, &error, false);
                match error {
                    DnsError::NoRecordsFound | DnsError::NonExistentDomain => {}
                    _ => failed_subdomains.push(subdomain),
                }
            }
        }

        cli::update_progress_bar(
            &progress_bar,
            (i + 1).try_into().unwrap(),
            total_subdomains,
            Some(failed_subdomains.len()),
            cmd_args.delay.as_ref(),
        );

        i += 1;
    }

    progress_bar.finish_and_clear();

    pool.shutdown();

    if !failed_subdomains.is_empty() && !cmd_args.no_retry {
        interrupted.store(false, Ordering::SeqCst);
        // Use a new resolver pool for retries
        let retry_pool = AsyncResolver::new(Some(2 * num_threads)).await?;
        let success_retrys = process_failed_subdomains(
            cmd_args,
            &retry_pool,
            dns_resolver_list,
            failed_subdomains,
            &interrupted,
        )
        .await;
        found_count += success_retrys;
        retry_pool.shutdown();
    }

    let elapsed_time = start_time.elapsed();
    log_info!(
        format!(
            "Done! Found {} subdomains in {:.2?}",
            found_count.to_string().bold(),
            elapsed_time
        ),
        true
    );

    if let (Some(output), Some(file)) = (&results_output, &cmd_args.json) {
        output.write_to_file(file)?;
    }

    Ok(())
}

async fn process_subdomain_chunk(params: WorkerParams) {
    let pool = params.connection_pool;
    let mut resolver_selector =
        resolver_selector::get_selector(params.use_random, params.dns_resolvers.clone());

    for subdomain in params.subdomains {
        let resolver = resolver_selector
            .select()
            .unwrap_or(resolver_selector::DEFAULT_RESOLVER);
        let fqdn = format!("{}.{}", subdomain, params.target);
        let mut all_results = HashSet::new();
        let mut first_error: Option<DnsError> = None;

        // Process all query types.
        for query_type in &params.query_types {
            match pool
                .resolve(&resolver, &fqdn, query_type, &params.transport, true)
                .await
            {
                Ok(packet) => {
                    all_results.extend(packet.answers);
                    // Report successful query
                    if let Some(delay) = &params.delay {
                        delay.report_query_result(true);
                    }
                }
                Err(error) => {
                    if matches!(error, DnsError::Network(_)) {
                        let duration = rand::rng().random_range(5..=30);
                        resolver_selector.disable(resolver, Duration::from_secs(duration));
                    }

                    // Report failed query (unless it's just NXDOMAIN)
                    if let Some(delay) = &params.delay {
                        let is_expected_error = matches!(
                            error,
                            DnsError::NonExistentDomain | DnsError::NoRecordsFound
                        );
                        delay.report_query_result(is_expected_error);
                    }

                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
            if let Some(delay) = &params.delay {
                time::sleep(Duration::from_millis(delay.get_delay())).await;
            }
        }

        // If any answers were found, send the success result.
        if !all_results.is_empty() {
            if params
                .tx
                .send(Ok((subdomain, resolver, all_results)))
                .await
                .is_err()
            {
                return;
            }
        } else if let Some(err) = first_error {
            // Otherwise send the error (if any).
            if params
                .tx
                .send(Err((subdomain, resolver, err)))
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

async fn process_failed_subdomains(
    cmd_args: &CommandArgs,
    pool: &AsyncResolver,
    dns_resolvers: &[Ipv4Addr],
    failed_subdomains: Vec<String>,
    interrupt: &AtomicBool,
) -> usize {
    log_info!(
        format!(
            "Retrying {} failed subdomains",
            failed_subdomains.len().to_string().bold(),
        ),
        true
    );
    let mut resolver_selector =
        resolver_selector::get_selector(cmd_args.use_random, dns_resolvers.to_vec());

    // Always use a delay for retries, even if the user didn't specify one.
    let adaptive_delay = delay::Delay::adaptive(75, 750);

    let mut found_count = 0;
    for subdomain in failed_subdomains {
        if interrupt.load(Ordering::SeqCst) {
            break;
        }
        let fqdn = format!("{}.{}", subdomain, cmd_args.target);
        let resolver = resolver_selector
            .select()
            .unwrap_or(resolver_selector::DEFAULT_RESOLVER);
        let mut results = HashSet::new();

        for query_type in &cmd_args.query_types {
            time::sleep(Duration::from_millis(adaptive_delay.get_delay())).await;

            match pool
                .resolve(
                    &resolver,
                    &fqdn,
                    query_type,
                    &cmd_args.transport_protocol,
                    true,
                )
                .await
            {
                Ok(packet) => {
                    results.extend(packet.answers);
                    adaptive_delay.report_query_result(true);
                }
                Err(error) => {
                    print_query_error(cmd_args, &subdomain, resolver, &error, true);
                    if !matches!(
                        error,
                        DnsError::NoRecordsFound | DnsError::NonExistentDomain
                    ) {
                        adaptive_delay.report_query_result(false);
                    }
                    break;
                }
            }
        }

        if !results.is_empty() {
            print_query_result(
                cmd_args,
                &subdomain,
                resolver,
                &create_query_response_string(&results),
            );
            found_count += 1;
        }
    }
    found_count
}

fn read_wordlist(wordlist_path: Option<&String>) -> Result<Vec<String>> {
    if let Some(path) = wordlist_path {
        Ok(wordlist::read_subdomain_list(path)?)
    } else {
        Err(anyhow!(
            "Wordlist path is required for subdomain enumeration"
        ))
    }
}

async fn handle_wildcard_domain(args: &CommandArgs, dns_resolvers: &[Ipv4Addr]) -> Result<bool> {
    if check_wildcard_domain(args, dns_resolvers).await? {
        log_warn!("Warning: Wildcard domain detected. Results may include false positives!");
        log_question!("Do you want to continue? (y/n): ");

        io::Write::flush(&mut io::stdout()).expect("Failed to flush stdout");

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

async fn check_wildcard_domain(args: &CommandArgs, dns_resolvers: &[Ipv4Addr]) -> Result<bool> {
    const ATTEMPTS: u8 = 3;
    const MAX_PREFIX_LENGTH: usize = 63;

    let resolver_pool = AsyncResolver::new(Some(1)).await?;

    let resolver = dns_resolvers
        .first()
        .ok_or_else(|| anyhow!("No DNS resolvers available"))?;

    let mut rng = rand::rng();

    let mut successful_resolutions = 0;

    for _ in 0..ATTEMPTS {
        // Generate a random subdomain prefix
        let random_length = rng.random_range(10..=MAX_PREFIX_LENGTH);
        let random_subdomain: String = (5..random_length)
            .map(|_| rng.random_range('a'..='z'))
            .collect();

        // Append a unique identifier to avoid DNS caching issues
        let fqdn = format!(
            "{}-{}.{}",
            random_subdomain,
            rng.random_range(0..=200),
            args.target
        );

        let query_type = &DEFAULT_QUERY_TYPES[rng.random_range(0..DEFAULT_QUERY_TYPES.len())];

        // Check if the subdomain resolves
        if resolver_pool
            .resolve(resolver, &fqdn, query_type, &args.transport_protocol, true)
            .await
            .is_ok()
        {
            successful_resolutions += 1;
        }

        // Break early if we already have enough successful resolutions
        if successful_resolutions >= 2 {
            break;
        }
    }

    Ok(successful_resolutions >= 2)
}

fn print_query_result(args: &CommandArgs, subdomain: &str, resolver: Ipv4Addr, response: &str) {
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
        write!(message, " [resolver: {}]", resolver.to_string().magenta()).unwrap();
    }
    if !args.no_print_records {
        write!(message, " {response}").unwrap();
    }

    log_success!(message);
}

fn print_query_error(
    args: &CommandArgs,
    subdomain: &str,
    resolver: Ipv4Addr,
    error: &DnsError,
    retry: bool,
) {
    // Skip printing the error if any of the following are true:
    if args.quiet // 1. Quiet mode: suppress all output.
    // 2. User requested not to print errors, and this is not a retry.
    || (args.no_print_errors && !retry)
    // 3. Not in verbose mode, not a retry, and the error is a "normal" negative response.
    || (!args.verbose
        && !retry
        && matches!(
            error,
            DnsError::NoRecordsFound | DnsError::NonExistentDomain
        ))
    {
        return;
    }

    let domain = format!("{}.{}", subdomain.red().bold(), args.target.blue().italic());
    let mut message = domain;

    if args.show_resolver {
        write!(message, " [resolver: {}]", resolver.to_string().magenta()).unwrap();
    }
    write!(message, " {error}").unwrap();

    log_error!(message);
}
