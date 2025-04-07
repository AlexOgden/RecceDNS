#![allow(clippy::future_not_send)]

use anyhow::{anyhow, Result};
use colored::Colorize;
use rand::Rng;
use std::fmt::Write;
use std::{
    cmp::max,
    collections::HashSet,
    io::{self},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    dns::{
        async_resolver_pool::AsyncResolverPool,
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
    Result<(String, String, HashSet<ResourceRecord>), (String, String, DnsError)>;

// A type alias for the sender channel.
type SubdomainResultSender = mpsc::Sender<SubdomainResult>;

// Parameters for the worker threads.
#[derive(Clone)]
struct WorkerParams {
    connection_pool: AsyncResolverPool,
    tx: SubdomainResultSender,
    subdomains: Vec<String>,
    query_types: Vec<QueryType>,
    target: String,
    transport: TransportProtocol,
    dns_resolvers: Vec<String>,
    use_random: bool,
    delay: Option<delay::Delay>,
}

// Default query types for subdomain enumeration if none provided.
const DEFAULT_QUERY_TYPES: &[QueryType] = &[QueryType::A, QueryType::AAAA];

#[allow(clippy::too_many_lines)]
pub async fn enumerate_subdomains(
    cmd_args: &CommandArgs,
    dns_resolver_list: &[&str],
) -> Result<()> {
    let interrupted = interrupt::initialize_interrupt_handler()?;

    if handle_wildcard_domain(cmd_args, dns_resolver_list).await? {
        return Ok(());
    }

    let query_types =
        if cmd_args.query_types.is_empty() || cmd_args.query_types.contains(&QueryType::ANY) {
            DEFAULT_QUERY_TYPES.to_vec()
        } else {
            cmd_args.query_types.clone()
        };

    // Prepare results output if JSON output is enabled.
    let mut results_output = if cmd_args.json.is_some() {
        Some(DnsEnumerationOutput::new(cmd_args.target.clone()))
    } else {
        None
    };

    let subdomain_list = read_wordlist(cmd_args.wordlist.as_ref())?;

    let num_threads = cmd_args
        .threads
        .map_or_else(|| max(num_cpus::get() - 1, 1), |threads| threads);

    log_info!(format!(
        "Starting subdomain enumeration with {} threads",
        num_threads.to_string().bold()
    ));

    // Split subdomain list into chunks for each thread.
    let chunk_size = subdomain_list.len().div_ceil(num_threads);
    let subdomain_chunks: Vec<Vec<String>> = subdomain_list
        .chunks(chunk_size)
        .map(<[std::string::String]>::to_vec)
        .collect();

    // Setup progress bar.
    let total_subdomains = subdomain_list.len() as u64;
    let progress_bar = cli::setup_progress_bar(total_subdomains);

    let start_time = Instant::now();

    // Create an mpsc channel for collecting results.
    let (tx, rx) = mpsc::channel();

    // Create connection pool
    let pool = AsyncResolverPool::new(Some(2 * num_threads)).await?;

    // Spawn worker threads.
    for chunk in subdomain_chunks {
        let worker_params = WorkerParams {
            connection_pool: pool.clone(),
            tx: tx.clone(),
            subdomains: chunk,
            query_types: query_types.clone(),
            target: cmd_args.target.clone(),
            transport: cmd_args.transport_protocol.clone(),
            dns_resolvers: dns_resolver_list
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            use_random: cmd_args.use_random,
            delay: cmd_args.delay.clone(),
        };

        thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(process_subdomain_chunk(worker_params));
        });
    }
    drop(tx); // Close original sender.

    // Process results from the receiver.
    let mut found_count = 0;
    let mut failed_subdomains = Vec::new();
    for (i, received) in rx.into_iter().enumerate() {
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
                print_query_result(cmd_args, &subdomain, &resolver, &response_str);

                if let Some(output) = &mut results_output {
                    results.iter().for_each(|r| output.add_result(r.clone()));
                }
            }
            Err((subdomain, resolver, error)) => {
                print_query_error(cmd_args, &subdomain, &resolver, &error, false);
                match error {
                    DnsError::NoRecordsFound | DnsError::NonExistentDomain => {}
                    _ => failed_subdomains.push(subdomain),
                }
            }
        }
        progress_bar.inc(1);
        cli::update_progress_bar(
            &progress_bar,
            ((i as u64) + 1).try_into().unwrap(),
            total_subdomains,
        );
    }

    progress_bar.finish_and_clear();

    if !failed_subdomains.is_empty() && !cmd_args.no_retry {
        interrupted.store(false, Ordering::SeqCst);
        let success_retrys = process_failed_subdomains(
            cmd_args,
            pool.clone(),
            dns_resolver_list,
            failed_subdomains,
            &interrupted,
        )
        .await;
        found_count += success_retrys;
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

    pool.shutdown();

    Ok(())
}

async fn process_subdomain_chunk(params: WorkerParams) {
    let pool = params.connection_pool;
    let mut resolver_selector =
        resolver_selector::get_selector(params.use_random, params.dns_resolvers.clone());

    for subdomain in params.subdomains {
        let resolver = resolver_selector
            .select()
            .unwrap_or(resolver_selector::DEFAULT_RESOLVER)
            .to_string();
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
                        let duration = rand::rng().random_range(2..=25);
                        resolver_selector.disable(&resolver, Duration::from_secs(duration));
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
                thread::sleep(Duration::from_millis(delay.get_delay()));
            }
        }

        // If any answers were found, send the success result.
        if !all_results.is_empty() {
            if params
                .tx
                .send(Ok((subdomain, resolver.to_string(), all_results)))
                .is_err()
            {
                return;
            }
        } else if let Some(err) = first_error {
            // Otherwise send the error (if any).
            if params
                .tx
                .send(Err((subdomain, resolver.to_string(), err)))
                .is_err()
            {
                return;
            }
        }
    }
}

async fn process_failed_subdomains(
    cmd_args: &CommandArgs,
    pool: AsyncResolverPool,
    dns_resolvers: &[&str],
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
    let mut resolver_selector = resolver_selector::get_selector(
        cmd_args.use_random,
        dns_resolvers
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
    );

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
            match pool
                .resolve(
                    resolver,
                    &fqdn,
                    query_type,
                    &cmd_args.transport_protocol,
                    true,
                )
                .await
            {
                Ok(packet) => results.extend(packet.answers),
                Err(error) => {
                    print_query_error(cmd_args, &subdomain, resolver, &error, true);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(125));
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
        Ok(wordlist::read_from_file(path)?)
    } else {
        Err(anyhow!(
            "Wordlist path is required for subdomain enumeration"
        ))
    }
}

async fn handle_wildcard_domain(args: &CommandArgs, dns_resolvers: &[&str]) -> Result<bool> {
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

async fn check_wildcard_domain(args: &CommandArgs, dns_resolvers: &[&str]) -> Result<bool> {
    const ATTEMPTS: u8 = 3;
    const MAX_PREFIX_LENGTH: usize = 63;

    let resolver_pool = AsyncResolverPool::new(Some(1)).await?;

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
        write!(message, " [resolver: {}]", resolver.magenta()).unwrap();
    }
    if !args.no_print_records {
        write!(message, " {response}").unwrap();
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
    if args.quiet
        || (args.no_print_errors && !retry)
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
        write!(message, " [resolver: {}]", resolver.magenta()).unwrap();
    }
    write!(message, " {error}").unwrap();

    log_error!(message);
}
