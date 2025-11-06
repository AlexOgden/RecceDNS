#![allow(clippy::future_not_send)]

use anyhow::{Result, anyhow};
use colored::Colorize;
use rand::Rng;
use std::fmt::Write;
use std::net::Ipv4Addr;
use std::{
    collections::HashSet,
    io::{self},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use tokio::sync::{Mutex, Semaphore, mpsc};

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
    modes::shared_state::{LookupContext, QueryFailure, QueryPlan},
    timing::delay,
};

// A type alias for the result sent between threads.
type SubdomainResult =
    Result<(String, Ipv4Addr, HashSet<ResourceRecord>), (String, Ipv4Addr, DnsError)>;
#[derive(Clone)]
struct SubdomainContext {
    lookup: LookupContext,
    target: String,
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

    let num_threads = cmd_args
        .threads
        .unwrap_or_else(|| num_cpus::get().saturating_sub(1).clamp(1, 8));

    log_info!(format!(
        "Starting subdomain enumeration with {} threads",
        num_threads.to_string().bold()
    ));

    // Setup progress bar.
    let total_subdomains = subdomain_list.len() as u64;
    let progress_bar = cli::setup_progress_bar(total_subdomains);

    let start_time = Instant::now();

    let buffer_size = std::cmp::min(1000, subdomain_list.len().max(1));
    let (tx, mut rx) = mpsc::channel(buffer_size);

    let query_plan = QueryPlan::new(query_types);

    let max_slots = 4096.max(num_threads);
    let slot_limit = num_threads.saturating_mul(32).clamp(num_threads, max_slots);

    // Create connection pool sized to the concurrency cap.
    let resolver_pool_target = slot_limit.max(num_threads.saturating_mul(2));
    let pool = AsyncResolver::new(Some(resolver_pool_target)).await?;

    let selector = Arc::new(Mutex::new(resolver_selector::get_selector(
        cmd_args.use_random,
        dns_resolver_list.to_vec(),
    )));
    let lookup_context = LookupContext::new(
        pool.clone(),
        selector,
        cmd_args.transport_protocol.clone(),
        cmd_args.delay.clone(),
        query_plan.clone(),
        !cmd_args.no_recursion,
    );
    let shared_context = Arc::new(SubdomainContext {
        lookup: lookup_context,
        target: cmd_args.target.clone(),
    });

    let semaphore = Arc::new(Semaphore::new(slot_limit));

    for subdomain in subdomain_list {
        let ctx = shared_context.clone();
        let permit_pool = semaphore.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let Ok(permit) = permit_pool.acquire_owned().await else {
                return;
            };

            let outcome = resolve_subdomain(ctx.as_ref(), &subdomain).await;
            let _ = tx_clone.send(outcome).await;

            drop(permit);
        });
    }
    drop(tx); // Close original sender.

    // Process results from the receiver.
    let mut found_count = 0;
    let mut failed_subdomains: Vec<String> = Vec::new();
    let mut processed_count: u64 = 0;
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
                    for r in &results {
                        output.add_result(r.clone());
                    }
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
            (processed_count + 1).try_into().unwrap(),
            total_subdomains,
            Some(failed_subdomains.len()),
            cmd_args.delay.as_ref(),
        );

        processed_count += 1;
    }

    progress_bar.finish_and_clear();

    pool.shutdown();

    let retry_queries = if !failed_subdomains.is_empty() && !cmd_args.no_retry {
        interrupted.store(false, Ordering::SeqCst);
        // Use a new resolver pool for retries
        let retry_pool = AsyncResolver::new(Some(2 * num_threads)).await?;
        let (success_retries, retry_query_count) = process_failed_subdomains(
            cmd_args,
            &retry_pool,
            dns_resolver_list,
            failed_subdomains,
            &interrupted,
            &query_plan,
        )
        .await;
        found_count += success_retries;
        retry_pool.shutdown();
        retry_query_count
    } else {
        0
    };

    let elapsed_time = start_time.elapsed();
    let total_queries = shared_context.lookup.total_queries() + retry_queries;

    let message = if cmd_args.no_query_stats {
        format!(
            "Done! Found {} subdomains in {:.2?}",
            found_count.to_string().bold(),
            elapsed_time,
        )
    } else {
        format!(
            "Done! Found {} subdomains in {:.2?} | Tested {} subdomains | Executed {} queries",
            found_count.to_string().bold(),
            elapsed_time,
            processed_count.to_string().bold(),
            total_queries.to_string().bold()
        )
    };

    log_info!(message, true);

    if let (Some(output), Some(file)) = (&results_output, &cmd_args.json) {
        output.write_to_file(file)?;
    }

    Ok(())
}

async fn resolve_subdomain(ctx: &SubdomainContext, subdomain: &str) -> SubdomainResult {
    let fqdn = format!("{}.{}", subdomain, ctx.target);
    let mut aggregated = HashSet::new();
    let mut first_failure: Option<QueryFailure> = None;
    let mut success_resolver: Option<Ipv4Addr> = None;
    let mut first_query = true;

    let primary_result = ctx
        .lookup
        .execute_query(
            &fqdn,
            ctx.lookup.query_plan.primary.clone(),
            &mut first_query,
        )
        .await;

    match primary_result {
        Ok((resolver, packet)) => {
            aggregated.extend(packet.answers.into_iter());
            success_resolver = Some(resolver);
        }
        Err(failure) => {
            let terminal = matches!(failure.error, DnsError::NonExistentDomain);
            if ctx.lookup.query_plan.gate_followups_on_primary_hit && terminal {
                return Err((subdomain.to_string(), failure.resolver, failure.error));
            }
            first_failure = Some(failure);
        }
    }

    for query_type in &ctx.lookup.query_plan.follow_ups {
        match ctx
            .lookup
            .execute_query(&fqdn, query_type.clone(), &mut first_query)
            .await
        {
            Ok((resolver, packet)) => {
                if success_resolver.is_none() {
                    success_resolver = Some(resolver);
                }
                aggregated.extend(packet.answers.into_iter());
            }
            Err(failure) => {
                if first_failure.is_none() {
                    first_failure = Some(failure);
                }
            }
        }
    }

    if !aggregated.is_empty() {
        let resolver = success_resolver.unwrap_or(resolver_selector::DEFAULT_RESOLVER);
        Ok((subdomain.to_string(), resolver, aggregated))
    } else if let Some(failure) = first_failure {
        Err((subdomain.to_string(), failure.resolver, failure.error))
    } else {
        Err((
            subdomain.to_string(),
            resolver_selector::DEFAULT_RESOLVER,
            DnsError::NoRecordsFound,
        ))
    }
}

async fn process_failed_subdomains(
    cmd_args: &CommandArgs,
    pool: &AsyncResolver,
    dns_resolvers: &[Ipv4Addr],
    failed_subdomains: Vec<String>,
    interrupt: &AtomicBool,
    query_plan: &QueryPlan,
) -> (usize, u64) {
    log_info!(
        format!(
            "Retrying {} failed subdomains",
            failed_subdomains.len().to_string().bold(),
        ),
        true
    );
    let adaptive_delay = delay::Delay::adaptive(75, 750);
    let retry_selector = Arc::new(Mutex::new(resolver_selector::get_selector(
        cmd_args.use_random,
        dns_resolvers.to_vec(),
    )));

    let retry_lookup = LookupContext::new(
        pool.clone(),
        retry_selector,
        cmd_args.transport_protocol.clone(),
        Some(adaptive_delay),
        query_plan.clone(),
        !cmd_args.no_recursion,
    );
    let retry_context = Arc::new(SubdomainContext {
        lookup: retry_lookup,
        target: cmd_args.target.clone(),
    });

    let mut found_count = 0;
    for subdomain in failed_subdomains {
        if interrupt.load(Ordering::SeqCst) {
            break;
        }

        match resolve_subdomain(retry_context.as_ref(), &subdomain).await {
            Ok((name, resolver, results)) => {
                print_query_result(
                    cmd_args,
                    &name,
                    resolver,
                    &create_query_response_string(&results),
                );
                found_count += 1;
            }
            Err((name, resolver, error)) => {
                print_query_error(cmd_args, &name, resolver, &error, true);
            }
        }
    }

    let total_queries = retry_context.lookup.total_queries();

    (found_count, total_queries)
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
