#![allow(clippy::future_not_send)]

use anyhow::{Result, anyhow};
use colored::Colorize;
use rand::RngExt;
use std::fmt::Write;
use std::net::SocketAddr;
use std::{
    collections::HashSet,
    io::{self},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, mpsc};

use crate::timing::delay::Delay;
use crate::{
    dns::{
        async_resolver::AsyncResolver,
        error::DnsError,
        format::create_query_response_string,
        protocol::{QueryType, RData, ResourceRecord},
        resolver_selector::{self, ResolverPool},
    },
    io::{
        cli::{self, CommandArgs},
        interrupt,
        json::{Output, RecceOutput},
        logger, wordlist,
    },
    log_error, log_info, log_question, log_success, log_warn,
    modes::shared_state::{LookupContext, QueryFailure, QueryPlan},
};

// A type alias for the result sent between threads.
type SubdomainResult =
    Result<(String, SocketAddr, HashSet<ResourceRecord>), (String, SocketAddr, DnsError)>;
#[derive(Clone)]
struct SubdomainContext {
    lookup: LookupContext,
    target: String,
    wildcard_records: Option<HashSet<RData>>,
}

// Default query types for subdomain enumeration if none provided.
const DEFAULT_QUERY_TYPES: &[QueryType] = &[QueryType::A, QueryType::AAAA];

#[allow(clippy::too_many_lines)]
pub async fn enumerate_subdomains(
    cmd_args: &CommandArgs,
    dns_resolver_list: &[SocketAddr],
) -> Result<()> {
    let interrupted = interrupt::initialize_interrupt_handler()?;

    let wildcard_records = handle_wildcard_prompt(cmd_args, dns_resolver_list).await?;

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

    let mut results_output = if cmd_args.json.is_some() {
        Some(RecceOutput::new(cmd_args.target.clone()))
    } else {
        None
    };

    let mutator =
        if cmd_args.mutate || cmd_args.mutate_rules.is_some() || cmd_args.mutate_words.is_some() {
            let engine = crate::modes::mutator::MutationEngine::new(
                cmd_args.mutate_rules.as_ref(),
                cmd_args.mutate_words.as_ref(),
            )?;
            log_info!(format!("Mutation engine {}", "enabled".bold()));
            Some(Arc::new(engine))
        } else {
            None
        };

    let wordlist_path = cmd_args
        .wordlist
        .as_ref()
        .ok_or_else(|| anyhow!("Wordlist path is required for subdomain enumeration"))?;

    // Unclamped concurrency
    let num_threads = cmd_args
        .threads
        .unwrap_or_else(|| crate::cpu::count().saturating_sub(1).max(1));

    log_info!(format!(
        "Starting subdomain enumeration with {} threads",
        num_threads.to_string().bold()
    ));

    // Fast line counting without loading all strings into memory
    let mut total_subdomains = wordlist::count_lines(wordlist_path).unwrap_or(0);
    let progress_bar = cli::setup_progress_bar(total_subdomains);

    let start_time = Instant::now();

    // Slot limit unclamped from 256
    let slot_limit = num_threads.saturating_mul(64).clamp(num_threads, 4096);
    let buffer_size = slot_limit.saturating_mul(2).clamp(100, 4096);

    let query_plan = QueryPlan::new(query_types);

    // Lean connection pool (capped to 16 sockets)
    let pool = AsyncResolver::new(None).await?;

    let resolver_pool = Arc::new(ResolverPool::new(
        dns_resolver_list.to_vec(),
        cmd_args.use_random,
    ));
    let lookup_context = LookupContext::new(
        pool.clone(),
        resolver_pool,
        cmd_args.transport_protocol.clone(),
        cmd_args.delay.clone(),
        query_plan.clone(),
        !cmd_args.no_recursion,
    );
    let shared_context = Arc::new(SubdomainContext {
        lookup: lookup_context,
        target: cmd_args.target.clone(),
        wildcard_records: wildcard_records.clone(),
    });

    let config = WorkerRunConfig {
        shared_context: shared_context.clone(),
        slot_limit,
        buffer_size,
        cmd_args,
        interrupted: &interrupted,
        progress_bar: &progress_bar,
    };

    let mut found_count = 0;
    let mut failed_subdomains: Vec<String> = Vec::new();
    let mut processed_count: u64 = 0;

    let mut state = WorkerRunState {
        total_subdomains,
        processed_count: &mut processed_count,
        found_count: &mut found_count,
        failed_subdomains: &mut failed_subdomains,
        results_output: &mut results_output,
    };

    // Phase 1: Wordlist streaming
    let (work_tx, work_rx) = mpsc::channel(slot_limit);
    let feeder_stream = wordlist::stream_subdomain_list(wordlist_path)?;
    let feeder_interrupted = interrupted.clone();
    tokio::spawn(async move {
        for line_res in feeder_stream {
            if feeder_interrupted.load(Ordering::SeqCst) {
                break;
            }
            let Ok(subdomain) = line_res else {
                continue;
            };
            if work_tx.send(subdomain).await.is_err() {
                break;
            }
        }
    });

    let mut discovered = run_worker_pool(work_rx, &config, &mut state).await;

    // Phase 2: Mutations if enabled
    let mut mutations_generated = 0;
    if let Some(mutator_ref) = &mutator {
        let mut seen_mutations = HashSet::<String>::new();
        for sub in &discovered {
            seen_mutations.insert(sub.clone());
        }

        while !discovered.is_empty() && !interrupted.load(Ordering::SeqCst) {
            let mut mutations = Vec::new();
            for sub in &discovered {
                for mutated in mutator_ref.mutate(sub) {
                    if seen_mutations.insert(mutated.clone()) {
                        mutations.push(mutated);
                    }
                }
            }

            if mutations.is_empty() {
                break;
            }

            let mutation_count = mutations.len() as u64;
            total_subdomains += mutation_count;
            mutations_generated += mutation_count;
            state.total_subdomains = total_subdomains;
            config.progress_bar.set_length(total_subdomains);

            let (mut_work_tx, mut_work_rx) = mpsc::channel(slot_limit);
            let mut_interrupted = interrupted.clone();
            tokio::spawn(async move {
                for mutated in mutations {
                    if mut_interrupted.load(Ordering::SeqCst) {
                        break;
                    }
                    if mut_work_tx.send(mutated).await.is_err() {
                        break;
                    }
                }
            });

            discovered = run_worker_pool(mut_work_rx, &config, &mut state).await;
        }
    }

    progress_bar.finish_and_clear();

    pool.shutdown();

    let retry_queries = if !failed_subdomains.is_empty() && !cmd_args.no_retry {
        interrupted.store(false, Ordering::SeqCst);
        // Use a lean resolver pool for retries
        let retry_pool = AsyncResolver::new(None).await?;
        let (success_retries, retry_query_count) = process_failed_subdomains(
            cmd_args,
            &retry_pool,
            dns_resolver_list,
            failed_subdomains,
            &interrupted,
            &query_plan,
            shared_context.wildcard_records.clone(),
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
    } else if mutations_generated > 0 {
        format!(
            "Done! Found {} subdomains in {:.2?} | Tested {} subdomains ({} mutations) | Executed {} queries",
            found_count.to_string().bold(),
            elapsed_time,
            processed_count.to_string().bold(),
            mutations_generated.to_string().bold(),
            total_queries.to_string().bold()
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

struct WorkerRunConfig<'a> {
    shared_context: Arc<SubdomainContext>,
    slot_limit: usize,
    buffer_size: usize,
    cmd_args: &'a CommandArgs,
    interrupted: &'a Arc<AtomicBool>,
    progress_bar: &'a indicatif::ProgressBar,
}

struct WorkerRunState<'a> {
    total_subdomains: u64,
    processed_count: &'a mut u64,
    found_count: &'a mut usize,
    failed_subdomains: &'a mut Vec<String>,
    results_output: &'a mut Option<RecceOutput>,
}

async fn run_worker_pool(
    work_rx: mpsc::Receiver<String>,
    config: &WorkerRunConfig<'_>,
    state: &mut WorkerRunState<'_>,
) -> Vec<String> {
    let (result_tx, mut result_rx) = mpsc::channel(config.buffer_size);
    let work_rx = Arc::new(tokio::sync::Mutex::new(work_rx));

    for _ in 0..config.slot_limit {
        let rx = work_rx.clone();
        let r_tx = result_tx.clone();
        let ctx = config.shared_context.clone();
        let inter = Arc::clone(config.interrupted);
        tokio::spawn(async move {
            loop {
                if inter.load(Ordering::SeqCst) {
                    break;
                }
                let subdomain = {
                    let mut guard = rx.lock().await;
                    guard.recv().await
                };
                let Some(subdomain) = subdomain else {
                    break;
                };
                let outcome = resolve_subdomain(ctx.as_ref(), &subdomain).await;
                if r_tx.send(outcome).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(result_tx);

    let mut discovered = Vec::new();
    let mut last_pb_update = Instant::now();
    let mut unrendered_count: u64 = 0;

    while let Some(received) = result_rx.recv().await {
        if config.interrupted.load(Ordering::SeqCst) {
            logger::clear_line();
            log_warn!("Interrupted by user");
            break;
        }

        match received {
            Ok((subdomain, resolver, results)) => {
                *state.found_count += 1;
                print_query_result(config.cmd_args, &subdomain, resolver, Some(&results));

                if let Some(output) = state.results_output.as_mut() {
                    let records: Vec<ResourceRecord> = results.iter().cloned().collect();
                    output.add_result(format!("{}.{}", subdomain, config.cmd_args.target), records);
                }

                discovered.push(subdomain);
            }
            Err((subdomain, resolver, error)) => {
                print_query_error(config.cmd_args, &subdomain, resolver, &error, false);
                match error {
                    DnsError::NoRecordsFound | DnsError::NonExistentDomain => {}
                    _ => state.failed_subdomains.push(subdomain),
                }
            }
        }

        *state.processed_count += 1;
        unrendered_count += 1;

        if last_pb_update.elapsed() >= Duration::from_millis(50) || unrendered_count >= 100 {
            cli::update_progress_bar_batch(
                config.progress_bar,
                *state.processed_count,
                state.total_subdomains.max(*state.processed_count),
                unrendered_count,
                Some(state.failed_subdomains.len()),
                config.cmd_args.delay.as_ref(),
            );
            unrendered_count = 0;
            last_pb_update = Instant::now();
        }
    }

    if unrendered_count > 0 {
        cli::update_progress_bar_batch(
            config.progress_bar,
            *state.processed_count,
            state.total_subdomains.max(*state.processed_count),
            unrendered_count,
            Some(state.failed_subdomains.len()),
            config.cmd_args.delay.as_ref(),
        );
    }

    discovered
}

async fn resolve_subdomain(ctx: &SubdomainContext, subdomain: &str) -> SubdomainResult {
    let fqdn = format!("{}.{}", subdomain, ctx.target);
    let mut aggregated = HashSet::new();
    let mut first_failure: Option<QueryFailure> = None;
    let mut success_resolver: Option<SocketAddr> = None;

    let primary_result = ctx
        .lookup
        .execute_query(&fqdn, ctx.lookup.query_plan.primary)
        .await;

    match primary_result {
        Ok((resolver, packet)) => {
            aggregated.extend(packet.answers);
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
        match ctx.lookup.execute_query(&fqdn, *query_type).await {
            Ok((resolver, packet)) => {
                if success_resolver.is_none() {
                    success_resolver = Some(resolver);
                }
                aggregated.extend(packet.answers);
            }
            Err(failure) => {
                if first_failure.is_none() {
                    first_failure = Some(failure);
                }
            }
        }
    }

    if let Some(wildcard_set) = &ctx.wildcard_records {
        aggregated.retain(|record| !wildcard_set.contains(&record.data));
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
    dns_resolvers: &[SocketAddr],
    failed_subdomains: Vec<String>,
    interrupt: &Arc<AtomicBool>,
    query_plan: &QueryPlan,
    wildcard_records: Option<HashSet<RData>>,
) -> (usize, u64) {
    log_info!(
        format!(
            "Retrying {} failed subdomains",
            failed_subdomains.len().to_string().bold(),
        ),
        true
    );
    let adaptive_delay = Delay::adaptive(75, 750);
    let retry_delay = adaptive_delay.clone();
    let retry_resolver_pool = Arc::new(ResolverPool::new(
        dns_resolvers.to_vec(),
        cmd_args.use_random,
    ));

    let retry_lookup = LookupContext::new(
        pool.clone(),
        retry_resolver_pool,
        cmd_args.transport_protocol.clone(),
        Some(retry_delay),
        query_plan.clone(),
        !cmd_args.no_recursion,
    );
    let retry_context = Arc::new(SubdomainContext {
        lookup: retry_lookup,
        target: cmd_args.target.clone(),
        wildcard_records,
    });

    let num_threads = cmd_args
        .threads
        .unwrap_or_else(|| crate::cpu::count().saturating_sub(1).max(1));
    let retry_concurrency = (num_threads * 4).clamp(4, 64);
    let retry_semaphore = Arc::new(Semaphore::new(retry_concurrency));
    let (retry_tx, mut retry_rx) = mpsc::channel(retry_concurrency * 2);

    let feeder_interrupted = Arc::clone(interrupt);
    let feeder_sem = retry_semaphore.clone();
    let feeder_ctx = retry_context.clone();
    let feeder_tx = retry_tx.clone();

    tokio::spawn(async move {
        for subdomain in failed_subdomains {
            if feeder_interrupted.load(Ordering::SeqCst) {
                break;
            }
            let Ok(permit) = feeder_sem.clone().acquire_owned().await else {
                break;
            };
            let ctx = feeder_ctx.clone();
            let task_tx = feeder_tx.clone();
            tokio::spawn(async move {
                let outcome = resolve_subdomain(ctx.as_ref(), &subdomain).await;
                let _ = task_tx.send(outcome).await;
                drop(permit);
            });
        }
    });
    drop(retry_tx);

    let mut found_count = 0;
    while let Some(result) = retry_rx.recv().await {
        if interrupt.load(Ordering::SeqCst) {
            break;
        }

        match result {
            Ok((name, resolver, results)) => {
                adaptive_delay.report_query_result(true);
                print_query_result(cmd_args, &name, resolver, Some(&results));
                found_count += 1;
            }
            Err((name, resolver, error)) => {
                let treat_as_failure = matches!(
                    error,
                    DnsError::Network(_)
                        | DnsError::Timeout(_)
                        | DnsError::Nameserver(_)
                        | DnsError::InvalidData(_)
                        | DnsError::ProtocolData(_)
                        | DnsError::Internal(_)
                );
                adaptive_delay.report_query_result(!treat_as_failure);
                print_query_error(cmd_args, &name, resolver, &error, true);
            }
        }
    }

    let total_queries = retry_context.lookup.total_queries();

    (found_count, total_queries)
}

async fn handle_wildcard_prompt(
    args: &CommandArgs,
    resolvers: &[SocketAddr],
) -> Result<Option<HashSet<RData>>> {
    let wildcard = check_wildcard_domain(args, resolvers).await?;
    if wildcard.is_some() {
        log_warn!("Warning: Wildcard domain detected. Results may include false positives!");
        log_question!("Do you want to continue? (y/n): ");

        let _ = io::Write::flush(&mut io::stdout());

        let input = tokio::task::spawn_blocking(|| {
            let mut input = String::new();
            io::stdin().read_line(&mut input).map(|_| input)
        })
        .await
        .map_err(|e| anyhow!("Failed to spawn blocking stdin task: {e}"))?
        .map_err(|e| anyhow!("Failed to read stdin: {e}"))?;

        if !matches!(input.trim().to_lowercase().as_str(), "y") {
            return Err(anyhow!("Aborted by user"));
        }
    }
    Ok(wildcard)
}

async fn check_wildcard_domain(
    args: &CommandArgs,
    dns_resolvers: &[SocketAddr],
) -> Result<Option<HashSet<RData>>> {
    const ATTEMPTS: u8 = 3;

    let resolver_pool = AsyncResolver::new(Some(1)).await?;

    let resolver = dns_resolvers
        .first()
        .ok_or_else(|| anyhow!("No DNS resolvers available"))?;

    let mut rng = rand::rng();

    let mut successful_resolutions = 0;
    let mut collected_records = HashSet::new();

    for _ in 0..ATTEMPTS {
        // Generate a random subdomain prefix
        let random_subdomain: String = (0..8).map(|_| rng.random_range('a'..='z')).collect();

        // Append a unique identifier to avoid DNS caching issues
        let fqdn = format!("{}.{}", random_subdomain, args.target);

        let query_type = &DEFAULT_QUERY_TYPES[rng.random_range(0..DEFAULT_QUERY_TYPES.len())];

        if let Ok(response) = resolver_pool
            .resolve(*resolver, &fqdn, query_type, &args.transport_protocol, true)
            .await
        {
            successful_resolutions += 1;
            for answer in response.answers {
                collected_records.insert(answer.data);
            }
        }

        // Break early if we already have enough successful resolutions
        if successful_resolutions >= 2 {
            break;
        }
    }

    if successful_resolutions >= 2 {
        Ok(Some(collected_records))
    } else {
        Ok(None)
    }
}

fn print_query_result(
    args: &CommandArgs,
    subdomain: &str,
    resolver: SocketAddr,
    records: Option<&HashSet<ResourceRecord>>,
) {
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
        let _ = write!(message, " [resolver: {}]", resolver.to_string().magenta());
    }
    if !args.no_print_records
        && let Some(records) = records
        && !records.is_empty()
    {
        let response = create_query_response_string(records);
        let _ = write!(message, " {response}");
    }
    log_success!(message);
}

fn print_query_error(
    args: &CommandArgs,
    subdomain: &str,
    resolver: SocketAddr,
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
        let _ = write!(message, " [resolver: {}]", resolver.to_string().magenta());
    }
    let _ = write!(message, " {error}");

    log_error!(message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{
        DnsPacket, DnsQuestion, QueryType, RData, ResourceRecord, ResultCode,
    };
    use crate::io::packet_buffer::PacketBuffer;
    use clap::Parser;
    use std::io::Write;
    use std::net::Ipv4Addr;

    struct FileCleanup(std::path::PathBuf);
    impl Drop for FileCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[tokio::test]
    async fn test_enumerate_subdomains_empty_wordlist_finishes_immediately() {
        // Set up mock DNS server that returns NXDOMAIN immediately for wildcard checks
        let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = mock_socket.recv_from(&mut buf).await else {
                    break;
                };
                if len >= 12 {
                    let id = u16::from_be_bytes([buf[0], buf[1]]);
                    let mut response = DnsPacket::new();
                    response.header.id = id;
                    response.header.response = true;
                    response.header.rescode = ResultCode::NXDOMAIN;
                    let mut pb = PacketBuffer::new();
                    if response.write(&mut pb).is_ok() {
                        let _ = mock_socket.send_to(pb.get_buffer_to_pos(), src).await;
                    }
                }
            }
        });

        // Create an empty temporary wordlist file
        let empty_path =
            std::env::temp_dir().join(format!("reccedns_empty_{}.txt", rand::random::<u64>()));
        std::fs::File::create(&empty_path).unwrap();
        let _cleanup = FileCleanup(empty_path.clone());

        let cmd_args = CommandArgs::try_parse_from([
            "reccedns",
            "-m",
            "s",
            "-t",
            "example.com",
            "-w",
            empty_path.to_str().unwrap(),
            "-d",
            &mock_addr.to_string(),
            "--no-dns-check",
            "--no-welcome",
            "--no-retry",
            "--quiet",
        ])
        .unwrap();

        let start = Instant::now();
        let result = enumerate_subdomains(&cmd_args, &[mock_addr]).await;
        let elapsed = start.elapsed();

        server_task.abort();

        assert!(result.is_ok(), "enumerate_subdomains failed: {result:?}");
        assert!(
            elapsed < Duration::from_millis(100),
            "enumerate_subdomains took too long ({elapsed:?}), expected < 100ms"
        );
    }

    #[tokio::test]
    async fn test_enumerate_subdomains_empty_wordlist_with_mutator_finishes_immediately() {
        let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = mock_socket.recv_from(&mut buf).await else {
                    break;
                };
                if len >= 12 {
                    let id = u16::from_be_bytes([buf[0], buf[1]]);
                    let mut response = DnsPacket::new();
                    response.header.id = id;
                    response.header.response = true;
                    response.header.rescode = ResultCode::NXDOMAIN;
                    let mut pb = PacketBuffer::new();
                    if response.write(&mut pb).is_ok() {
                        let _ = mock_socket.send_to(pb.get_buffer_to_pos(), src).await;
                    }
                }
            }
        });

        let empty_path =
            std::env::temp_dir().join(format!("reccedns_empty_mut_{}.txt", rand::random::<u64>()));
        std::fs::File::create(&empty_path).unwrap();
        let _cleanup = FileCleanup(empty_path.clone());

        let cmd_args = CommandArgs::try_parse_from([
            "reccedns",
            "-m",
            "s",
            "-t",
            "example.com",
            "-w",
            empty_path.to_str().unwrap(),
            "-d",
            &mock_addr.to_string(),
            "--mutate",
            "--no-dns-check",
            "--no-welcome",
            "--no-retry",
            "--quiet",
        ])
        .unwrap();

        let start = Instant::now();
        let result = enumerate_subdomains(&cmd_args, &[mock_addr]).await;
        let elapsed = start.elapsed();

        server_task.abort();

        assert!(
            result.is_ok(),
            "enumerate_subdomains failed with mutate: {result:?}"
        );
        assert!(
            elapsed < Duration::from_millis(100),
            "enumerate_subdomains with mutate took too long ({elapsed:?}), expected < 100ms"
        );
    }

    #[tokio::test]
    async fn test_enumerate_subdomains_blank_lines_wordlist_finishes_immediately() {
        let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = mock_socket.recv_from(&mut buf).await else {
                    break;
                };
                if len >= 12 {
                    let id = u16::from_be_bytes([buf[0], buf[1]]);
                    let mut response = DnsPacket::new();
                    response.header.id = id;
                    response.header.response = true;
                    response.header.rescode = ResultCode::NXDOMAIN;
                    let mut pb = PacketBuffer::new();
                    if response.write(&mut pb).is_ok() {
                        let _ = mock_socket.send_to(pb.get_buffer_to_pos(), src).await;
                    }
                }
            }
        });

        let blank_path =
            std::env::temp_dir().join(format!("reccedns_blank_{}.txt", rand::random::<u64>()));
        {
            let mut f = std::fs::File::create(&blank_path).unwrap();
            f.write_all(b"\r\n\n   \n\t\r\n").unwrap();
        }
        let _cleanup = FileCleanup(blank_path.clone());

        let cmd_args = CommandArgs::try_parse_from([
            "reccedns",
            "-m",
            "s",
            "-t",
            "example.com",
            "-w",
            blank_path.to_str().unwrap(),
            "-d",
            &mock_addr.to_string(),
            "--no-dns-check",
            "--no-welcome",
            "--no-retry",
            "--quiet",
        ])
        .unwrap();

        let start = Instant::now();
        let result = enumerate_subdomains(&cmd_args, &[mock_addr]).await;
        let elapsed = start.elapsed();

        server_task.abort();

        assert!(result.is_ok(), "enumerate_subdomains failed: {result:?}");
        assert!(
            elapsed < Duration::from_millis(100),
            "enumerate_subdomains took too long ({elapsed:?}), expected < 100ms"
        );
    }

    #[tokio::test]
    async fn test_enumerate_subdomains_resolves_and_finds_subdomain() {
        let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = mock_socket.recv_from(&mut buf).await else {
                    break;
                };
                if len >= 12 {
                    let mut req_buffer = PacketBuffer::new();
                    if req_buffer.set_data(&buf[..len]).is_err() {
                        continue;
                    }
                    let Ok(req_packet) = DnsPacket::from_buffer(&mut req_buffer) else {
                        continue;
                    };

                    let mut response = DnsPacket::new();
                    response.header.id = req_packet.header.id;
                    response.header.response = true;

                    let is_www = req_packet
                        .questions
                        .iter()
                        .any(|q| q.name.eq_ignore_ascii_case("www.example.com"));

                    if is_www {
                        response.header.rescode = ResultCode::NOERROR;
                        response.questions.push(DnsQuestion::new(
                            "www.example.com".to_string(),
                            QueryType::A,
                        ));
                        response.answers.push(ResourceRecord {
                            name: "www.example.com".to_string(),
                            class: 1,
                            ttl: 300,
                            data: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
                        });
                    } else {
                        response.header.rescode = ResultCode::NXDOMAIN;
                    }

                    let mut pb = PacketBuffer::new();
                    if response.write(&mut pb).is_ok() {
                        let _ = mock_socket.send_to(pb.get_buffer_to_pos(), src).await;
                    }
                }
            }
        });

        let test_path =
            std::env::temp_dir().join(format!("reccedns_test_find_{}.txt", rand::random::<u64>()));
        {
            let mut f = std::fs::File::create(&test_path).unwrap();
            f.write_all(b"www\nnonexistent\n").unwrap();
        }
        let _cleanup = FileCleanup(test_path.clone());

        let cmd_args = CommandArgs::try_parse_from([
            "reccedns",
            "-m",
            "s",
            "-t",
            "example.com",
            "-w",
            test_path.to_str().unwrap(),
            "-d",
            &mock_addr.to_string(),
            "--no-dns-check",
            "--no-welcome",
            "--no-retry",
            "--quiet",
        ])
        .unwrap();

        let start = Instant::now();
        let result = enumerate_subdomains(&cmd_args, &[mock_addr]).await;
        let elapsed = start.elapsed();

        server_task.abort();

        assert!(result.is_ok(), "enumerate_subdomains failed: {result:?}");
        assert!(
            elapsed < Duration::from_millis(500),
            "enumerate_subdomains took too long ({elapsed:?})"
        );
    }
}
