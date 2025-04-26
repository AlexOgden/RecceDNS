use anyhow::Result;
use colored::Colorize;
use std::fmt::Write as _;
use std::{
    cmp::max,
    collections::HashSet,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

use crate::dns::async_resolver_pool::AsyncResolverPool;
use crate::{
    dns::{
        error::DnsError,
        format::create_query_response_string,
        protocol::{QueryType, ResourceRecord},
        resolver_selector::{self},
    },
    io::{
        cli::{self, CommandArgs},
        interrupt,
        json::{DnsEnumerationOutput, Output},
        logger, wordlist,
    },
    log_error, log_info, log_success, log_warn,
    network::types::TransportProtocol,
    timing::delay,
};

const IANA_TLD_URL: &str = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";
const DEFAULT_QUERY_TYPES: &[QueryType] = &[QueryType::A, QueryType::AAAA];

type TldResult = Result<(String, String, HashSet<ResourceRecord>), (String, String, DnsError)>;
type TldResultSender = mpsc::Sender<TldResult>;

// Parameters for the worker threads.
#[derive(Clone)]
struct WorkerParams {
    connection_pool: AsyncResolverPool,
    tx: TldResultSender,
    tlds: Vec<String>,
    query_types: Vec<QueryType>,
    target_base_domain: String,
    transport: TransportProtocol,
    dns_resolvers: Vec<String>,
    use_random: bool,
    delay: Option<delay::Delay>,
    no_recursion: bool,
}

#[allow(clippy::too_many_lines)]
pub async fn expand_tlds(cmd_args: &CommandArgs, dns_resolver_list: &[&str]) -> Result<()> {
    let interrupted = interrupt::initialize_interrupt_handler()?;
    let tld_list_vec = get_tld_list(cmd_args).await?;
    let tld_set: HashSet<String> = tld_list_vec.iter().cloned().collect(); // Keep set for strip_tld

    let target_fqdn = &cmd_args.target;
    let target_base_domain = strip_tld(target_fqdn, &tld_set);

    let mut results_output = cmd_args
        .json
        .as_ref()
        .map(|_| DnsEnumerationOutput::new(cmd_args.target.clone()));

    let num_threads = cmd_args.threads.map_or_else(
        || {
            let cpus = num_cpus::get();
            if cpus > 6 { 6 } else { max(cpus - 1, 1) }
        },
        |threads| threads,
    );

    log_info!(format!(
        "Starting TLD expansion for {} with {} threads",
        target_base_domain.cyan().italic(),
        num_threads.to_string().bold()
    ));

    // Split TLD list into chunks for each thread.
    let chunk_size = tld_list_vec.len().div_ceil(num_threads);
    let tld_chunks: Vec<Vec<String>> = tld_list_vec
        .chunks(chunk_size)
        .map(<[std::string::String]>::to_vec)
        .collect();

    let progress_bar = cli::setup_progress_bar(tld_list_vec.len() as u64);
    progress_bar.set_message("Performing TLD expansion search...");

    let start_time = Instant::now();

    let (tx, mut rx) = mpsc::channel(1000);
    let pool = AsyncResolverPool::new(Some(2 * num_threads)).await?;

    let query_types = if cmd_args.query_types.is_empty() {
        DEFAULT_QUERY_TYPES.to_vec()
    } else {
        cmd_args.query_types.clone()
    };

    // Spawn worker threads.
    for chunk in tld_chunks {
        let worker_params = WorkerParams {
            connection_pool: pool.clone(),
            tx: tx.clone(),
            tlds: chunk,
            query_types: query_types.clone(),
            target_base_domain: target_base_domain.clone(),
            transport: cmd_args.transport_protocol.clone(),
            dns_resolvers: dns_resolver_list
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            use_random: cmd_args.use_random,
            delay: cmd_args.delay.clone(),
            no_recursion: cmd_args.no_recursion,
        };

        tokio::spawn(process_tld_chunk(worker_params));
    }
    drop(tx); // Close original sender.

    // Process results from the receiver.
    let mut found_count = 0;
    let mut error_count = 0;
    let mut i: u64 = 0;
    while let Some(received) = rx.recv().await {
        if interrupted.load(Ordering::SeqCst) {
            logger::clear_line();
            log_warn!("Interrupted by user".to_string(), true);
            pool.shutdown();
            break;
        }
        match received {
            Ok((fqdn, resolver, results)) => {
                let response_str = create_query_response_string(&results);
                found_count += 1;
                print_query_result(cmd_args, &fqdn, &resolver, &response_str);

                if let Some(output) = &mut results_output {
                    results.iter().for_each(|r| output.add_result(r.clone()));
                }
            }
            Err((fqdn, resolver, error)) => {
                if !matches!(
                    error,
                    DnsError::NoRecordsFound | DnsError::NonExistentDomain
                ) {
                    error_count += 1;
                }
                print_query_error(cmd_args, &fqdn, &resolver, &error);
            }
        }

        cli::update_progress_bar(
            &progress_bar,
            (i + 1).try_into().unwrap(),
            tld_list_vec.len() as u64,
            Some(error_count),
            cmd_args.delay.as_ref(),
        );
        i += 1;
    }

    progress_bar.finish_and_clear();

    let elapsed_time = start_time.elapsed();
    log_info!(
        format!(
            "Done! Found {} valid TLDs for {} in {:.2?}",
            found_count.to_string().bold(),
            target_base_domain.cyan().italic(),
            elapsed_time
        ),
        true
    );

    if let (Some(output), Some(file)) = (results_output, &cmd_args.json) {
        output.write_to_file(file)?;
    }

    pool.shutdown();

    Ok(())
}

async fn process_tld_chunk(params: WorkerParams) {
    let pool = params.connection_pool;
    let mut resolver_selector =
        resolver_selector::get_selector(params.use_random, params.dns_resolvers.clone());

    for tld in params.tlds {
        let resolver = resolver_selector
            .select()
            .unwrap_or(resolver_selector::DEFAULT_RESOLVER)
            .to_string();
        let query_fqdn = format!("{}.{}", params.target_base_domain, tld);
        let mut all_query_results = HashSet::<ResourceRecord>::new();
        let mut first_error: Option<DnsError> = None;
        let mut query_success = false;

        for query_type in &params.query_types {
            let query_result = pool
                .resolve(
                    &resolver,
                    &query_fqdn,
                    query_type,
                    &params.transport,
                    !params.no_recursion,
                )
                .await;

            // If the query succeeds, add all answer records.
            if let Ok(response) = query_result {
                all_query_results.extend(response.answers);
                query_success = true;
            } else if let Err(ref error) = query_result {
                // If it's a network error, temporarily disable this resolver.
                if let DnsError::Network(_) = error {
                    let duration = Duration::from_secs(rand::random::<u64>() % 26 + 5); // 5-30 seconds
                    resolver_selector.disable(&resolver, duration);
                }
                // Treat "no records" and "non-existent domain" as successful queries for delay logic.
                if matches!(
                    error,
                    DnsError::NoRecordsFound | DnsError::NonExistentDomain
                ) {
                    query_success = true;
                }

                first_error.get_or_insert_with(|| query_result.err().unwrap());
            }
        }

        // Report query result to adaptive delay mechanism if it's being used
        if let Some(delay) = &params.delay {
            delay.report_query_result(query_success);
        }

        // Send result back to main thread
        let send_result = if !all_query_results.is_empty() {
            params
                .tx
                .send(Ok((query_fqdn, resolver.to_string(), all_query_results)))
                .await
        } else if let Some(err) = first_error {
            params
                .tx
                .send(Err((query_fqdn, resolver.to_string(), err)))
                .await
        } else {
            Ok(())
        };

        if send_result.is_err() {
            // Receiver has likely been dropped, main thread probably exited.
            return;
        }

        if let Some(delay) = &params.delay {
            tokio::time::sleep(Duration::from_millis(delay.get_delay())).await;
        }
    }
}

fn strip_tld(domain: &str, tld_list: &HashSet<String>) -> String {
    let normalized = domain.replace(',', ".");
    let normalized_lower = normalized.to_lowercase();
    let mut tlds: Vec<&String> = tld_list.iter().collect();

    // Sort so that longer TLDs (e.g. "co.uk") come before shorter ones (e.g. "uk")
    tlds.sort_by_key(|t| std::cmp::Reverse(t.len()));

    for candidate in tlds {
        let candidate_lower = candidate.to_lowercase();
        let suffix = format!(".{candidate_lower}");
        if normalized_lower.ends_with(&suffix) {
            return normalized[..normalized.len() - suffix.len()].to_string();
        }
        if normalized_lower == candidate_lower {
            // If the input domain *is* a TLD, return empty string
            return String::new();
        }
    }

    normalized
}

async fn get_tld_list(cmd_args: &CommandArgs) -> Result<Vec<String>> {
    if let Some(wordlist_path) = &cmd_args.wordlist {
        let tld_list = wordlist::read_from_file(wordlist_path)?;
        log_success!(format!("Using wordlist with {} TLDs", tld_list.len()));
        Ok(tld_list)
    } else {
        let iana_list = retrieve_iana_tld_list(cmd_args).await?;
        log_success!(format!(
            "Fetched IANA TLD list with {} TLDs",
            iana_list.len()
        ));
        Ok(iana_list)
    }
}

async fn retrieve_iana_tld_list(cmd_args: &CommandArgs) -> Result<Vec<String>> {
    let spinner = cli::setup_basic_spinner();
    spinner.set_message("Fetching IANA TLD list...");

    let max_attempts = 3;
    let tld_list = {
        let mut attempt = 1;
        loop {
            match fetch_and_filter_tld_list().await {
                Ok(list) => break list,
                Err(e) if attempt < max_attempts && !cmd_args.no_retry => {
                    log_error!(format!(
                        "Attempt {}/{} failed: {}. Retrying...",
                        attempt, max_attempts, e
                    ));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    attempt += 1;
                }
                Err(e) => {
                    spinner.finish_and_clear();
                    return Err(e);
                }
            }
        }
    };
    spinner.finish_and_clear();
    Ok(tld_list)
}

async fn fetch_and_filter_tld_list() -> Result<Vec<String>> {
    let response = reqwest::get(IANA_TLD_URL).await?.text().await?;
    let tld_list = response
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|s| s.trim().to_lowercase())
        .collect();
    Ok(tld_list)
}

fn print_query_result(args: &CommandArgs, domain: &str, resolver: &str, response: &str) {
    if args.quiet {
        return;
    }

    let domain = domain.cyan().bold();
    let mut message = format!("{domain}");

    if args.verbose || args.show_resolver {
        let _ = write!(message, " [resolver: {}]", resolver.magenta());
    }
    if !args.no_print_records {
        let _ = write!(message, " {response}");
    }

    log_success!(message);
}

fn print_query_error(args: &CommandArgs, domain: &str, resolver: &str, error: &DnsError) {
    if (!args.verbose
        && matches!(
            error,
            DnsError::NoRecordsFound | DnsError::NonExistentDomain
        ))
        || args.quiet
        || args.no_print_errors
    {
        return;
    }

    let domain = domain.red().bold();
    let mut message = format!("{domain}");

    if args.show_resolver {
        let _ = write!(message, " [resolver: {}]", resolver.magenta());
    }
    let _ = write!(message, " {error}");

    log_error!(message);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_tld_set(tlds: &[&str]) -> HashSet<String> {
        tlds.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn test_strip_tld_simple() {
        let tlds = create_tld_set(&["com", "net"]);
        let domain = "example.com";
        let result = strip_tld(domain, &tlds);
        assert_eq!(result, "example");
    }

    #[test]
    fn test_strip_tld_with_longer_tld_priority() {
        let tlds = create_tld_set(&["uk", "co.uk"]);
        let domain = "example.co.uk";
        let result = strip_tld(domain, &tlds);
        assert_eq!(result, "example");
    }

    #[test]
    fn test_strip_tld_exact_match_returns_empty() {
        let tlds = create_tld_set(&["org"]);
        let domain = "org";
        let result = strip_tld(domain, &tlds);
        assert_eq!(result, ""); // Expect empty string if input is just a TLD
    }

    #[test]
    fn test_strip_tld_no_match_returns_original() {
        let tlds = create_tld_set(&["com", "net"]);
        let domain = "example.org";
        let result = strip_tld(domain, &tlds);
        assert_eq!(result, "example.org"); // Expect original if no TLD matches
    }

    #[test]
    fn test_strip_tld_comma_replacement() {
        let tlds = create_tld_set(&["com"]);
        let domain = "example,com";
        let result = strip_tld(domain, &tlds);
        assert_eq!(result, "example");
    }

    #[test]
    fn test_strip_tld_case_insensitive() {
        let tlds = create_tld_set(&["COM"]);
        let domain = "example.com";
        let result = strip_tld(domain, &tlds);
        assert_eq!(result, "example");
    }

    #[test]
    fn test_strip_tld_input_is_tld_itself() {
        let tlds = create_tld_set(&["com", "net", "org"]);
        let domain = "com";
        let result = strip_tld(domain, &tlds);
        assert_eq!(result, "");
    }

    #[test]
    fn test_strip_tld_input_is_longer_tld() {
        let tlds = create_tld_set(&["uk", "co.uk"]);
        let domain = "co.uk";
        let result = strip_tld(domain, &tlds);
        assert_eq!(result, "");
    }
}
