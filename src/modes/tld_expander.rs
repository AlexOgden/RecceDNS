use anyhow::Result;
use colored::Colorize;
use rand::Rng;
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::{
    cmp::max,
    collections::HashSet,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, Semaphore, mpsc},
    time,
};

use crate::dns::async_resolver::AsyncResolver;
use crate::{
    dns::{
        error::DnsError,
        format::create_query_response_string,
        protocol::{DnsPacket, QueryType, ResourceRecord},
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

type TldResult = Result<(String, Ipv4Addr, HashSet<ResourceRecord>), (String, Ipv4Addr, DnsError)>;

#[derive(Clone)]
struct QueryPlan {
    primary: QueryType,
    follow_ups: Vec<QueryType>,
    gate_followups_on_primary_hit: bool,
}

#[derive(Clone)]
struct SharedLookupContext {
    pool: AsyncResolver,
    resolver_selector: Arc<Mutex<Box<dyn resolver_selector::ResolverSelector>>>,
    transport: TransportProtocol,
    delay: Option<delay::Delay>,
    query_plan: QueryPlan,
    recursion: bool,
    base_domain: String,
}

struct QueryFailure {
    resolver: Ipv4Addr,
    error: DnsError,
}

impl QueryPlan {
    fn new(query_types: &[QueryType]) -> Self {
        if query_types.is_empty() {
            return Self {
                primary: QueryType::A,
                follow_ups: Vec::new(),
                gate_followups_on_primary_hit: false,
            };
        }

        query_types
            .iter()
            .position(|t| *t == QueryType::A)
            .map_or_else(
                || {
                    let mut iter = query_types.iter();
                    let primary = iter.next().cloned().unwrap_or(QueryType::A);
                    let follow_ups = iter.cloned().collect();
                    Self {
                        primary,
                        follow_ups,
                        gate_followups_on_primary_hit: false,
                    }
                },
                |pos| {
                    let mut follow_ups = Vec::new();
                    for (idx, query_type) in query_types.iter().enumerate() {
                        if idx != pos {
                            follow_ups.push(query_type.clone());
                        }
                    }
                    Self {
                        primary: QueryType::A,
                        follow_ups,
                        gate_followups_on_primary_hit: true,
                    }
                },
            )
    }
}

impl SharedLookupContext {
    async fn apply_delay(&self) {
        if let Some(delay) = &self.delay {
            let millis = delay.get_delay();
            if millis > 0 {
                time::sleep(Duration::from_millis(millis)).await;
            }
        }
    }

    async fn perform_query(
        &self,
        fqdn: &str,
        query_type: QueryType,
    ) -> Result<(Ipv4Addr, DnsPacket), QueryFailure> {
        let resolver = {
            let mut selector = self.resolver_selector.lock().await;
            match selector.select() {
                Ok(ip) => ip,
                Err(err) => {
                    return Err(QueryFailure {
                        resolver: resolver_selector::DEFAULT_RESOLVER,
                        error: DnsError::Internal(err.to_string()),
                    });
                }
            }
        };

        let result = self
            .pool
            .resolve(
                &resolver,
                fqdn,
                &query_type,
                &self.transport,
                self.recursion,
            )
            .await;

        match &result {
            Ok(packet) => {
                if let Some(delay) = &self.delay {
                    let has_answers = !packet.answers.is_empty();
                    delay.report_query_result(has_answers);
                }
            }
            Err(error) => {
                if let Some(delay) = &self.delay {
                    delay.report_query_result(!matches!(
                        error,
                        DnsError::Network(_)
                            | DnsError::Timeout(_)
                            | DnsError::Nameserver(_)
                            | DnsError::InvalidData(_)
                            | DnsError::ProtocolData(_)
                            | DnsError::Internal(_)
                    ));
                }
                if matches!(error, DnsError::Network(_) | DnsError::Timeout(_)) {
                    let disable_for = Duration::from_secs(rand::rng().random_range(2..=30));
                    let mut selector = self.resolver_selector.lock().await;
                    selector.disable(resolver, disable_for);
                }
            }
        }

        result
            .map(|packet| (resolver, packet))
            .map_err(|error| QueryFailure { resolver, error })
    }

    async fn execute_query(
        &self,
        fqdn: &str,
        query_type: QueryType,
        first_query: &mut bool,
    ) -> Result<(Ipv4Addr, DnsPacket), QueryFailure> {
        let should_wait = !*first_query;
        if *first_query {
            *first_query = false;
        }
        if should_wait {
            self.apply_delay().await;
        }
        self.perform_query(fqdn, query_type).await
    }
}

#[allow(clippy::too_many_lines)]
pub async fn expand_tlds(cmd_args: &CommandArgs, dns_resolver_list: &[Ipv4Addr]) -> Result<()> {
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

    let progress_bar = cli::setup_progress_bar(tld_list_vec.len() as u64);
    progress_bar.set_message("Performing TLD expansion search...");

    let start_time = Instant::now();

    let buffer_size = std::cmp::min(1000, tld_list_vec.len().max(1));
    let (tx, mut rx) = mpsc::channel(buffer_size);

    let query_types: Vec<QueryType> = if cmd_args.query_types.is_empty() {
        DEFAULT_QUERY_TYPES.to_vec()
    } else {
        cmd_args.query_types.clone()
    };
    let query_plan = QueryPlan::new(&query_types);

    let max_slots = 4096.max(num_threads);
    let slot_limit = num_threads.saturating_mul(32).clamp(num_threads, max_slots);

    let resolver_pool_target = slot_limit.max(num_threads.saturating_mul(2));
    let pool = AsyncResolver::new(Some(resolver_pool_target)).await?;

    let selector = Arc::new(Mutex::new(resolver_selector::get_selector(
        cmd_args.use_random,
        dns_resolver_list.to_vec(),
    )));

    let shared_context = Arc::new(SharedLookupContext {
        pool: pool.clone(),
        resolver_selector: selector,
        transport: cmd_args.transport_protocol.clone(),
        delay: cmd_args.delay.clone(),
        query_plan: query_plan.clone(),
        recursion: !cmd_args.no_recursion,
        base_domain: target_base_domain.clone(),
    });

    let semaphore = Arc::new(Semaphore::new(slot_limit));

    for tld in &tld_list_vec {
        let tld = tld.clone();
        let ctx = shared_context.clone();
        let permit_pool = semaphore.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let Ok(permit) = permit_pool.acquire_owned().await else {
                return;
            };

            let outcome = resolve_tld(ctx.as_ref(), &tld).await;
            let _ = tx_clone.send(outcome).await;

            drop(permit);
        });
    }
    drop(tx);

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
                print_query_result(cmd_args, &fqdn, resolver, &response_str);

                if let Some(output) = &mut results_output {
                    for r in &results {
                        output.add_result(r.clone());
                    }
                }
            }
            Err((fqdn, resolver, error)) => {
                if !matches!(
                    error,
                    DnsError::NoRecordsFound | DnsError::NonExistentDomain
                ) {
                    error_count += 1;
                }
                print_query_error(cmd_args, &fqdn, resolver, &error);
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

async fn resolve_tld(ctx: &SharedLookupContext, tld: &str) -> TldResult {
    let fqdn = if ctx.base_domain.is_empty() {
        tld.to_string()
    } else {
        format!("{}.{}", ctx.base_domain, tld)
    };

    let mut aggregated = HashSet::new();
    let mut first_failure: Option<QueryFailure> = None;
    let mut success_resolver: Option<Ipv4Addr> = None;
    let mut first_query = true;

    let primary_result = ctx
        .execute_query(&fqdn, ctx.query_plan.primary.clone(), &mut first_query)
        .await;

    match primary_result {
        Ok((resolver, packet)) => {
            aggregated.extend(packet.answers.into_iter());
            success_resolver = Some(resolver);
        }
        Err(failure) => {
            let terminal = matches!(failure.error, DnsError::NonExistentDomain);
            if ctx.query_plan.gate_followups_on_primary_hit && terminal {
                return Err((fqdn, failure.resolver, failure.error));
            }
            first_failure = Some(failure);
        }
    }

    for query_type in &ctx.query_plan.follow_ups {
        match ctx
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
        Ok((fqdn, resolver, aggregated))
    } else if let Some(failure) = first_failure {
        Err((fqdn, failure.resolver, failure.error))
    } else {
        Err((
            fqdn,
            resolver_selector::DEFAULT_RESOLVER,
            DnsError::NoRecordsFound,
        ))
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
        let tld_list = wordlist::read_subdomain_list(wordlist_path)?;
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

fn print_query_result(args: &CommandArgs, domain: &str, resolver: Ipv4Addr, response: &str) {
    if args.quiet {
        return;
    }

    let domain = domain.cyan().bold();
    let mut message = format!("{domain}");

    if args.verbose || args.show_resolver {
        let _ = write!(message, " [resolver: {}]", resolver.to_string().magenta());
    }
    if !args.no_print_records {
        let _ = write!(message, " {response}");
    }

    log_success!(message);
}

fn print_query_error(args: &CommandArgs, domain: &str, resolver: Ipv4Addr, error: &DnsError) {
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
        let _ = write!(message, " [resolver: {}]", resolver.to_string().magenta());
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
