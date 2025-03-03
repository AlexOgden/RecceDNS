use anyhow::Result;
use colored::Colorize;
use std::{collections::HashSet, sync::atomic::Ordering, thread, time::Duration};

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
        logger,
        validation::get_correct_query_types,
        wordlist,
    },
    log_error, log_info, log_success, log_warn,
    timing::stats::QueryTimer,
};

const IANA_TLD_URL: &str = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";
const DEFAULT_QUERY_TYPES: &[QueryType] = &[QueryType::A, QueryType::AAAA];

pub async fn expand_tlds(cmd_args: &CommandArgs, dns_resolver_list: &[&str]) -> Result<()> {
    let interrupted = interrupt::initialize_interrupt_handler()?;
    let tld_list = get_tld_list(cmd_args).await?;

    let mut resolver_selector = resolver_selector::get_selector(cmd_args, dns_resolver_list);
    let mut query_timer = QueryTimer::new(!cmd_args.no_query_stats);
    let mut results_output = cmd_args
        .json
        .as_ref()
        .map(|_| DnsEnumerationOutput::new(cmd_args.target.clone()));

    let target_fqdn = &cmd_args.target;
    let target_base_domain = strip_tld(target_fqdn, &tld_list);

    let progress_bar = cli::setup_progress_bar(tld_list.len() as u64);
    progress_bar.set_message("Performing TLD expansion search...");

    log_info!(format!(
        "Performing TLD Expansion for {}",
        target_base_domain.cyan().italic()
    ));

    for (idx, tld) in tld_list.iter().enumerate() {
        if interrupted.load(Ordering::SeqCst) {
            logger::clear_line();
            log_warn!("Interrupted by user".to_string(), true);
            break;
        }

        cli::update_progress_bar(&progress_bar, idx, tld_list.len() as u64);
        let query_fqdn = format!("{target_base_domain}.{tld}");
        process_domain(
            &query_fqdn,
            &mut *resolver_selector,
            &mut query_timer,
            &mut results_output,
            cmd_args,
        )?;

        if let Some(delay_ms) = &cmd_args.delay {
            if let Some(sleep_delay) = delay_ms.get_delay().checked_sub(0) {
                thread::sleep(Duration::from_millis(sleep_delay));
            }
        }
    }

    progress_bar.finish_and_clear();

    if let Some(avg) = query_timer.average() {
        if !cmd_args.no_query_stats {
            log_info!(format!(
                "Average query time: {} ms",
                avg.to_string().bold().bright_yellow()
            ));
        }
    }

    if let (Some(output), Some(file)) = (results_output, &cmd_args.json) {
        output.write_to_file(file)?;
    }
    Ok(())
}

fn process_domain(
    domain_name: &str,
    resolver_selector: &mut dyn ResolverSelector,
    query_timer: &mut QueryTimer,
    results_output: &mut Option<DnsEnumerationOutput>,
    cmd_args: &CommandArgs,
) -> Result<()> {
    let resolver = resolver_selector.select()?;
    let query_types = get_correct_query_types(&cmd_args.query_types, DEFAULT_QUERY_TYPES);

    let mut all_query_results: HashSet<ResourceRecord> = HashSet::new();

    for query_type in query_types {
        query_timer.start();
        let query_result = resolve_domain(
            resolver,
            domain_name,
            &query_type,
            &cmd_args.transport_protocol,
            !cmd_args.no_recursion,
        );
        query_timer.stop();

        match query_result {
            Ok(response) => {
                all_query_results.extend(response.answers);
            }
            Err(error) => {
                if !error.to_string().contains("(os error 4)") {
                    print_query_error(cmd_args, domain_name, resolver, &error);
                }
            }
        }
    }

    if !all_query_results.is_empty() {
        let response_output = create_query_response_string(&all_query_results);
        print_query_result(cmd_args, domain_name, resolver, &response_output);

        if let Some(output) = results_output {
            all_query_results
                .iter()
                .for_each(|r| output.add_result(r.clone()));
        }
    }

    Ok(())
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
            return String::new();
        }
    }

    normalized
}

async fn get_tld_list(cmd_args: &CommandArgs) -> Result<HashSet<String>> {
    if let Some(wordlist_path) = &cmd_args.wordlist {
        let tld_list = wordlist::read_from_file(wordlist_path)?;
        let tld_set: HashSet<String> = tld_list.into_iter().collect();
        log_success!(format!("Using wordlist with {} TLDs", tld_set.len()));
        Ok(tld_set)
    } else {
        let iana_list = retrieve_iana_tld_list(cmd_args).await?;
        let tld_set: HashSet<String> = iana_list.into_iter().collect();
        log_success!(format!("Fetched IANA TLD list with {} TLDs", tld_set.len()));
        Ok(tld_set)
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
                    thread::sleep(Duration::from_secs(2));
                    attempt += 1;
                }
                Err(e) => return Err(e),
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
        .filter(|line| !line.starts_with('#'))
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
        message.push_str(&format!(" [resolver: {}]", resolver.magenta()));
    }
    if !args.no_print_records {
        message.push_str(&format!(" {response}"));
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
    {
        return;
    }

    let domain = domain.red().bold();
    let mut message = format!("{domain}");

    if args.show_resolver {
        message.push_str(&format!(" [resolver: {}]", resolver.magenta()));
    }
    message.push_str(&format!(" {error}"));

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
        assert_eq!(result, "");
    }

    #[test]
    fn test_strip_tld_no_match_returns_original() {
        let tlds = create_tld_set(&["com", "net"]);
        let domain = "example.org";
        let result = strip_tld(domain, &tlds);
        assert_eq!(result, "example.org");
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
}
