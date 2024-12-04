use anyhow::Result;
use colored::Colorize;
use std::{collections::HashSet, string, sync::atomic::Ordering};

use crate::{
    dns::{
        error::DnsError,
        protocol::{QueryType, RData, ResourceRecord},
        resolver::resolve_domain,
        resolver_selector::{self, ResolverSelector},
    },
    io::{
        cli::{self, CommandArgs},
        interrupt,
        validation::get_correct_query_types,
    },
    timing::stats::QueryTimer,
};

const IANA_TLD_URL: &str = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";
const DEFAULT_QUERY_TYPES: &[QueryType] = &[QueryType::A, QueryType::AAAA];

pub async fn expand_tlds(cmd_args: &CommandArgs, dns_resolver_list: &[&str]) -> Result<()> {
    let interrupted = interrupt::initialize_interrupt_handler()?;
    let tld_list = attempt_iana_tld_list_fetch(cmd_args).await?;

    let mut resolver_selector = resolver_selector::get_selector(cmd_args, dns_resolver_list);
    let mut query_timer = QueryTimer::new(!cmd_args.no_query_stats);

    let target_fqdn = &cmd_args.target;
    let target_base_domain = target_fqdn.rsplit('.').nth(1).unwrap_or(target_fqdn);

    let progress_bar = cli::setup_progress_bar(tld_list.len() as u64);
    progress_bar.set_message("Performing TLD expansion search...");
    progress_bar.println(format!(
        "[{}] Performing TLD Expansion for {}\n\n",
        "~".green(),
        target_base_domain.cyan().italic()
    ));

    for (idx, tld) in tld_list.iter().enumerate() {
        if interrupted.load(Ordering::SeqCst) {
            cli::clear_line();
            println!("[{}] Interrupted by user", "!".red());
            break;
        }

        cli::update_progress_bar(&progress_bar, idx, tld_list.len() as u64);
        let query_fqdn = format!("{target_base_domain}.{tld}");
        process_domain(
            &query_fqdn,
            &mut *resolver_selector,
            &mut query_timer,
            cmd_args,
        )?;
    }

    progress_bar.finish_and_clear();

    if let Some(avg) = query_timer.average() {
        if !cmd_args.no_query_stats {
            println!(
                "[{}] Average query time: {} ms",
                "~".green(),
                avg.to_string().bold().bright_yellow()
            );
        }
    }

    Ok(())
}

fn process_domain(
    domain_name: &str,
    resolver_selector: &mut dyn ResolverSelector,
    query_timer: &mut QueryTimer,
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

        cli::clear_line();
        match query_result {
            Ok(response) => {
                all_query_results.extend(response.answers);
            }
            Err(error) => {
                print_query_error(cmd_args, domain_name, resolver, &error);
            }
        }
    }

    if !all_query_results.is_empty() {
        let mut query_results: Vec<_> = all_query_results.iter().cloned().collect();
        query_results.sort_by(|a, b| a.data.to_qtype().cmp(&b.data.to_qtype()));
        let response_output = create_query_response_string(&query_results);
        print_query_result(cmd_args, domain_name, resolver, &response_output);
    }

    Ok(())
}

async fn attempt_iana_tld_list_fetch(cmd_args: &CommandArgs) -> Result<Vec<String>> {
    let spinner = cli::setup_basic_spinner();
    spinner.set_message("Fetching IANA TLD list...");

    let max_attempts = 3;
    let tld_list = {
        let mut attempt = 1;
        loop {
            match fetch_and_filter_tld_list().await {
                Ok(list) => break list,
                Err(e) if attempt < max_attempts && !cmd_args.no_retry => {
                    eprintln!(
                        "[{}] Attempt {}/{} failed: {}. Retrying...",
                        "!".red(),
                        attempt,
                        max_attempts,
                        e
                    );
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    };
    spinner.finish_and_clear();
    println!(
        "[{}] Fetched IANA TLD list with {} TLDs",
        "+".green(),
        tld_list.len()
    );
    Ok(tld_list)
}

async fn fetch_and_filter_tld_list() -> Result<Vec<String>> {
    let tld_list: Vec<String> = reqwest::get(IANA_TLD_URL)
        .await?
        .text()
        .await?
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(string::ToString::to_string)
        .map(|s| s.to_lowercase())
        .collect();

    Ok(tld_list)
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

fn print_query_result(args: &CommandArgs, domain: &str, resolver: &str, response: &str) {
    if args.quiet {
        return;
    }

    let status = "+".green();
    let domain = domain.cyan().bold();
    let mut message = format!("\r\x1b[2K[{status}] {domain}");

    if args.verbose || args.show_resolver {
        message.push_str(&format!(" [resolver: {}]", resolver.magenta()));
    }
    if !args.no_print_records {
        message.push_str(&format!(" {response}"));
    }

    println!("{message}");
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
    let status = "-".red();
    let mut message = format!("\r\x1b[2K[{status}] {domain}");

    if args.show_resolver {
        message.push_str(&format!(" [resolver: {}]", resolver.magenta()));
    }
    message.push_str(&format!(" {error}"));

    eprintln!("{message}");
}
