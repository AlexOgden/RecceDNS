use colored::Colorize;

use crate::{
    dns::{
        async_resolver_pool::AsyncResolverPool,
        error::DnsError,
        protocol::{QueryType, RData, ResourceRecord},
    },
    io::{
        cli::CommandArgs,
        json::{DnsEnumerationOutput, Output},
    },
    log_info,
    timing::stats::QueryTimer,
};
use anyhow::Result;
use std::collections::HashSet;

const DEFAULT_QUERY_TYPES: &[QueryType] = &[
    QueryType::A,
    QueryType::AAAA,
    QueryType::CNAME,
    QueryType::MX,
    QueryType::TXT,
    QueryType::NS,
    QueryType::SOA,
];

pub async fn enumerate_records(cmd_args: &CommandArgs, dns_resolvers: &[&str]) -> Result<()> {
    println!(
        "Enumerating records for target domain: {}\n",
        cmd_args.target.bold().bright_blue()
    );

    let mut data_output = cmd_args
        .json
        .as_ref()
        .map(|_| DnsEnumerationOutput::new(cmd_args.target.clone()));

    let query_types = if cmd_args.query_types.is_empty() {
        DEFAULT_QUERY_TYPES.to_vec()
    } else {
        cmd_args.query_types.clone()
    };
    let resolver = dns_resolvers[0];
    let domain = &cmd_args.target;
    let mut seen_cnames = HashSet::new();
    let mut query_timer = QueryTimer::new(!cmd_args.no_query_stats);

    check_dnssec(resolver, domain, cmd_args).await?;

    let resolver_pool = AsyncResolverPool::new(Some(1)).await?;

    for query_type in query_types {
        query_timer.start();
        let query_result = resolver_pool
            .resolve(
                resolver,
                domain,
                &query_type,
                &cmd_args.transport_protocol,
                !&cmd_args.no_recursion,
            )
            .await;
        query_timer.stop();

        match query_result {
            Ok(mut response) => {
                response.answers.sort_by_key(|a| a.data.to_qtype());
                process_response(
                    &mut seen_cnames,
                    &response.answers,
                    resolver,
                    &mut data_output,
                    cmd_args,
                )
                .await?;
            }
            Err(err) if !matches!(err, DnsError::NoRecordsFound | DnsError::NonExistentDomain) => {
                eprintln!("{query_type} {err}");
            }
            _ => {}
        }
    }

    if let Some(average_query_time) = query_timer.average() {
        log_info!(
            format!(
                "Average query time: {} ms",
                average_query_time.to_string().bold().bright_yellow()
            ),
            true
        );
    }

    if let (Some(output_file), Some(data_output)) = (&cmd_args.json, data_output) {
        data_output.write_to_file(output_file)?;
    }

    Ok(())
}

async fn check_dnssec(resolver: &str, domain: &str, cmd_args: &CommandArgs) -> Result<()> {
    let resolver_pool = AsyncResolverPool::new(Some(1)).await?;
    let response = resolver_pool
        .resolve(
            resolver,
            domain,
            &QueryType::DNSKEY,
            &cmd_args.transport_protocol,
            !&cmd_args.no_recursion,
        )
        .await;

    let dnssec_status = match response {
        Ok(response) if response.answers.is_empty() => "is not enabled",
        Ok(_) => "is enabled",
        Err(DnsError::NoRecordsFound) => "is not enabled",
        Err(err) => return Err(err.into()),
    };

    if !cmd_args.quiet {
        println!("{}", format_response("DNSSEC", dnssec_status));
    }
    Ok(())
}

async fn process_response(
    seen_cnames: &mut HashSet<String>,
    response: &[ResourceRecord],
    resolver: &str,
    data_output: &mut Option<DnsEnumerationOutput>,
    cmd_args: &CommandArgs,
) -> Result<()> {
    for record in response {
        if let RData::CNAME(cname) = &record.data {
            if !seen_cnames.insert(cname.clone()) {
                continue; // Skip if CNAME is already seen
            }
        }
        if let Some(data_output) = data_output {
            data_output.add_result(record.clone());
        }
        let response_data_string = create_query_response_string(record, resolver, cmd_args).await?;
        if !cmd_args.quiet {
            println!("{response_data_string}");
        }
    }
    Ok(())
}

fn format_response(query_type: &str, content: &str) -> String {
    format!("[{} {}]", query_type.bold().bright_cyan(), content)
}

async fn handle_ns_response(
    query_type_formatted: &str,
    domain: &str,
    resolver: &str,
    ns_domain: &str,
    cmd_args: &CommandArgs,
) -> Result<String, DnsError> {
    let mut result = format_response(query_type_formatted, domain);
    let resolver_pool = AsyncResolverPool::new(Some(1)).await?;
    for query_type in [QueryType::A, QueryType::AAAA] {
        match resolver_pool
            .resolve(
                resolver,
                ns_domain,
                &query_type,
                &cmd_args.transport_protocol,
                !&cmd_args.no_recursion,
            )
            .await
        {
            Ok(records) => {
                for record in records.answers {
                    result.push(' ');
                    match record.data {
                        RData::A(a_record) => {
                            result.push_str(&format_response("A", &a_record.to_string()));
                        }
                        RData::AAAA(aaaa_record) => {
                            result.push_str(&format_response("AAAA", &aaaa_record.to_string()));
                        }
                        _ => {}
                    }
                }
            }
            Err(DnsError::NoRecordsFound) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(result)
}

async fn create_query_response_string(
    query_response: &ResourceRecord,
    resolver: &str,
    cmd_args: &CommandArgs,
) -> Result<String> {
    let query_type_formatted = query_response
        .data
        .to_qtype()
        .to_string()
        .bold()
        .bright_cyan();
    match &query_response.data {
        RData::A(record) => Ok(format_response(&query_type_formatted, &record.to_string())),
        RData::AAAA(record) => Ok(format_response(&query_type_formatted, &record.to_string())),
        RData::TXT(txt_data) => Ok(format_response(&query_type_formatted, txt_data)),
        RData::CNAME(cname) => Ok(format_response(&query_type_formatted, cname)),
        RData::NS(domain) => {
            Ok(
                handle_ns_response(&query_type_formatted, domain, resolver, domain, cmd_args)
                    .await?,
            )
        }
        RData::MX {
            preference,
            exchange,
        } => Ok(format!("[{query_type_formatted} {preference} {exchange}]")),
        RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => Ok(format!(
            "[{query_type_formatted} {mname} {rname} {serial} {refresh} {retry} {expire} {minimum}]"
        )),
        RData::SRV {
            priority,
            weight,
            port,
            target,
        } => Ok(format!(
            "[{query_type_formatted} {priority} {weight} {port} {target}]"
        )),
        RData::DNSKEY { .. } => Ok(format!("[{} Enabled]", "DNSSEC".bold().bright_cyan())),
        RData::Unknown { qtype, data_len } => Err(anyhow::Error::msg(format!(
            "Unsupported data type: {qtype} with length {data_len} bytes"
        ))),
        RData::PTR { .. } => Err(anyhow::Error::msg("PTR query type is unsupported")),
    }
}
