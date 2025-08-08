use colored::Colorize;

use crate::{
    dns::{
        async_resolver::AsyncResolver,
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
use std::{collections::HashSet, net::Ipv4Addr};

const DEFAULT_QUERY_TYPES: &[QueryType] = &[
    QueryType::A,
    QueryType::AAAA,
    QueryType::CNAME,
    QueryType::MX,
    QueryType::TXT,
    QueryType::NS,
    QueryType::SOA,
];

pub async fn enumerate_records(cmd_args: &CommandArgs, dns_resolvers: &[Ipv4Addr]) -> Result<()> {
    println!(
        "Enumerating records for target domain: {}\n",
        cmd_args.target.bold().bright_blue()
    );

    let mut data_output = cmd_args
        .json
        .as_ref()
        .map(|_| DnsEnumerationOutput::new(cmd_args.target.clone()));

    let query_types: &[QueryType] = match cmd_args.query_types.as_slice() {
        [] | [QueryType::ANY] => DEFAULT_QUERY_TYPES,
        qt => qt,
    };

    let resolver = dns_resolvers[0];
    let domain = &cmd_args.target;
    let mut seen_cnames = HashSet::new();
    let mut query_timer = QueryTimer::new(!cmd_args.no_query_stats);
    let resolver_pool = AsyncResolver::new(Some(1)).await?;

    check_dnssec(&resolver_pool, &resolver, domain, cmd_args).await?;

    for query_type in query_types {
        query_timer.start();
        let query_result = resolver_pool
            .resolve(
                &resolver,
                domain,
                query_type,
                &cmd_args.transport_protocol,
                !&cmd_args.no_recursion,
            )
            .await;
        query_timer.stop();

        match query_result {
            Ok(mut response) => {
                response.answers.sort_by_key(|a| a.data.to_qtype());
                process_response(
                    &resolver_pool,
                    &mut seen_cnames,
                    &response.answers,
                    &resolver,
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

async fn check_dnssec(
    resolver_pool: &AsyncResolver,
    resolver: &Ipv4Addr,
    domain: &str,
    cmd_args: &CommandArgs,
) -> Result<()> {
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
    resolver_pool: &AsyncResolver,
    seen_cnames: &mut HashSet<String>,
    response: &[ResourceRecord],
    resolver: &Ipv4Addr,
    data_output: &mut Option<DnsEnumerationOutput>,
    cmd_args: &CommandArgs,
) -> Result<()> {
    for record in response {
        process_and_format_record(
            resolver_pool,
            seen_cnames,
            record,
            resolver,
            data_output,
            cmd_args,
        )
        .await?;
    }
    Ok(())
}

async fn process_and_format_record(
    resolver_pool: &AsyncResolver,
    seen_cnames: &mut HashSet<String>,
    record: &ResourceRecord,
    resolver: &Ipv4Addr,
    data_output: &mut Option<DnsEnumerationOutput>,
    cmd_args: &CommandArgs,
) -> Result<()> {
    if let RData::CNAME(cname) = &record.data
        && !seen_cnames.insert(cname.clone())
    {
        return Ok(()); // Skip if CNAME is already seen
    }

    // Add to JSON output
    if let Some(output) = data_output {
        output.add_result(record.clone());
    }

    let query_type_formatted = record.data.to_qtype().to_string().bold().bright_cyan();

    let response_data_string_result = match &record.data {
        RData::A(a_record) => Ok(format_response(
            &query_type_formatted,
            &a_record.to_string(),
        )),
        RData::AAAA(aaaa_record) => Ok(format_response(
            &query_type_formatted,
            &aaaa_record.to_string(),
        )),
        RData::TXT(txt_data) => Ok(format_response(&query_type_formatted, txt_data)),
        RData::CNAME(cname) => Ok(format_response(&query_type_formatted, cname)),
        RData::NS(ns_domain) => {
            let mut result = format_response(&query_type_formatted, ns_domain);
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
                    Ok(ip_records) => {
                        for ip_record in ip_records.answers {
                            result.push(' ');
                            match ip_record.data {
                                RData::A(a_rec) => {
                                    result.push_str(&format_response("A", &a_rec.to_string()));
                                }
                                RData::AAAA(aaaa_rec) => {
                                    result
                                        .push_str(&format_response("AAAA", &aaaa_rec.to_string()));
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(DnsError::NoRecordsFound) => {}
                    Err(err) => return Err(err.into()),
                }
            }
            Ok(result)
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
    };

    let response_data_string = response_data_string_result?;

    if !cmd_args.quiet {
        println!("{response_data_string}");
    }

    Ok(())
}

fn format_response(query_type: &str, content: &str) -> String {
    format!("[{} {}]", query_type.bold().bright_cyan(), content)
}
