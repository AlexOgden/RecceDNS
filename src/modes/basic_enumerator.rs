use colored::Colorize;

use crate::{
    dns::{
        error::DnsError,
        protocol::{QueryType, RData, ResourceRecord},
        resolver::resolve_domain,
    },
    io::{cli::CommandArgs, json::EnumerationOutput},
    timing::stats::QueryTimer,
};
use anyhow::Result;
use std::collections::HashSet;

pub fn enumerate_records(cmd_args: &CommandArgs, dns_resolvers: &[&str]) -> Result<()> {
    const QUERY_TYPES: &[QueryType] = &[
        QueryType::A,
        QueryType::AAAA,
        QueryType::CNAME,
        QueryType::MX,
        QueryType::TXT,
        QueryType::NS,
        QueryType::SOA,
    ];

    println!(
        "Enumerating records for target domain: {}\n",
        cmd_args.target.bold().bright_blue()
    );

    let mut data_output = if cmd_args.json.is_some() {
        Some(EnumerationOutput::new(cmd_args.target.clone()))
    } else {
        None
    };
    let resolver = dns_resolvers[0];
    let domain = &cmd_args.target;
    let mut seen_cnames = HashSet::new();
    let mut query_timer = QueryTimer::new(!cmd_args.no_query_stats);

    check_dnssec(resolver, domain, cmd_args)?;

    for query_type in QUERY_TYPES {
        query_timer.start();
        let query_result =
            resolve_domain(resolver, domain, query_type, &cmd_args.transport_protocol);
        query_timer.stop();

        match query_result {
            Ok(mut response) => {
                response
                    .answers
                    .sort_by(|a, b| a.data.to_qtype().cmp(&b.data.to_qtype()));
                process_response(
                    &mut seen_cnames,
                    &response.answers,
                    resolver,
                    &mut data_output,
                    cmd_args,
                )?;
            }
            Err(err) if !matches!(err, DnsError::NoRecordsFound | DnsError::NonExistentDomain) => {
                eprintln!("{query_type} {err}");
            }
            _ => {}
        }
    }

    if let Some(average_query_time) = query_timer.average() {
        println!(
            "\n[{}] Average query time: {} ms",
            "~".green(),
            average_query_time.to_string().bold().bright_yellow()
        );
    }

    if let (Some(output_file), Some(data_output)) = (&cmd_args.json, data_output) {
        data_output.write_to_file(output_file)?;
    }
    Ok(())
}

fn check_dnssec(resolver: &str, domain: &str, cmd_args: &CommandArgs) -> Result<()> {
    let response = resolve_domain(
        resolver,
        domain,
        &QueryType::DNSKEY,
        &cmd_args.transport_protocol,
    );

    let dnssec_status = match response {
        Ok(response) if response.answers.is_empty() => "is not enabled",
        Ok(_) => "is enabled",
        Err(DnsError::NoRecordsFound) => "is not enabled",
        Err(err) => return Err(err.into()),
    };

    println!("{}", format_response("DNSSEC", dnssec_status));
    Ok(())
}

fn process_response(
    seen_cnames: &mut HashSet<String>,
    response: &[ResourceRecord],
    resolver: &str,
    data_output: &mut Option<EnumerationOutput>,
    cmd_args: &CommandArgs,
) -> Result<()> {
    for record in response {
        if let RData::CNAME(ref cname) = record.data {
            if !seen_cnames.insert(cname.clone()) {
                continue; // Skip if CNAME is already seen
            }
        }
        if let Some(data_output) = data_output {
            data_output.add_result(record.clone());
        }
        let response_data_string = create_query_response_string(record, resolver, cmd_args)?;
        if !cmd_args.quiet {
            println!("{response_data_string}");
        }
    }
    Ok(())
}

fn format_response(query_type: &str, content: &str) -> String {
    format!("[{} {}]", query_type.bold().bright_cyan(), content)
}

fn handle_ns_response(
    query_type_formatted: &str,
    domain: &str,
    resolver: &str,
    ns_domain: &str,
    cmd_args: &CommandArgs,
) -> Result<String, DnsError> {
    let mut result = format_response(query_type_formatted, domain);

    for query_type in [QueryType::A, QueryType::AAAA] {
        match resolve_domain(
            resolver,
            ns_domain,
            &query_type,
            &cmd_args.transport_protocol,
        ) {
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

fn create_query_response_string(
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
        RData::NS(domain) => Ok(handle_ns_response(
            &query_type_formatted,
            domain,
            resolver,
            domain,
            cmd_args,
        )?),
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
