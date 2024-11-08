use colored::Colorize;

use crate::{
    dns::{
        error::DnsError,
        protocol::{DnsQueryResponse, DnsRecord, QueryType},
        resolver::resolve_domain,
    },
    io::cli::CommandArgs,
};
use anyhow::Result;
use std::collections::HashSet;

pub fn enumerate_records(args: &CommandArgs, dns_resolvers: &[&str]) -> Result<()> {
    println!(
        "Enumerating records for target domain: {}\n",
        args.target_domain.bold().bright_blue()
    );

    let resolver = dns_resolvers[0];
    let domain = &args.target_domain;
    let query_types = get_query_types();
    let mut seen_cnames = HashSet::new();

    check_dnssec(resolver, domain, args)?;

    for query_type in query_types {
        match resolve_domain(resolver, domain, &query_type, &args.transport_protocol) {
            Ok(mut response) => {
                response.sort_by(|a, b| a.query_type.cmp(&b.query_type));
                process_response(&mut seen_cnames, &response, resolver, args)?;
            }
            Err(err) if !matches!(err, DnsError::NoRecordsFound | DnsError::NonExistentDomain) => {
                eprintln!("{query_type} {err}");
            }
            _ => {}
        }
    }

    Ok(())
}

fn check_dnssec(resolver: &str, domain: &str, args: &CommandArgs) -> Result<()> {
    let response = resolve_domain(
        resolver,
        domain,
        &QueryType::DNSKEY,
        &args.transport_protocol,
    );
    match response {
        Ok(response) if response.is_empty() => {
            println!("{}", format_response("DNSSEC", "is not enabled"));
        }
        Ok(_) => {
            println!("{}", format_response("DNSSEC", "is enabled"));
        }
        Err(DnsError::NoRecordsFound) => {
            println!("{}", format_response("DNSSEC", "is not enabled"));
        }
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

fn get_query_types() -> Vec<QueryType> {
    vec![
        QueryType::A,
        QueryType::AAAA,
        QueryType::CNAME,
        QueryType::MX,
        QueryType::TXT,
        QueryType::NS,
        QueryType::SOA,
    ]
}

fn process_response(
    seen_cnames: &mut HashSet<String>,
    response: &[DnsQueryResponse],
    resolver: &str,
    args: &CommandArgs,
) -> Result<()> {
    for record in response {
        if let DnsRecord::CNAME(ref cname) = record.response_content {
            if !seen_cnames.insert(cname.data.clone()) {
                continue; // Skip if CNAME is already seen
            }
        }
        let response_data_string = create_query_response_string(record, resolver, args)?;
        println!("{response_data_string}");
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
    args: &CommandArgs,
) -> Result<String, DnsError> {
    let mut result = format_response(query_type_formatted, domain);

    for query_type in [QueryType::A, QueryType::AAAA] {
        match resolve_domain(resolver, ns_domain, &query_type, &args.transport_protocol) {
            Ok(records) => {
                for record in records {
                    result.push(' ');
                    match record.response_content {
                        DnsRecord::A(a_record) => {
                            result.push_str(&format_response("A", &a_record.addr.to_string()));
                        }
                        DnsRecord::AAAA(aaaa_record) => {
                            result
                                .push_str(&format_response("AAAA", &aaaa_record.addr.to_string()));
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
    query_response: &DnsQueryResponse,
    resolver: &str,
    args: &CommandArgs,
) -> Result<String> {
    let query_type_formatted = query_response.query_type.to_string().bold().bright_cyan();
    match &query_response.response_content {
        DnsRecord::A(record) => Ok(format_response(
            &query_type_formatted,
            &record.addr.to_string(),
        )),
        DnsRecord::AAAA(record) => Ok(format_response(
            &query_type_formatted,
            &record.addr.to_string(),
        )),
        DnsRecord::TXT(txt_data) => Ok(format_response(&query_type_formatted, &txt_data.data)),
        DnsRecord::CNAME(cname) => Ok(format_response(&query_type_formatted, &cname.data)),
        DnsRecord::NS(domain) => Ok(handle_ns_response(
            &query_type_formatted,
            &domain.data,
            resolver,
            &domain.data,
            args,
        )?),
        DnsRecord::MX(mx) => Ok(format!(
            "[{} {} {}]",
            query_type_formatted, mx.priority, mx.domain
        )),
        DnsRecord::SOA(soa) => Ok(format!(
            "[{} {} {} {} {} {} {} {}]",
            query_type_formatted,
            soa.mname,
            soa.rname,
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        )),
        DnsRecord::SRV(srv) => Ok(format!(
            "[{} {} {} {} {}]",
            query_type_formatted, srv.priority, srv.weight, srv.port, srv.target
        )),
        DnsRecord::DNSKEY(_dnskey) => Ok(format!("[{} Enabled]", "DNSSEC".bold().bright_cyan())),
    }
}
