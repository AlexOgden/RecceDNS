use colored::Colorize;

use crate::{
    dns::{
        resolver::resolve_domain,
        types::{QueryResponse, QueryType, ResponseType},
    },
    io::cli::CommandArgs,
};
use anyhow::{anyhow, Result};
use std::collections::HashSet;

pub fn enumerate_records(args: &CommandArgs, dns_resolvers: &[&str]) -> Result<()> {
    println!(
        "Enumerating records for target domain: {}\n",
        args.target_domain.bold().bright_blue()
    );

    let resolver = dns_resolvers[0];
    let domain = &args.target_domain;
    let query_types = vec![
        QueryType::A,
        QueryType::AAAA,
        QueryType::CNAME,
        QueryType::MX,
        QueryType::NS,
        QueryType::SOA,
        QueryType::TXT,
    ];

    let mut seen_cnames = HashSet::new();

    for query_type in query_types {
        match resolve_domain(resolver, domain, &query_type) {
            Ok(mut response) => {
                response.sort_by(|a, b| a.query_type.cmp(&b.query_type));
                for record in response {
                    if let ResponseType::CNAME(ref cname) = record.response_content {
                        if !seen_cnames.insert(cname.clone()) {
                            continue; // Skip if CNAME is already seen
                        }
                    }
                    let response_data_string = create_query_response_string(&record, resolver)?;
                    println!("{response_data_string}");
                }
            }
            Err(err) => {
                if err.to_string() == "No record found" {
                    continue;
                }
                eprintln!("{err}");
                return Err(anyhow!("Error querying with resolver {resolver}"));
            }
        }
    }

    Ok(())
}

fn format_response(query_type: &str, content: &str) -> String {
    format!("[{} {}]", query_type.bold(), content)
}

fn handle_ns_response(
    query_type_formatted: &str,
    domain: &str,
    resolver: &str,
    ns_domain: &str,
) -> Result<String> {
    let mut result = format_response(query_type_formatted, domain);
    let a_records = resolve_domain(resolver, ns_domain, &QueryType::A)?;
    let aaaa_records = resolve_domain(resolver, ns_domain, &QueryType::AAAA)?;
    for a_record in a_records {
        if let ResponseType::IPv4(ip) = a_record.response_content {
            result.push_str(&format!(" [{} {}]", "A".bold(), ip));
        }
    }
    for aaaa_record in aaaa_records {
        if let ResponseType::IPv6(ip) = aaaa_record.response_content {
            result.push_str(&format!(" [{} {}]", "AAAA".bold(), ip));
        }
    }
    Ok(result)
}

fn create_query_response_string(query_response: &QueryResponse, resolver: &str) -> Result<String> {
    let query_type_formatted = query_response.query_type.to_string().bold();
    match &query_response.response_content {
        ResponseType::IPv4(ip) => Ok(format_response(&query_type_formatted, &ip.to_string())),
        ResponseType::IPv6(ip) => Ok(format_response(&query_type_formatted, &ip.to_string())),
        ResponseType::TXT(txt_data) => Ok(format_response(&query_type_formatted, txt_data)),
        ResponseType::CNAME(domain) | ResponseType::NS(domain) => {
            if let ResponseType::NS(ns_domain) = &query_response.response_content {
                handle_ns_response(&query_type_formatted, domain, resolver, ns_domain)
            } else {
                Ok(format_response(&query_type_formatted, domain))
            }
        }
        ResponseType::MX(mx) => Ok(format!(
            "[{} {} {}]",
            query_type_formatted, mx.priority, mx.domain
        )),
        ResponseType::SOA(soa) => Ok(format!(
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
    }
}
