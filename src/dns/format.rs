use std::collections::{HashMap, HashSet};

use crate::dns::protocol::RData;

use super::protocol::ResourceRecord;

pub fn create_query_response_string(query_result: &HashSet<ResourceRecord>) -> String {
    // Group ResourceRecords by their domain name and record type
    let mut domain_map: HashMap<&str, HashMap<&str, HashSet<String>>> = HashMap::new();

    for response in query_result {
        let (record_type, record_data) = match &response.data {
            RData::A(record) => ("A", record.to_string()),
            RData::AAAA(record) => ("AAAA", record.to_string()),
            RData::TXT(txt_data) => ("TXT", txt_data.to_string()),
            RData::CNAME(domain) => ("CNAME", domain.to_string()),
            RData::NS(domain) => ("NS", domain.to_string()),
            RData::PTR(domain) => ("PTR", domain.to_string()),
            RData::MX {
                preference,
                exchange,
            } => ("MX", format!("{preference} {exchange}")),
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => (
                "SOA",
                format!(
                    "{mname} {rname} Serial:{serial} Refresh:{refresh} Retry:{retry} Expire:{expire} Minimum:{minimum}"
                ),
            ),
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => (
                "SRV",
                format!(
                    "Priority:{priority} Weight:{weight} Port:{port} Target:{target}"
                ),
            ),
            RData::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key: _,
            } => (
                "DNSKEY",
                format!(
                    "Flags:{flags} Protocol:{protocol} Algorithm:{algorithm}"
                ),
            ),
            RData::Unknown { qtype, data_len } => {
                ("Unknown", format!("{qtype}: {data_len} bytes"))
            }
        };

        domain_map
            .entry(&response.name)
            .or_default()
            .entry(record_type)
            .or_default()
            .insert(record_data);
    }

    // Prepare the final formatted output
    let formatted_domains: Vec<String> = domain_map
        .iter()
        .map(|(domain, records)| {
            let mut formatted_records: Vec<String> = records
                .iter()
                .map(|(record_type, data_set)| {
                    let mut sorted_data: Vec<&str> =
                        data_set.iter().map(std::string::String::as_str).collect();
                    sorted_data.sort_unstable();
                    format!("    {}: [{}]", record_type, sorted_data.join(", "))
                })
                .collect();
            formatted_records.sort();
            format!("  {}:\n{}", domain, formatted_records.join("\n"))
        })
        .collect();

    format!("\n{}", formatted_domains.join("\n\n"))
}
