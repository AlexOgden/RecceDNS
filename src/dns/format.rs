use colored::Colorize;

use crate::dns::protocol::RData;

use super::protocol::ResourceRecord;

pub fn create_query_response_string(query_result: &[ResourceRecord]) -> String {
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
