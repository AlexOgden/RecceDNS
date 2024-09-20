use anyhow::{anyhow, Result};

use crate::dns::types::{MXResponse, QueryResponse, QueryType, ResponseType, SOAResponse};
use rand::Rng;
use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
};

pub fn resolve_domain(
    socket: &UdpSocket,
    dns_server: &str,
    domain: &str,
    query_type: &QueryType,
) -> Result<Vec<QueryResponse>> {
    let mut all_results = HashSet::new();
    let mut seen_cnames = HashSet::new();

    match query_type {
        QueryType::Any => {
            for qt in &[QueryType::A, QueryType::AAAA, QueryType::MX, QueryType::TXT] {
                query_and_collect(
                    socket,
                    dns_server,
                    domain,
                    qt,
                    &mut seen_cnames,
                    &mut all_results,
                )?;
            }
        }
        _ => {
            query_and_collect(
                socket,
                dns_server,
                domain,
                query_type,
                &mut seen_cnames,
                &mut all_results,
            )?;
        }
    }

    if all_results.is_empty() {
        Err(anyhow!("No record found"))
    } else {
        Ok(all_results.into_iter().collect())
    }
}

fn query_and_collect(
    socket: &UdpSocket,
    dns_server: &str,
    domain: &str,
    query_type: &QueryType,
    seen_cnames: &mut HashSet<String>,
    all_results: &mut HashSet<QueryResponse>,
) -> Result<()> {
    match dns_query(socket, dns_server, domain, query_type) {
        Ok(query_result) => {
            for response in query_result {
                match response.response_content {
                    ResponseType::CNAME(ref cname) => {
                        if seen_cnames.insert(cname.clone()) {
                            all_results.insert(response.clone());
                            query_and_collect(
                                socket,
                                dns_server,
                                cname,
                                query_type,
                                seen_cnames,
                                all_results,
                            )?;
                        }
                    }
                    _ => {
                        all_results.insert(response);
                    }
                }
            }
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn dns_query(
    socket: &UdpSocket,
    dns_server: &str,
    domain: &str,
    query_type: &QueryType,
) -> Result<Vec<QueryResponse>> {
    const UDP_PORT: u8 = 53;
    let dns_server_address = format!("{dns_server}:{UDP_PORT}");

    let query = build_dns_query(domain, query_type)?;
    let response = send_dns_query(socket, &query, &dns_server_address)?;
    parse_dns_response(&response)
}

#[allow(clippy::match_wildcard_for_single_variants)]
fn build_dns_query(domain: &str, query_type: &QueryType) -> Result<Vec<u8>> {
    let mut packet = Vec::new();

    // Generate a random ID
    let random_id: u16 = rand::thread_rng().gen();

    // Header
    packet.extend_from_slice(&random_id.to_be_bytes()); // ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // Question
    for part in domain.split('.') {
        let q_length = u8::try_from(part.len())?;
        packet.push(q_length);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0); // Terminate the domain name
    match query_type {
        QueryType::A => packet.extend_from_slice(&[0x00, 0x01]),
        QueryType::AAAA => packet.extend_from_slice(&[0x00, 0x1c]),
        QueryType::MX => packet.extend_from_slice(&[0x00, 0x0f]),
        QueryType::TXT => packet.extend_from_slice(&[0x00, 0x10]),
        QueryType::CNAME => packet.extend_from_slice(&[0x00, 0x05]),
        QueryType::SOA => packet.extend_from_slice(&[0x00, 0x06]),
        _ => {}
    }
    packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN (Internet)

    Ok(packet)
}

fn send_dns_query(socket: &UdpSocket, query: &[u8], dns_server: &str) -> Result<Vec<u8>> {
    const BUFFER_SIZE: usize = 512;

    socket
        .send_to(query, dns_server)
        .map_err(|error| anyhow!("Failed to send DNS query: {}", error))?;

    let mut response_buffer = [0; BUFFER_SIZE];
    let (bytes_received, _) = socket
        .recv_from(&mut response_buffer)
        .map_err(|error| anyhow!("Failed to receive DNS response: {}", error))?;

    Ok(response_buffer[..bytes_received].to_vec())
}

fn parse_dns_response(response: &[u8]) -> Result<Vec<QueryResponse>> {
    if response.len() < 12 {
        return Err(anyhow!("Malformed DNS response: Response length too short"));
    }

    let qdcount = u16::from_be_bytes([response[4], response[5]]); //Question Count
    let ancount = u16::from_be_bytes([response[6], response[7]]); //Answer Count

    if qdcount != 1 {
        return Err(anyhow!("Malformed DNS response: Incorrect question count"));
    }

    let mut offset = 12; // Start of the Question section

    // Skip the Question section
    while offset < response.len() && response[offset] != 0 {
        offset += response[offset] as usize + 1;
    }
    offset += 5; // Skip QTYPE and QCLASS

    // Parse the Answer section
    let mut results: Vec<QueryResponse> = Vec::new();
    for _ in 0..ancount {
        if offset + 10 > response.len() {
            return Err(anyhow!("Malformed DNS response: Answer section incomplete"));
        }

        offset += 2; // Skip the NAME (pointer)
        let query_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        offset += 2;
        let class = u16::from_be_bytes([response[offset], response[offset + 1]]);
        offset += 2;
        offset += 4; // Skip the TTL
        let rdlength = u16::from_be_bytes([response[offset], response[offset + 1]]);

        offset += 2;
        if class == 1 {
            match query_type {
                1 => {
                    // A (1)
                    results.push(parse_a_record(response, &mut offset, rdlength)?);
                }
                28 => {
                    // AAAA (28)
                    results.push(parse_aaaa_record(response, &mut offset, rdlength)?);
                }
                15 => {
                    // MX (15)
                    results.push(parse_mx_record(response, &mut offset, rdlength)?);
                }
                5 => {
                    // CNAME (5)
                    results.push(parse_cname_record(response, &mut offset, rdlength)?);
                }
                16 => {
                    // TXT (16)
                    results.push(parse_txt_record(response, &mut offset, rdlength)?);
                }
                6 => {
                    // SOA (6)
                    results.push(parse_soa_record(response, &mut offset, rdlength)?);
                }
                _ => {} // Unsupported record type, ignore
            }
        } else {
            // Unsupported class, skip the record
            offset += rdlength as usize;
        }
    }

    Ok(results)
}

fn parse_a_record(response: &[u8], offset: &mut usize, rdlength: u16) -> Result<QueryResponse> {
    // A (1)
    if *offset + 4 > response.len() {
        return Err(anyhow!("Malformed DNS response: A record incomplete"));
    }
    let ipv4 = Ipv4Addr::new(
        response[*offset],
        response[*offset + 1],
        response[*offset + 2],
        response[*offset + 3],
    );

    let record_response = QueryResponse {
        query_type: QueryType::A,
        response_content: ResponseType::IPv4(ipv4),
    };

    *offset += rdlength as usize - 4; // Adjust offset for A record

    Ok(record_response)
}

fn parse_aaaa_record(response: &[u8], offset: &mut usize, rdlength: u16) -> Result<QueryResponse> {
    // AAAA (28)
    if *offset + 16 > response.len() {
        return Err(anyhow!("Malformed DNS response: AAAA record incomplete"));
    }
    let ipv6 = Ipv6Addr::new(
        (response[*offset] as u16) << 8 | (response[*offset + 1] as u16),
        (response[*offset + 2] as u16) << 8 | (response[*offset + 3] as u16),
        (response[*offset + 4] as u16) << 8 | (response[*offset + 5] as u16),
        (response[*offset + 6] as u16) << 8 | (response[*offset + 7] as u16),
        (response[*offset + 8] as u16) << 8 | (response[*offset + 9] as u16),
        (response[*offset + 10] as u16) << 8 | (response[*offset + 11] as u16),
        (response[*offset + 12] as u16) << 8 | (response[*offset + 13] as u16),
        (response[*offset + 14] as u16) << 8 | (response[*offset + 15] as u16),
    );

    let record_response = QueryResponse {
        query_type: QueryType::AAAA,
        response_content: ResponseType::IPv6(ipv6),
    };

    *offset += rdlength as usize - 16; // Adjust offset for AAAA record

    Ok(record_response)
}

fn parse_mx_record(response: &[u8], offset: &mut usize, rdlength: u16) -> Result<QueryResponse> {
    // MX (15)
    if *offset + 2 > response.len() {
        return Err(anyhow!("Malformed DNS response: MX record incomplete"));
    }

    let priority_number = u16::from_be_bytes([response[*offset], response[*offset + 1]]);
    *offset += 2;

    let mut response_domain: String = String::new();
    let mut jump_offset = *offset;

    // Loop to parse the domain name labels
    loop {
        let label_length = response[jump_offset] as usize;

        // Check for compression pointer
        if label_length & 0b1100_0000 == 0b1100_0000 {
            // Jump to the offset specified in the pointer
            let pointer_offset =
                u16::from_be_bytes([response[jump_offset], response[jump_offset + 1]]) as usize
                    & 0x3FFF;
            jump_offset = pointer_offset;
        } else {
            // Normal label, parse and append to answer_domain
            for i in 1..=label_length {
                response_domain.push(response[jump_offset + i] as char);
            }
            jump_offset += label_length + 1;
            if response[jump_offset] == 0 {
                break; // End of domain name
            }
            response_domain.push('.'); // Append dot between labels
        }
    }

    let mx_data = MXResponse {
        priority: priority_number,
        domain: response_domain,
    };
    let record_response = QueryResponse {
        query_type: QueryType::MX,
        response_content: ResponseType::MX(mx_data),
    };
    *offset += rdlength as usize - 2; // Adjust offset for MX record

    Ok(record_response)
}

fn parse_cname_record(response: &[u8], offset: &mut usize, rdlength: u16) -> Result<QueryResponse> {
    // CNAME (5)
    if *offset + rdlength as usize > response.len() {
        return Err(anyhow!(
            "Malformed DNS response: CNAME record domain name incomplete"
        ));
    }

    let mut cname_target = String::new();
    let mut jump_offset = *offset;
    loop {
        let label_length = response[jump_offset] as usize;
        if label_length & 0b1100_0000 == 0b1100_0000 {
            // Compression pointer, follow the offset
            jump_offset = u16::from_be_bytes([response[jump_offset], response[jump_offset + 1]])
                as usize
                & 0x3FFF;
        } else {
            // Normal label, append to cname_target
            for i in 1..=label_length {
                cname_target.push(response[jump_offset + i] as char);
            }
            jump_offset += label_length + 1;
            if response[jump_offset] == 0 {
                break; // End of domain name
            }
            cname_target.push('.'); // Append dot between labels
        }
    }

    let record_response = QueryResponse {
        query_type: QueryType::CNAME,
        response_content: ResponseType::CNAME(cname_target),
    };
    *offset += rdlength as usize; // Adjust offset for CNAME record

    Ok(record_response)
}

fn parse_txt_record(response: &[u8], offset: &mut usize, rdlength: u16) -> Result<QueryResponse> {
    // TXT (16)
    if *offset + rdlength as usize > response.len() {
        return Err(anyhow!(
            "Malformed DNS response: TXT record data incomplete"
        ));
    }

    let txt_data_length = response[*offset];
    *offset += 1;

    let mut txt_data = String::new();
    for _ in 0..txt_data_length {
        txt_data.push(response[*offset] as char);
        *offset += 1;
    }

    let record_response = QueryResponse {
        query_type: QueryType::TXT,
        response_content: ResponseType::TXT(txt_data),
    };

    Ok(record_response)
}

fn parse_soa_record(response: &[u8], offset: &mut usize, rdlength: u16) -> Result<QueryResponse> {
    // SOA (6)
    if *offset + rdlength as usize > response.len() {
        return Err(anyhow!(
            "Malformed DNS response: SOA record data incomplete"
        ));
    }

    let read_domain_name = |data: &[u8], offset: &mut usize| -> Result<String> {
        let mut domain_name = String::new();
        let mut first_label = true;

        while data[*offset] != 0 {
            if !first_label {
                domain_name.push('.');
            }
            first_label = false;

            let length = data[*offset] as usize;
            *offset += 1;

            if *offset + length > data.len() {
                return Err(anyhow!(
                    "Malformed DNS response: Domain name data incomplete"
                ));
            }

            domain_name.push_str(core::str::from_utf8(&data[*offset..*offset + length])?);
            *offset += length;
        }

        *offset += 1;
        Ok(domain_name)
    };

    let mname_data = read_domain_name(response, offset)?;
    let rname_data = read_domain_name(response, offset)?;

    let serial_data: u32 = u32::from_be_bytes([
        response[*offset],
        response[*offset + 1],
        response[*offset + 2],
        response[*offset + 3],
    ]);
    *offset += 4;

    let refresh_data: u32 = u32::from_be_bytes([
        response[*offset],
        response[*offset + 1],
        response[*offset + 2],
        response[*offset + 3],
    ]);
    *offset += 4;

    let retry_data: u32 = u32::from_be_bytes([
        response[*offset],
        response[*offset + 1],
        response[*offset + 2],
        response[*offset + 3],
    ]);
    *offset += 4;

    let expire_data: u32 = u32::from_be_bytes([
        response[*offset],
        response[*offset + 1],
        response[*offset + 2],
        response[*offset + 3],
    ]);
    *offset += 4;

    let minimum_data: u32 = u32::from_be_bytes([
        response[*offset],
        response[*offset + 1],
        response[*offset + 2],
        response[*offset + 3],
    ]);
    *offset += 4;

    let soa_response = SOAResponse {
        mname: mname_data,
        rname: rname_data,
        serial: serial_data,
        refresh: refresh_data,
        retry: retry_data,
        expire: expire_data,
        minimum: minimum_data,
    };

    let record_response = QueryResponse {
        query_type: QueryType::SOA,
        response_content: ResponseType::SOA(soa_response),
    };

    Ok(record_response)
}
