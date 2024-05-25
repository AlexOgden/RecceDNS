use anyhow::{anyhow, Result};
use clap::ValueEnum;
use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use strum_macros::Display;

const BUFFER_SIZE: usize = 512;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Clone, ValueEnum, Display)]
pub enum QueryType {
    #[strum(to_string = "A")]
    A,
    #[strum(to_string = "AAAA")]
    AAAA,
    #[strum(to_string = "MX")]
    MX,
    #[strum(to_string = "all")]
    All,
}

pub fn resolve_domain(
    socket: &UdpSocket,
    dns_server: &str,
    domain: &str,
    query_type: &QueryType,
) -> Result<Vec<String>> {
    let mut all_results = Vec::new();

    match query_type {
        QueryType::All => {
            for qt in &[QueryType::A, QueryType::AAAA, QueryType::MX] {
                match dns_query(socket, dns_server, domain, qt) {
                    Ok(query_result) => all_results.extend(query_result),
                    Err(_) => continue,
                }
            }
        }
        _ => match dns_query(socket, dns_server, domain, query_type) {
            Ok(query_result) => all_results.extend(query_result),
            Err(err) => return Err(err),
        },
    }

    if all_results.is_empty() {
        Err(anyhow!("No IP address found"))
    } else {
        Ok(all_results)
    }
}

fn dns_query(
    socket: &UdpSocket,
    dns_server: &str,
    domain: &str,
    query_type: &QueryType,
) -> Result<Vec<String>> {
    const UDP_PORT: u8 = 53;
    let dns_server_address = format!("{}:{}", dns_server, UDP_PORT);

    let query = build_dns_query(domain, query_type);
    let response = send_dns_query(socket, &query, &dns_server_address)?;
    parse_dns_response(&response)
}

fn build_dns_query(domain: &str, query_type: &QueryType) -> Vec<u8> {
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
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0); // Terminate the domain name
    match query_type {
        QueryType::A => packet.extend_from_slice(&[0x00, 0x01]), // QTYPE: A
        QueryType::AAAA => packet.extend_from_slice(&[0x00, 0x1c]), // QTYPE: AAAA
        QueryType::MX => packet.extend_from_slice(&[0x00, 0x0f]), // QTYPE: AAAA
        _ => {}
    }
    packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN (Internet)

    packet
}

fn send_dns_query(socket: &UdpSocket, query: &[u8], dns_server: &str) -> Result<Vec<u8>> {
    socket
        .send_to(query, dns_server)
        .map_err(|error| anyhow!("Failed to send DNS query: {}", error))?;

    let mut response_buffer = [0; BUFFER_SIZE];
    let (bytes_received, _) = socket
        .recv_from(&mut response_buffer)
        .map_err(|error| anyhow!("Failed to receive DNS response: {}", error))?;

    Ok(response_buffer[..bytes_received].to_vec())
}

fn parse_dns_response(response: &[u8]) -> Result<Vec<String>> {
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
    let mut results = Vec::new();
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
                    if offset + 4 > response.len() {
                        return Err(anyhow!("Malformed DNS response: A record incomplete"));
                    }
                    let ipv4 = Ipv4Addr::new(
                        response[offset],
                        response[offset + 1],
                        response[offset + 2],
                        response[offset + 3],
                    );
                    results.push(format!("[A {}]", ipv4));
                    offset += rdlength as usize - 4; // Adjust offset for A record
                }
                28 => {
                    // AAAA (28)
                    if offset + 16 > response.len() {
                        return Err(anyhow!("Malformed DNS response: AAAA record incomplete"));
                    }
                    let ipv6 = Ipv6Addr::new(
                        (response[offset] as u16) << 8 | (response[offset + 1] as u16),
                        (response[offset + 2] as u16) << 8 | (response[offset + 3] as u16),
                        (response[offset + 4] as u16) << 8 | (response[offset + 5] as u16),
                        (response[offset + 6] as u16) << 8 | (response[offset + 7] as u16),
                        (response[offset + 8] as u16) << 8 | (response[offset + 9] as u16),
                        (response[offset + 10] as u16) << 8 | (response[offset + 11] as u16),
                        (response[offset + 12] as u16) << 8 | (response[offset + 13] as u16),
                        (response[offset + 14] as u16) << 8 | (response[offset + 15] as u16),
                    );
                    results.push(format!("[AAAA {}]", ipv6));
                    offset += rdlength as usize - 16; // Adjust offset for AAAA record
                }
                15 => {
                    if offset + 2 > response.len() {
                        return Err(anyhow!("Malformed DNS response: MX record incomplete"));
                    }

                    let preference_number =
                        u16::from_be_bytes([response[offset], response[offset + 1]]);
                    offset += 2;

                    let mut answer_domain: String = String::new();
                    let mut jump_offset = offset;

                    // Loop to parse the domain name labels
                    loop {
                        let label_length = response[jump_offset] as usize;

                        // Check for compression pointer
                        if label_length & 0b1100_0000 == 0b1100_0000 {
                            // Jump to the offset specified in the pointer
                            let pointer_offset = u16::from_be_bytes([
                                response[jump_offset],
                                response[jump_offset + 1],
                            ]) as usize
                                & 0x3FFF;
                            jump_offset = pointer_offset;
                        } else {
                            // Normal label, parse and append to answer_domain
                            for i in 1..=label_length {
                                answer_domain.push(response[jump_offset + i] as char);
                            }
                            jump_offset += label_length + 1;
                            if response[jump_offset] == 0 {
                                break; // End of domain name
                            }
                            answer_domain.push('.'); // Append dot between labels
                        }
                    }

                    results.push(format!("[MX {} {}]", preference_number, answer_domain));
                    offset += rdlength as usize - 2; // Adjust offset for MX record
                }
                5 => {
                    // CNAME (5)
                    let mut cname_target = String::new();
                    let mut jump_offset = offset;
                    loop {
                        let label_length = response[jump_offset] as usize;
                        if label_length & 0b1100_0000 == 0b1100_0000 {
                            // Compression pointer, follow the offset
                            jump_offset = u16::from_be_bytes([
                                response[jump_offset],
                                response[jump_offset + 1],
                            ]) as usize
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
                    results.push(format!("[CNAME {}]", cname_target));
                    offset += rdlength as usize; // Adjust offset for CNAME record
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
