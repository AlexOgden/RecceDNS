use anyhow::{anyhow, Result};

use crate::dns::types::{MXResponse, QueryResponse, QueryType, ResponseType, SOAResponse};
use once_cell::sync::Lazy;
use rand::Rng;
use std::sync::Mutex;
use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
};

static SOCKET: Lazy<Mutex<Option<UdpSocket>>> = Lazy::new(|| Mutex::new(None));

fn get_socket() -> Result<UdpSocket> {
    let mut socket_guard = SOCKET.lock().expect("Failed to lock the mutex");
    if socket_guard.is_none() {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        *socket_guard = Some(socket);
    }
    Ok(socket_guard
        .as_ref()
        .expect("Socket should be initialized")
        .try_clone()?)
}

pub fn resolve_domain(
    dns_server: &str,
    domain: &str,
    query_type: &QueryType,
) -> Result<Vec<QueryResponse>> {
    let mut all_results = HashSet::new();
    let mut seen_cnames = HashSet::new();
    let socket = get_socket()?;

    let query_types: Vec<&QueryType> = match query_type {
        QueryType::Any => vec![
            &QueryType::A,
            &QueryType::AAAA,
            &QueryType::MX,
            &QueryType::TXT,
        ],
        _ => vec![query_type],
    };

    for qt in query_types {
        query_and_collect(
            &socket,
            dns_server,
            domain,
            qt,
            &mut seen_cnames,
            &mut all_results,
        )?;
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
    let query_result = dns_query(socket, dns_server, domain, query_type)?;

    for response in query_result {
        if let ResponseType::CNAME(ref cname) = response.response_content {
            if seen_cnames.insert(cname.clone()) {
                all_results.insert(response);
            }
        } else {
            all_results.insert(response);
        }
    }

    Ok(())
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
        QueryType::Any => return Err(anyhow!("Invalid query type")),
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
    let nscount = u16::from_be_bytes([response[8], response[9]]); // Authority Record Count

    if qdcount != 1 {
        return Err(anyhow!(
            "Malformed DNS response: Incorrect question count ({qdcount})"
        ));
    }

    let mut offset = 12; // Start of the Question section

    // Skip the Question section
    while offset < response.len() && response[offset] != 0 {
        offset += response[offset] as usize + 1;
    }

    // Extract QTYPE and QCLASS
    let q_type = u16::from_be_bytes([response[offset + 1], response[offset + 2]]);
    offset += 5; // Skip QTYPE and QCLASS

    // Parse the Answer section
    let mut results: Vec<QueryResponse> = Vec::new();
    for _ in 0..ancount {
        if offset + 10 > response.len() {
            return Err(anyhow!("Malformed DNS response: Answer section incomplete"));
        }

        offset += 2; // Skip the NAME (pointer)
        let query_type =
            QueryType::from_number(u16::from_be_bytes([response[offset], response[offset + 1]]));
        offset += 2;
        let class = u16::from_be_bytes([response[offset], response[offset + 1]]);
        offset += 2;
        offset += 4; // Skip the TTL
        let rdlength = u16::from_be_bytes([response[offset], response[offset + 1]]);

        offset += 2;
        if class == 1 {
            match query_type {
                QueryType::A => {
                    // A (1)
                    results.push(parse_a_record(response, &mut offset, rdlength)?);
                }
                QueryType::AAAA => {
                    // AAAA (28)
                    results.push(parse_aaaa_record(response, &mut offset, rdlength)?);
                }
                QueryType::MX => {
                    // MX (15)
                    results.push(parse_mx_record(response, &mut offset, rdlength)?);
                }
                QueryType::CNAME => {
                    // CNAME (5)
                    results.push(parse_cname_record(response, &mut offset, rdlength)?);
                }
                QueryType::TXT => {
                    // TXT (16)
                    results.push(parse_txt_record(response, &mut offset, rdlength)?);
                }
                QueryType::SOA => {
                    // SOA (6)
                    results.push(parse_soa_record(response, &mut offset, rdlength)?);
                }
                QueryType::Any => {} // Unsupported record type, ignore
            }
        } else {
            // Unsupported class, skip the record
            offset += rdlength as usize;
        }
    }

    // Parse the Authority section if there are authority records (NSCOUNT)
    if nscount > 0 && QueryType::from_number(q_type) == QueryType::SOA {
        for _ in 0..nscount {
            if offset + 10 > response.len() {
                return Err(anyhow!(
                    "Malformed DNS response: Authority section incomplete"
                ));
            }

            offset += 2; // Skip the NAME (pointer)
            let query_type = QueryType::from_number(u16::from_be_bytes([
                response[offset],
                response[offset + 1],
            ]));
            offset += 2;
            let class = u16::from_be_bytes([response[offset], response[offset + 1]]);
            offset += 2;
            offset += 4; // Skip the TTL
            let rdlength = u16::from_be_bytes([response[offset], response[offset + 1]]);

            offset += 2;
            if class == 1 {
                match query_type {
                    QueryType::SOA => {
                        // SOA (6) in Authority section
                        results.push(parse_soa_record(response, &mut offset, rdlength)?);
                    }
                    _ => {
                        // Unsupported or irrelevant record type, skip
                        offset += rdlength as usize;
                    }
                }
            } else {
                // Unsupported class, skip the record
                offset += rdlength as usize;
            }
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
        let mut domain_name = Vec::with_capacity(256);
        let mut first_label = true;
        let mut original_offset = *offset; // Keep track of the original offset
        let mut jumped = false; // To track if we've jumped to a pointer location

        loop {
            let length = data[*offset] as usize;

            // If length indicates pointer compression (0b11000000), follow the pointer
            if length & 0b1100_0000 == 0b1100_0000 {
                let pointer = ((length & 0b0011_1111) << 8) | data[*offset + 1] as usize;
                *offset += 2;

                // Set the offset to the pointer's target, but only if we haven't already jumped
                if !jumped {
                    original_offset = *offset; // Save the current offset for after the jump
                    *offset = pointer;
                    jumped = true;
                }
                continue;
            }

            // Stop when we encounter a null byte (end of domain name)
            if length == 0 {
                if jumped {
                    *offset = original_offset; // Restore offset to continue parsing after the jump
                } else {
                    *offset += 1;
                }
                break;
            }

            // Ensure there's enough data to read the label
            if *offset + length + 1 > data.len() {
                return Err(anyhow!(
                    "Malformed DNS response: Domain name data incomplete"
                ));
            }

            // Append a dot between labels
            if !first_label {
                domain_name.push(b'.');
            }
            first_label = false;

            // Append the label
            *offset += 1;
            domain_name.extend_from_slice(&data[*offset..*offset + length]);
            *offset += length;
        }

        // Convert the domain name from Vec<u8> to String
        String::from_utf8(domain_name).map_err(|e| anyhow!("Invalid UTF-8 sequence: {}", e))
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_invalid_response() {
        let invalid_data: [u8; 8] = [0x00, 0x32, 0x45, 0x21, 0x2F, 0xFF, 0xA2, 0x80];

        let parse_result = parse_dns_response(&invalid_data);
        assert!(parse_result.is_err());
    }

    #[test]
    fn parse_valid_a_response() {
        // google.com A 142.250.187.206
        let a_record_response_data: [u8; 55] = [
            0x2c, 0xb7, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x8e, 0xfa,
            0xbb, 0xce, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let parsed_response: Vec<QueryResponse> =
            parse_dns_response(&a_record_response_data).expect("Parse Failed");
        assert_eq!(parsed_response.len(), 1);

        let query_response = &parsed_response[0];
        assert_eq!(query_response.query_type, QueryType::A);

        let expected_ip = Ipv4Addr::new(142, 250, 187, 206);

        if let ResponseType::IPv4(parsed_ip) = query_response.response_content {
            assert_eq!(parsed_ip, expected_ip);
        }
    }

    #[test]
    fn parse_valid_aaaa_response() {
        // google.com AAAA 2a00:1450:4009:81f::200e
        let aaaa_record_response_data: [u8; 67] = [
            0xb2, 0xf6, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x10, 0x2a, 0x00,
            0x14, 0x50, 0x40, 0x09, 0x08, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e,
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let parsed_response: Vec<QueryResponse> =
            parse_dns_response(&aaaa_record_response_data).expect("Parse Failed");
        assert_eq!(parsed_response.len(), 1);

        let query_response = &parsed_response[0];
        assert_eq!(query_response.query_type, QueryType::AAAA);

        let expected_ip = Ipv6Addr::new(
            0x2a00, 0x1450, 0x4009, 0x0081f, 0x0000, 0x0000, 0x0000, 0x200e,
        );

        if let ResponseType::IPv6(parsed_ip) = query_response.response_content {
            assert_eq!(parsed_ip, expected_ip);
        }
    }

    #[test]
    fn parse_valid_single_mx_response() {
        // google.com MX
        let mx_single_reponse_data: [u8; 60] = [
            0x29, 0x5b, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x6, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0xf, 0x0, 0x1, 0xc0, 0xc, 0x0, 0xf,
            0x0, 0x1, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x9, 0x0, 0xa, 0x4, 0x73, 0x6d, 0x74, 0x70, 0xc0,
            0xc, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        let parsed_response: Vec<QueryResponse> =
            parse_dns_response(&mx_single_reponse_data).expect("Parse Failed");
        assert_eq!(parsed_response.len(), 1);

        let response_data = &parsed_response[0];
        assert_eq!(response_data.query_type, QueryType::MX);

        if let ResponseType::MX(mx_response) = &response_data.response_content {
            assert_eq!(mx_response.priority, 10);
            assert_eq!(mx_response.domain, "smtp.google.com");
        }
    }

    #[test]
    fn parse_valid_two_mx_response() {
        // google.com MX
        let mx_two_reponse_data: [u8; 87] = [
            0x46, 0xa8, 0x81, 0xa0, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x1, 0xa, 0x70, 0x72, 0x6f,
            0x74, 0x6f, 0x6e, 0x6d, 0x61, 0x69, 0x6c, 0x2, 0x63, 0x68, 0x0, 0x0, 0xf, 0x0, 0x1,
            0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x1, 0x7d, 0x0, 0x9, 0x0, 0x5, 0x4, 0x6d,
            0x61, 0x69, 0x6c, 0xc0, 0xc, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x1, 0x7d, 0x0,
            0xc, 0x0, 0xa, 0x7, 0x6d, 0x61, 0x69, 0x6c, 0x73, 0x65, 0x63, 0xc0, 0xc, 0x0, 0x0,
            0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        let parsed_response: Vec<QueryResponse> =
            parse_dns_response(&mx_two_reponse_data).expect("Parse Failed");
        assert_eq!(parsed_response.len(), 2);

        let response_data = &parsed_response[0];
        assert_eq!(response_data.query_type, QueryType::MX);

        if let ResponseType::MX(mx_response) = &response_data.response_content {
            assert_eq!(mx_response.priority, 5);
            assert_eq!(mx_response.domain, "mail.protonmail.ch");
        }

        let response_data = &parsed_response[1];
        assert_eq!(response_data.query_type, QueryType::MX);

        if let ResponseType::MX(mx_response) = &response_data.response_content {
            assert_eq!(mx_response.priority, 10);
            assert_eq!(mx_response.domain, "mailsec.protonmail.ch");
        }
    }

    #[test]
    fn parse_valid_cname_response() {
        // www.alexogden.com CNAME
        let cname_record_response_data: [u8; 60] = [
            0x92, 0x59, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x3, 0x77, 0x77, 0x77,
            0x9, 0x61, 0x6c, 0x65, 0x78, 0x6f, 0x67, 0x64, 0x65, 0x6e, 0x3, 0x63, 0x6f, 0x6d, 0x0,
            0x0, 0x5, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x1d, 0xa9, 0x0, 0x2,
            0xc0, 0x10, 0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        let parsed_response: Vec<QueryResponse> =
            parse_dns_response(&cname_record_response_data).expect("Parse Failed");
        assert_eq!(parsed_response.len(), 1);

        let query_response = &parsed_response[0];
        assert_eq!(query_response.query_type, QueryType::CNAME);

        if let ResponseType::CNAME(domain) = &query_response.response_content {
            assert_eq!(domain, "alexogden.com");
        }
    }

    #[test]
    fn parse_valid_txt_response() {
        // mail.google.com TXT
        let txt_record_response_data: [u8; 125] = [
            0xe8, 0x3e, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x4, 0x6d, 0x61, 0x69,
            0x6c, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x10,
            0x0, 0x1, 0xc0, 0xc, 0x0, 0x10, 0x0, 0x1, 0x0, 0x1, 0x51, 0x77, 0x0, 0x45, 0x44, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2d, 0x73, 0x69, 0x74, 0x65, 0x2d, 0x76, 0x65, 0x72,
            0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x50, 0x6e, 0x63, 0x58,
            0x70, 0x52, 0x4b, 0x52, 0x43, 0x41, 0x6c, 0x44, 0x41, 0x64, 0x6c, 0x65, 0x73, 0x54,
            0x74, 0x4e, 0x46, 0x66, 0x36, 0x6b, 0x39, 0x54, 0x76, 0x67, 0x78, 0x67, 0x63, 0x52,
            0x66, 0x6f, 0x6a, 0x64, 0x61, 0x4b, 0x6b, 0x45, 0x41, 0x43, 0x59, 0x0, 0x0, 0x29, 0x4,
            0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        let parsed_response: Vec<QueryResponse> =
            parse_dns_response(&txt_record_response_data).expect("Parse Failed");
        assert_eq!(parsed_response.len(), 1);

        let query_response = &parsed_response[0];
        assert_eq!(query_response.query_type, QueryType::TXT);

        if let ResponseType::TXT(text) = &query_response.response_content {
            assert_eq!(
                text,
                "google-site-verification=PncXpRKRCAlDAdlesTtNFf6k9TvgxgcRfojdaKkEACY"
            );
        }
    }

    #[test]
    fn parse_valid_soa_response() {
        // google.com SOA
        let soa_record_response_data: [u8; 89] = [
            0xff, 0xfe, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x6, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x6, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x6,
            0x0, 0x1, 0x0, 0x0, 0x0, 0x3c, 0x0, 0x26, 0x3, 0x6e, 0x73, 0x31, 0xc0, 0xc, 0x9, 0x64,
            0x6e, 0x73, 0x2d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0xc0, 0xc, 0x28, 0x65, 0x8, 0x9a, 0x0,
            0x0, 0x3, 0x84, 0x0, 0x0, 0x3, 0x84, 0x0, 0x0, 0x7, 0x8, 0x0, 0x0, 0x0, 0x3c, 0x0, 0x0,
            0x29, 0x4, 0xd0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        let parsed_response: Vec<QueryResponse> =
            parse_dns_response(&soa_record_response_data).expect("Parse Failed");
        assert_eq!(parsed_response.len(), 1);

        let response_data = &parsed_response[0];
        assert_eq!(response_data.query_type, QueryType::SOA);

        if let ResponseType::SOA(soa_response) = &response_data.response_content {
            assert_eq!(soa_response.expire, 1800);
            assert_eq!(soa_response.retry, 900);
            assert_eq!(soa_response.refresh, 900);
            assert_eq!(soa_response.minimum, 60);
            assert_eq!(soa_response.serial, 677_709_978);
        }
    }
}
