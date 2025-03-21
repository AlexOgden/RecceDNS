use anyhow::{Context, Result};
use rand::Rng;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream, UdpSocket};
use std::time::Duration;

use crate::dns::{
    error::DnsError,
    protocol::{DnsPacket, DnsQuestion, QueryType, ResultCode},
};
use crate::io::packet_buffer::PacketBuffer;
use crate::network::types::TransportProtocol;

const DNS_PORT: u8 = 53;
const UDP_BUFFER_SIZE: usize = 512;
const TIMEOUT: std::time::Duration = Duration::from_secs(1);

fn initialize_udp_socket() -> Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    socket
        .set_read_timeout(Some(TIMEOUT))
        .context("Failed to set read timeout")?;
    socket
        .set_write_timeout(Some(TIMEOUT))
        .context("Failed to set write timeout")?;

    Ok(socket)
}

pub fn resolve_domain(
    dns_resolver: &str,
    domain: &str,
    query_type: &QueryType,
    transport_protocol: &TransportProtocol,
    recursion: bool,
) -> Result<DnsPacket, DnsError> {
    let socket = initialize_udp_socket()
        .map_err(|e| DnsError::Network(format!("Failed to create socket: {e}")))?;

    let result = execute_dns_query(
        &socket,
        transport_protocol,
        dns_resolver,
        domain,
        query_type,
        recursion,
    );

    // Process the result
    match result {
        Ok(query_result) => match query_result.header.rescode {
            ResultCode::NOERROR => {
                if query_result.answers.is_empty() {
                    Err(DnsError::NoRecordsFound)
                } else {
                    Ok(query_result)
                }
            }
            ResultCode::NXDOMAIN => Err(DnsError::NonExistentDomain),
            ResultCode::SERVFAIL => Err(DnsError::NameserverError("Server Failed".to_owned())),
            ResultCode::NOTIMP => Err(DnsError::NameserverError("Not Implemented".to_owned())),
            ResultCode::REFUSED => Err(DnsError::NameserverError("Refused".to_owned())),
            ResultCode::FORMERR => Err(DnsError::ProtocolData("Format Error".to_owned())),
        },
        Err(e) => Err(e),
    }
}

fn execute_dns_query(
    socket: &UdpSocket,
    transport_protocol: &TransportProtocol,
    dns_resolver: &str,
    domain: &str,
    query_type: &QueryType,
    recursion: bool,
) -> Result<DnsPacket, DnsError> {
    let mut query = build_dns_query(domain, query_type, recursion)?;
    let query_id = query.header.id;

    let mut req_buffer = PacketBuffer::new();
    query.write(&mut req_buffer)?;
    let request_data = req_buffer.get_buffer_to_pos();

    let dns_server_address = format!("{dns_resolver}:{DNS_PORT}");
    let response = match transport_protocol {
        TransportProtocol::UDP => send_query_udp(socket, request_data, &dns_server_address)?,
        TransportProtocol::TCP => send_query_tcp(request_data, &dns_server_address)?,
    };

    let parsed_response = parse_dns_response(&response)?;

    // Verify the response ID matches our query ID to prevent spoofing/detect network issues
    if parsed_response.header.id != query_id {
        return Err(DnsError::InvalidData(format!(
            "Response ID {} does not match query ID {} for domain '{}'",
            parsed_response.header.id, query_id, domain
        )));
    }

    Ok(parsed_response)
}

fn send_query_udp(socket: &UdpSocket, query: &[u8], dns_server: &str) -> Result<Vec<u8>, DnsError> {
    socket
        .send_to(query, dns_server)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::TimedOut => {
                DnsError::Network(format!("Timeout sending query to {dns_server} (UDP)"))
            }
            std::io::ErrorKind::ConnectionRefused => {
                DnsError::Network(format!("Connection refused by {dns_server} (UDP)"))
            }
            _ => DnsError::Network(format!(
                "Failed to send query to {dns_server} (UDP): {error}"
            )),
        })?;

    let mut response_buffer = [0u8; UDP_BUFFER_SIZE];
    let (bytes_received, remote_addr) =
        socket
            .recv_from(&mut response_buffer)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::TimedOut => DnsError::Network(format!(
                    "Timeout waiting for response from {dns_server} (UDP)"
                )),
                _ => DnsError::Network(format!("Error receiving DNS response: {error}")),
            })?;

    if bytes_received == 0 {
        return Err(DnsError::Network(format!(
            "Empty response received from {dns_server}"
        )));
    }

    // Verify the response came from the expected server
    if remote_addr.to_string() != dns_server {
        return Err(DnsError::Network(format!(
            "Response received from unexpected address: {remote_addr}, expected: {dns_server}"
        )));
    }

    Ok(response_buffer[..bytes_received].to_vec())
}

fn send_query_tcp(query: &[u8], dns_server: &str) -> Result<Vec<u8>, DnsError> {
    const MAX_RESPONSE_SIZE: usize = 16384;

    // Establish TCP connection to the DNS server
    let mut stream = TcpStream::connect(dns_server)
        .map_err(|e| DnsError::Network(format!("Failed to connect to {dns_server} (TCP): {e}")))?;

    // Set read and write timeouts
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| DnsError::Network(format!("Failed to set read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| DnsError::Network(format!("Failed to set write timeout: {e}")))?;

    // Send query length in big-endian format
    let query_len = u16::try_from(query.len())
        .map_err(|_| DnsError::InvalidData("Query length exceeds u16 maximum value".to_owned()))?
        .to_be_bytes();
    stream
        .write_all(&query_len)
        .map_err(|e| DnsError::Network(format!("Failed to write query length: {e}")))?;
    stream
        .write_all(query)
        .map_err(|e| DnsError::Network(format!("Failed to write query: {e}")))?;

    // Read response length
    let mut len_buffer = [0u8; 2];
    stream
        .read_exact(&mut len_buffer)
        .map_err(|_| DnsError::Network("Failed to read response length".to_owned()))?;
    let response_len = u16::from_be_bytes(len_buffer) as usize;

    if response_len == 0 {
        return Err(DnsError::InvalidData("Empty response received".to_owned()));
    }

    if response_len > MAX_RESPONSE_SIZE {
        return Err(DnsError::InvalidData(format!(
            "Response length too large: {response_len} bytes (max: {MAX_RESPONSE_SIZE})"
        )));
    }

    // Read the actual response
    let mut response_buffer = vec![0u8; response_len];
    stream
        .read_exact(&mut response_buffer)
        .map_err(|_| DnsError::Network("Failed to read response".to_owned()))?;

    let _ = stream.shutdown(std::net::Shutdown::Both);

    Ok(response_buffer)
}

fn build_dns_query(
    domain: &str,
    query_type: &QueryType,
    recursion: bool,
) -> Result<DnsPacket, DnsError> {
    // Validate domain name
    if domain.is_empty() {
        return Err(DnsError::InvalidData(
            "Domain name cannot be empty".to_owned(),
        ));
    }

    if domain.len() > 253 {
        return Err(DnsError::InvalidData(format!(
            "Domain name exceeds maximum length of 253 characters: {domain}"
        )));
    }

    // Convert IP address to PTR format if needed
    let domain = if query_type == &QueryType::PTR {
        #[allow(clippy::option_if_let_else)]
        if let Ok(ipv4) = domain.parse::<Ipv4Addr>() {
            ipv4_to_ptr(ipv4)
        } else if let Ok(ipv6) = domain.parse::<Ipv6Addr>() {
            ipv6_to_ptr(&ipv6)
        } else {
            domain.to_owned()
        }
    } else {
        domain.to_owned()
    };

    // Build the query packet with thread-safe random ID
    let mut packet = DnsPacket::new();
    packet.header.id = rand::rng().random();
    packet.header.questions = 1;
    packet.header.recursion_desired = recursion;
    packet
        .questions
        .push(DnsQuestion::new(domain, query_type.clone()));

    Ok(packet)
}

fn ipv4_to_ptr(ip: Ipv4Addr) -> String {
    ip.octets()
        .iter()
        .rev()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
        + ".in-addr.arpa"
}

fn ipv6_to_ptr(ip: &Ipv6Addr) -> String {
    // Convert IPv6 to its expanded hex representation without colons
    let mut expanded = String::with_capacity(32); // 8 segments × 4 chars each
    for segment in ip.segments() {
        expanded.push_str(&format!("{segment:04x}"));
    }

    let reversed = expanded.chars().rev().fold(String::new(), |mut acc, c| {
        acc.push(c);
        acc.push('.');
        acc
    });

    // Add the ip6.arpa suffix
    format!("{reversed}ip6.arpa")
}

fn parse_dns_response(response: &[u8]) -> Result<DnsPacket, DnsError> {
    let mut packet_buffer = PacketBuffer::new();
    packet_buffer
        .set_data(response)
        .map_err(|_| DnsError::InvalidData("Invalid response".to_owned()))?;

    let dns_packet = DnsPacket::from_buffer(&mut packet_buffer)?;

    Ok(dns_packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query() {
        let domain = "example.com";
        let query_type = QueryType::A;
        let dns_packet = build_dns_query(domain, &query_type, true).unwrap();

        assert_eq!(dns_packet.header.questions, 1);
        assert_eq!(dns_packet.questions.len(), 1);
        assert_eq!(dns_packet.questions[0].name, domain);
        assert_eq!(dns_packet.questions[0].qtype, query_type);
    }

    #[test]
    fn test_build_dns_query_empty_domain() {
        let domain = "";
        let query_type = QueryType::A;
        let result = build_dns_query(domain, &query_type, true);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            DnsError::InvalidData("Domain name cannot be empty".to_owned())
        );
    }

    #[test]
    fn test_build_dns_query_with_recursion() {
        let domain = "example.com";
        let query_type = QueryType::A;
        let dns_packet = build_dns_query(domain, &query_type, true).unwrap();

        assert!(dns_packet.header.recursion_desired);
    }

    #[test]
    fn test_build_dns_query_without_recursion() {
        let domain = "example.com";
        let query_type = QueryType::A;
        let dns_packet = build_dns_query(domain, &query_type, false).unwrap();

        assert!(!dns_packet.header.recursion_desired);
    }

    #[test]
    fn test_ipv4_to_ptr() {
        let ip = Ipv4Addr::new(192, 168, 1, 22);
        let ptr = ipv4_to_ptr(ip);

        assert_eq!(ptr, "22.1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_build_dns_query_ptr() {
        let domain = "192.168.1.50";
        let query_type = QueryType::PTR;
        let dns_packet = build_dns_query(domain, &query_type, true).unwrap();

        assert_eq!(dns_packet.questions[0].name, "50.1.168.192.in-addr.arpa");
        assert_eq!(dns_packet.questions[0].qtype, query_type);
    }

    #[test]
    fn test_ipv6_to_ptr() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1);
        let ptr = ipv6_to_ptr(&ip);

        assert_eq!(
            ptr,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn test_build_dns_query_ipv6_ptr() {
        let domain = "2001:db8::1";
        let query_type = QueryType::PTR;
        let dns_packet = build_dns_query(domain, &query_type, true).unwrap();

        assert_eq!(
            dns_packet.questions[0].name,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert_eq!(dns_packet.questions[0].qtype, query_type);
    }

    #[test]
    fn test_domain_name_too_long() {
        let long_domain = "a".repeat(254);
        let query_type = QueryType::A;
        let result = build_dns_query(&long_domain, &query_type, true);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DnsError::InvalidData(_)));
    }

    #[test]
    fn test_normal_domain_ptr_unchanged() {
        let domain = "example.com";
        let query_type = QueryType::PTR;
        let dns_packet = build_dns_query(domain, &query_type, true).unwrap();

        assert_eq!(dns_packet.questions[0].name, domain);
        assert_eq!(dns_packet.questions[0].qtype, query_type);
    }

    #[test]
    fn test_query_id_is_random() {
        let domain = "example.com";
        let query_type = QueryType::A;
        let packet1 = build_dns_query(domain, &query_type, true).unwrap();
        let packet2 = build_dns_query(domain, &query_type, true).unwrap();

        assert_ne!(packet1.header.id, packet2.header.id);
    }
}
