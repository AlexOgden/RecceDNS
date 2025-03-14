use anyhow::{Context, Result};
use rand::Rng;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use crate::dns::{
    error::DnsError,
    protocol::{DnsPacket, DnsQuestion, QueryType, ResultCode},
};
use crate::io::packet_buffer::PacketBuffer;
use crate::network::types::TransportProtocol;

const DNS_PORT: u8 = 53;
const UDP_BUFFER_SIZE: usize = 512;

fn initialize_udp_socket() -> Result<Arc<UdpSocket>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let timeout = Duration::from_millis(1500);

    socket
        .set_read_timeout(Some(timeout))
        .context("Failed to set read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("Failed to set write timeout")?;

    Ok(Arc::new(socket))
}

pub fn resolve_domain(
    dns_resolver: &str,
    domain: &str,
    query_type: &QueryType,
    transport_protocol: &TransportProtocol,
    recursion: bool,
) -> Result<DnsPacket, DnsError> {
    let udp_socket =
        initialize_udp_socket().map_err(|error| DnsError::Network(error.to_string()))?;

    let query_result = execute_dns_query(
        &udp_socket,
        transport_protocol,
        dns_resolver,
        domain,
        query_type,
        recursion,
    )?;

    match query_result.header.rescode {
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
    let dns_server_address = format!("{dns_resolver}:{DNS_PORT}");

    let mut query = build_dns_query(domain, query_type, recursion)?;
    let query_id = query.header.id;

    let mut req_buffer = PacketBuffer::new();
    query.write(&mut req_buffer)?;
    let response = match transport_protocol {
        TransportProtocol::UDP => {
            send_dns_query_udp(socket, req_buffer.get_buffer_to_pos(), &dns_server_address)?
        }
        TransportProtocol::TCP => {
            send_dns_query_tcp(req_buffer.get_buffer_to_pos(), &dns_server_address)?
        }
    };
    let parsed_response = parse_dns_response(&response)?;
    if parsed_response.header.id != query_id {
        return Err(DnsError::InvalidData(format!(
            "Response ID {} does not match query ID {}",
            parsed_response.header.id, query_id
        )));
    }

    Ok(parsed_response)
}

fn send_dns_query_udp(
    socket: &UdpSocket,
    query: &[u8],
    dns_server: &str,
) -> Result<Vec<u8>, DnsError> {
    socket.send_to(query, dns_server).map_err(|error| {
        if error.raw_os_error() == Some(10060) {
            DnsError::Network(format!(
                "Failed to send query to {dns_server} (UDP): Connection attempt failed."
            ))
        } else {
            DnsError::Network(format!(
                "Failed to send query to {dns_server} (UDP): {error}"
            ))
        }
    })?;

    let mut response_buffer = [0; UDP_BUFFER_SIZE];
    let (bytes_received, _) = socket.recv_from(&mut response_buffer).map_err(|error| {
        if error.raw_os_error() == Some(10060) {
            DnsError::Network(format!("UDP receive timeout ({dns_server})"))
        } else {
            DnsError::Network(format!("UDP receive error: {error}"))
        }
    })?;

    Ok(response_buffer[..bytes_received].to_vec())
}

fn send_dns_query_tcp(query: &[u8], dns_server: &str) -> Result<Vec<u8>, DnsError> {
    // Establish TCP connection to the DNS server
    let mut stream = TcpStream::connect(dns_server)
        .map_err(|e| DnsError::Network(format!("Failed to connect to {dns_server} (TCP): {e}")))?;

    // Set read and write timeouts
    let timeout = Duration::from_secs(3);
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| DnsError::Network(format!("Failed to set read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(timeout))
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

    // Read the actual response
    let mut response_buffer = vec![0u8; response_len];
    stream
        .read_exact(&mut response_buffer)
        .map_err(|_| DnsError::Network("Failed to read response".to_owned()))?;

    Ok(response_buffer)
}

fn build_dns_query(
    domain: &str,
    query_type: &QueryType,
    recursion: bool,
) -> Result<DnsPacket, DnsError> {
    if domain.is_empty() {
        return Err(DnsError::InvalidData(
            "Domain name cannot be empty".to_owned(),
        ));
    }

    // Reverse the IP address for PTR queries
    let domain = if query_type == &QueryType::PTR {
        domain
            .parse::<Ipv4Addr>()
            .map_or_else(|_| domain.to_owned(), ip_to_ptr)
    } else {
        domain.to_owned()
    };

    let mut packet = DnsPacket::new();
    packet.header.id = rand::rng().random();
    packet.header.questions = 1;
    packet.header.recursion_desired = recursion;
    packet
        .questions
        .push(DnsQuestion::new(domain, query_type.clone()));

    Ok(packet)
}

fn ip_to_ptr(ip: Ipv4Addr) -> String {
    ip.octets()
        .iter()
        .rev()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
        + ".in-addr.arpa"
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
    fn test_ip_to_ptr() {
        let ip = Ipv4Addr::new(192, 168, 1, 22);
        let ptr = ip_to_ptr(ip);

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
}
