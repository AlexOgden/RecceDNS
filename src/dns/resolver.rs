use anyhow::{Context, Result};

use crate::dns::error::Error;
use crate::dns::protocol::{DnsQueryResponse, QueryType};
use crate::io::packet_buffer::PacketBuffer;
use crate::network::types::TransportProtocol;
use once_cell::sync::Lazy;
use rand::Rng;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::protocol::{DnsPacket, DnsQuestion};

static UDP_SOCKET: Lazy<Mutex<Option<Arc<UdpSocket>>>> = Lazy::new(|| Mutex::new(None));
const DNS_PORT: u8 = 53;
const UDP_BUFFER_SIZE: usize = 512;

fn initialize_udp_socket() -> Result<Arc<UdpSocket>> {
    let mut socket_guard = UDP_SOCKET.lock().expect("Failed to lock the socket mutex");
    if socket_guard.is_none() {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let timeout = Duration::from_secs(3);

        socket
            .set_read_timeout(Some(timeout))
            .context("Failed to set read timeout")?;
        socket
            .set_write_timeout(Some(timeout))
            .context("Failed to set write timeout")?;

        *socket_guard = Some(Arc::new(socket));
    }
    Ok(Arc::clone(
        socket_guard.as_ref().expect("Socket should be initialized"),
    ))
}

pub fn resolve_domain(
    dns_server: &str,
    domain: &str,
    query_type: &QueryType,
    transport_protocol: &TransportProtocol,
) -> Result<Vec<DnsQueryResponse>> {
    let mut all_results = HashSet::new();
    let udp_socket = initialize_udp_socket()?;

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
        let query_result =
            execute_dns_query(&udp_socket, transport_protocol, dns_server, domain, qt)?;

        for response in query_result.answers {
            all_results.insert(response);
        }
    }

    if all_results.is_empty() {
        Err(Error::NoRecordsFound.into())
    } else {
        Ok(all_results.into_iter().collect())
    }
}

fn execute_dns_query(
    socket: &UdpSocket,
    transport_protocol: &TransportProtocol,
    dns_server: &str,
    domain: &str,
    query_type: &QueryType,
) -> Result<DnsPacket> {
    let dns_server_address = format!("{dns_server}:{DNS_PORT}");

    let mut query = build_dns_query(domain, query_type)?;
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
    parse_dns_response(&response)
}

fn send_dns_query_udp(socket: &UdpSocket, query: &[u8], dns_server: &str) -> Result<Vec<u8>> {
    socket.send_to(query, dns_server).map_err(|error| {
        Error::Network(format!(
            "Failed to send query to {dns_server} (UDP): {error}"
        ))
    })?;

    let mut response_buffer = [0; UDP_BUFFER_SIZE];
    let (bytes_received, _) = socket
        .recv_from(&mut response_buffer)
        .map_err(|error| Error::Network(format!("Failed to receive response (UDP): {error}")))?;

    Ok(response_buffer[..bytes_received].to_vec())
}

fn send_dns_query_tcp(query: &[u8], dns_server: &str) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(dns_server).map_err(|error| {
        Error::Network(format!("Failed to connect to {dns_server} (TCP): {error}"))
    })?;

    // Prefix the query with its length (2 bytes, big-endian)
    let query_len = u16::try_from(query.len())
        .map_err(|_| Error::InvalidData("Query length exceeds u16 maximum value".to_owned()))?
        .to_be_bytes();
    stream.write_all(&query_len)?;
    stream.write_all(query)?;

    // Read the length of the response (2 bytes, big-endian)
    let mut len_buffer = [0; 2];
    stream.read_exact(&mut len_buffer)?;
    let response_len = u16::from_be_bytes(len_buffer) as usize;

    // Read the response
    let mut response_buffer = vec![0; response_len];
    stream.read_exact(&mut response_buffer)?;

    Ok(response_buffer)
}

fn build_dns_query(domain: &str, query_type: &QueryType) -> Result<DnsPacket> {
    if domain.is_empty() {
        return Err(Error::InvalidData("Domain name cannot be empty".to_owned()).into());
    }

    let mut packet = DnsPacket::new();
    packet.header.id = rand::thread_rng().gen();
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(domain.to_owned(), query_type.clone()));

    Ok(packet)
}

fn parse_dns_response(response: &[u8]) -> Result<DnsPacket> {
    let mut packet_buffer = PacketBuffer::new();
    packet_buffer.set_data(response)?;

    let dns_packet = DnsPacket::from_buffer(&mut packet_buffer)?;

    Ok(dns_packet)
}
