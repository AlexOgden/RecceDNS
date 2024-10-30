use anyhow::{Context, Result};

use crate::dns::error::DnsError;
use crate::dns::protocol::{DnsQueryResponse, QueryType};
use crate::io::packet_buffer::PacketBuffer;
use crate::network::types::TransportProtocol;
use lazy_static::lazy_static;
use rand::Rng;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::protocol::{DnsPacket, DnsQuestion, ResultCode};

lazy_static! {
    static ref UDP_SOCKET: Mutex<Option<Arc<UdpSocket>>> = Mutex::new(None);
}
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
) -> Result<Vec<DnsQueryResponse>, DnsError> {
    let udp_socket =
        initialize_udp_socket().map_err(|error| DnsError::Network(error.to_string()))?;

    let query_result = execute_dns_query(
        &udp_socket,
        transport_protocol,
        dns_server,
        domain,
        query_type,
    )?;

    match query_result.header.rescode {
        ResultCode::NOERROR => {
            if query_result.answers.is_empty() {
                Err(DnsError::NoRecordsFound)
            } else {
                Ok(query_result.answers)
            }
        }
        ResultCode::NXDOMAIN => Err(DnsError::NonExistentDomain),
        ResultCode::SERVFAIL => Err(DnsError::NameserverError("Server failed".to_owned())),
        ResultCode::NOTIMP => Err(DnsError::NameserverError("Not implemented".to_owned())),
        ResultCode::REFUSED => Err(DnsError::NameserverError("Refused".to_owned())),
        ResultCode::FORMERR => Err(DnsError::ProtocolData("Format error".to_owned())),
    }
}

fn execute_dns_query(
    socket: &UdpSocket,
    transport_protocol: &TransportProtocol,
    dns_server: &str,
    domain: &str,
    query_type: &QueryType,
) -> Result<DnsPacket, DnsError> {
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
            DnsError::Network(
                "Failed to receive response (UDP): Connection attempt failed.".to_string(),
            )
        } else {
            DnsError::Network(format!("Failed to receive response (UDP): {error}"))
        }
    })?;

    Ok(response_buffer[..bytes_received].to_vec())
}

fn send_dns_query_tcp(query: &[u8], dns_server: &str) -> Result<Vec<u8>, DnsError> {
    let mut stream = TcpStream::connect(dns_server)
        .map_err(|e| DnsError::Network(format!("Failed to connect to {dns_server} (TCP): {e}")))?;

    let timeout = Some(Duration::new(3, 0));
    stream
        .set_read_timeout(timeout)
        .and_then(|()| stream.set_write_timeout(timeout))
        .map_err(|e| DnsError::Network(format!("Failed to set timeout: {e}")))?;

    let query_len = u16::try_from(query.len())
        .map_err(|_| DnsError::InvalidData("Query length exceeds u16 maximum value".to_owned()))?
        .to_be_bytes();
    stream
        .write_all(&query_len)
        .and_then(|()| stream.write_all(query))
        .map_err(|e| DnsError::Network(format!("Failed to write query: {e}")))?;

    let mut len_buffer = [0; 2];
    stream
        .read_exact(&mut len_buffer)
        .map_err(|_| DnsError::Network("Failed to read response length".to_owned()))?;
    let response_len = u16::from_be_bytes(len_buffer) as usize;

    let mut response_buffer = vec![0; response_len];
    stream
        .read_exact(&mut response_buffer)
        .map_err(|_| DnsError::Network("Failed to read response".to_owned()))?;

    Ok(response_buffer)
}

fn build_dns_query(domain: &str, query_type: &QueryType) -> Result<DnsPacket, DnsError> {
    if domain.is_empty() {
        return Err(DnsError::InvalidData(
            "Domain name cannot be empty".to_owned(),
        ));
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

fn parse_dns_response(response: &[u8]) -> Result<DnsPacket, DnsError> {
    let mut packet_buffer = PacketBuffer::new();
    packet_buffer
        .set_data(response)
        .map_err(|_| DnsError::InvalidData("Invalid response".to_owned()))?;

    let dns_packet = DnsPacket::from_buffer(&mut packet_buffer)?;

    Ok(dns_packet)
}
