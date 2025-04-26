use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, atomic},
    time::Duration,
};

use dashmap::DashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{broadcast, oneshot},
    time::timeout,
};

use crate::{io::packet_buffer::PacketBuffer, log_error, network::types::TransportProtocol};

use super::{
    error::DnsError,
    protocol::{DnsPacket, DnsQuestion, QueryType, ResultCode},
};

// Type aliases for clarity (UDP specific)
type PendingQueryResult = Result<DnsPacket, DnsError>;
type QueryResultSender = oneshot::Sender<PendingQueryResult>;

// Constants for default settings
const DEFAULT_POOL_SIZE: usize = 10; // Default number of UDP sockets in the pool
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1); // Default request timeout (UDP/TCP)
const UDP_BUFFER_SIZE: usize = 512; // Standard DNS UDP buffer size for receiving
const TCP_BUFFER_SIZE: usize = 65535; // Max DNS TCP message size
const DNS_PORT: u16 = 53; // Standard DNS port

#[derive(Clone)]
pub struct AsyncResolverPool {
    sockets: Vec<Arc<UdpSocket>>,
    next_query_id: Arc<atomic::AtomicU16>,
    pending_queries: Arc<DashMap<u16, QueryResultSender>>,
    next_socket_index: Arc<atomic::AtomicUsize>,
    shutdown_tx: Arc<broadcast::Sender<()>>,
}

impl AsyncResolverPool {
    pub async fn new(pool_size: Option<usize>) -> Result<Self, DnsError> {
        let pool_size = pool_size.unwrap_or(DEFAULT_POOL_SIZE);

        let mut sockets = Vec::with_capacity(pool_size);
        let pending_queries = Arc::new(DashMap::<u16, QueryResultSender>::new());
        let (shutdown_tx, _) = broadcast::channel(1);
        let shutdown_tx_arc = Arc::new(shutdown_tx);

        for i in 0..pool_size {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| DnsError::Network(format!("Failed to bind UDP socket {i}: {e}")))?;
            let socket_arc = Arc::new(socket);
            sockets.push(socket_arc.clone());

            let pq_clone = pending_queries.clone();
            let mut shutdown_rx = shutdown_tx_arc.subscribe();
            let local_addr = socket_arc.local_addr().ok();

            tokio::spawn(async move {
                let mut recv_buffer = [0u8; UDP_BUFFER_SIZE];
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.recv() => { break; },
                        result = socket_arc.recv_from(&mut recv_buffer) => {
                            match result {
                                Ok((len, _src_addr)) => {
                                    if len >= 2 {
                                        let query_id = u16::from_be_bytes(recv_buffer[0..2].try_into().unwrap());
                                        if let Some((_id, sender)) = pq_clone.remove(&query_id) {
                                            let mut packet_buffer = PacketBuffer::new();
                                            if packet_buffer.set_data(&recv_buffer[..len]).is_ok() {
                                                match DnsPacket::from_buffer(&mut packet_buffer) {
                                                    Ok(dns_packet) => { let _ = sender.send(Ok(dns_packet)); }
                                                    Err(e) => {
                                                        log_error!(format!("Failed UDP parse (ID: {}) on {:?}: {}", query_id, local_addr, e));
                                                        let _ = sender.send(Err(DnsError::ProtocolData(e.to_string())));
                                                    }
                                                }
                                            } else {
                                                 log_error!(format!("Failed UDP set_data (ID: {}) on {:?}", query_id, local_addr));
                                                 let _ = sender.send(Err(DnsError::Internal("UDP Buffer handling error".to_string())));
                                            }
                                        }
                                    } else if len > 0 { /* Packet too small */ }
                                }
                                Err(e) => { /* Handle UDP recv error */ log_error!(format!("ERROR: UDP Recv: {}", e)); }
                            }
                        },
                    }
                }
            });
        }

        Ok(Self {
            sockets,
            next_query_id: Arc::new(atomic::AtomicU16::new(0)),
            pending_queries,
            next_socket_index: Arc::new(atomic::AtomicUsize::new(0)),
            shutdown_tx: shutdown_tx_arc,
        })
    }

    pub async fn resolve(
        &self,
        dns_resolver: &str,
        domain: &str,
        query_type: &QueryType,
        protocol: &TransportProtocol,
        recursion: bool,
    ) -> Result<DnsPacket, DnsError> {
        let mut attempts = 0;
        let query_id = loop {
            let id = self
                .next_query_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let id = id % 65535;
            if !self.pending_queries.contains_key(&id) {
                break id;
            }
            attempts += 1;
            if attempts > 65536 {
                return Err(DnsError::Internal("No available query IDs".to_string()));
            }
        };
        let query_packet = Self::build_dns_query(query_id, domain, query_type, recursion)?;

        match protocol {
            TransportProtocol::UDP => self.resolve_udp(dns_resolver, query_packet).await,
            TransportProtocol::TCP => Self::resolve_tcp(dns_resolver, query_packet).await,
        }
    }

    async fn resolve_udp(
        &self,
        dns_resolver: &str,
        mut query_packet: DnsPacket,
    ) -> Result<DnsPacket, DnsError> {
        if self.sockets.is_empty() {
            return Err(DnsError::Internal(
                "Cannot resolve UDP, pool size is 0".to_string(),
            ));
        }

        let query_id = query_packet.header.id;

        // Serialize packet
        let mut req_buffer = PacketBuffer::new();
        query_packet
            .write(&mut req_buffer)
            .map_err(|e| DnsError::Internal(format!("UDP: Failed to serialize query: {e}")))?;
        let request_data = req_buffer.get_buffer_to_pos().to_vec();

        // Prepare for response via oneshot channel
        let (tx, rx) = oneshot::channel::<PendingQueryResult>();
        if self.pending_queries.insert(query_id, tx).is_some() {
            return Err(DnsError::Internal(format!(
                "UDP: Query ID collision: {query_id}"
            )));
        }

        // Select socket and send
        let socket_index = self
            .next_socket_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.sockets.len();
        let socket = &self.sockets[socket_index];

        let target_addr_str = format!("{dns_resolver}:{DNS_PORT}");
        let target_sock_addr: SocketAddr = match target_addr_str.parse() {
            Ok(addr) => addr,
            Err(e) => {
                self.pending_queries.remove(&query_id);
                return Err(DnsError::Network(format!(
                    "UDP: Invalid resolver address '{target_addr_str}': {e}"
                )));
            }
        };

        if let Err(e) = socket.send_to(&request_data, target_sock_addr).await {
            self.pending_queries.remove(&query_id);
            return Err(DnsError::Network(format!(
                "UDP: Failed to send query to {target_addr_str}: {e}"
            )));
        }

        // Wait for response with timeout
        match timeout(DEFAULT_TIMEOUT, rx).await {
            Ok(Ok(result_from_channel)) => {
                // Received result from receiver task
                match result_from_channel {
                    Ok(packet) => Self::process_dns_result(packet),
                    Err(e) => Err(e),
                }
            }
            Ok(Err(_recv_error)) => {
                self.pending_queries.remove(&query_id);
                Err(DnsError::Internal(
                    "UDP: Resolver receiver task channel closed unexpectedly".to_string(),
                ))
            }
            Err(_timeout_elapsed) => {
                self.pending_queries.remove(&query_id);
                Err(DnsError::Timeout(dns_resolver.to_owned()))
            }
        }
    }

    async fn resolve_tcp(
        dns_resolver: &str,
        mut query_packet: DnsPacket,
    ) -> Result<DnsPacket, DnsError> {
        let query_id = query_packet.header.id;

        // Serialize packet
        let mut req_buffer = PacketBuffer::new();
        query_packet
            .write(&mut req_buffer)
            .map_err(|e| DnsError::Internal(format!("TCP: Failed to serialize query: {e}")))?;
        let query_data = req_buffer.get_buffer_to_pos();

        // Prepend 2-byte length field (Big Endian)
        let query_len = u16::try_from(query_data.len()).map_err(|_| {
            DnsError::InvalidData("TCP: Query data length exceeds 65535 bytes".to_string())
        })?;
        if query_len == 0 {
            return Err(DnsError::InvalidData(
                "TCP: Serialized query data is empty".to_string(),
            ));
        }
        let mut tcp_request_data = Vec::with_capacity(2 + query_data.len());
        tcp_request_data.extend_from_slice(&query_len.to_be_bytes());
        tcp_request_data.extend_from_slice(query_data);

        let target_addr_str = format!("{dns_resolver}:{DNS_PORT}");

        // Establish TCP connection with timeout
        let stream = match timeout(DEFAULT_TIMEOUT, TcpStream::connect(&target_addr_str)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(DnsError::Network(format!(
                    "Failed to connect to {target_addr_str}: {e}"
                )));
            }
            Err(_) => {
                return Err(DnsError::Network(format!(
                    "Timeout connecting to {target_addr_str}"
                )));
            }
        };
        let (mut reader, mut writer) = stream.into_split();

        match timeout(DEFAULT_TIMEOUT, writer.write_all(&tcp_request_data)).await {
            Ok(Ok(())) => { /* Write successful */ }
            Ok(Err(e)) => {
                return Err(DnsError::Network(format!(
                    "Failed to write request to {target_addr_str}: {e}"
                )));
            }
            Err(_) => {
                return Err(DnsError::Timeout(dns_resolver.to_owned()));
            }
        }

        // Read response length (2 bytes) with timeout
        let mut len_buffer = [0u8; 2];
        match timeout(DEFAULT_TIMEOUT, reader.read_exact(&mut len_buffer)).await {
            Ok(Ok(_)) => { /* Read length successful */ }
            Ok(Err(e)) => {
                return Err(DnsError::Network(format!(
                    "Failed to read response length from {target_addr_str}: {e}"
                )));
            }
            Err(_) => {
                return Err(DnsError::Timeout(dns_resolver.to_owned()));
            }
        }
        let response_len = u16::from_be_bytes(len_buffer) as usize;

        if response_len == 0 {
            return Err(DnsError::InvalidData(
                "TCP: Received zero length response".to_owned(),
            ));
        }
        // Basic sanity check for response size
        if response_len > TCP_BUFFER_SIZE {
            return Err(DnsError::InvalidData(format!(
                "TCP: Response length too large: {response_len} bytes (max: {TCP_BUFFER_SIZE})"
            )));
        }

        // Read the actual response with timeout
        let mut response_buffer = vec![0u8; response_len];
        match timeout(DEFAULT_TIMEOUT, reader.read_exact(&mut response_buffer)).await {
            Ok(Ok(_)) => { /* Read body successful */ }
            Ok(Err(e)) => {
                return Err(DnsError::Network(format!(
                    "Failed to read response from {target_addr_str}: {e}"
                )));
            }
            Err(_) => {
                return Err(DnsError::Timeout(dns_resolver.to_owned()));
            }
        }

        let mut packet_buffer = PacketBuffer::from_slice(&response_buffer)
            .map_err(|e| DnsError::Internal(format!("Failed to create PacketBuffer: {e}")))?;
        let response_packet = DnsPacket::from_buffer(&mut packet_buffer)?;

        // Verify response ID matches query ID
        if response_packet.header.id != query_id {
            return Err(DnsError::InvalidData(format!(
                "DNS: Response ID {} does not match query ID {}",
                response_packet.header.id, query_id
            )));
        }

        Self::process_dns_result(response_packet)
    }

    fn process_dns_result(query_result: DnsPacket) -> Result<DnsPacket, DnsError> {
        match query_result.header.rescode {
            ResultCode::NOERROR => {
                if query_result.answers.is_empty()
                    && query_result
                        .questions
                        .first()
                        .is_none_or(|q| q.qtype != QueryType::SOA)
                {
                    Err(DnsError::NoRecordsFound)
                } else {
                    Ok(query_result)
                }
            }
            ResultCode::NXDOMAIN => Err(DnsError::NonExistentDomain),
            ResultCode::SERVFAIL => {
                Err(DnsError::Nameserver("Server Failed (SERVFAIL)".to_owned()))
            }
            ResultCode::NOTIMP => Err(DnsError::Nameserver("Not Implemented (NOTIMP)".to_owned())),
            ResultCode::REFUSED => Err(DnsError::Nameserver("Refused (REFUSED)".to_owned())),
            ResultCode::FORMERR => Err(DnsError::ProtocolData("Format Error (FORMERR)".to_owned())),
        }
    }

    fn build_dns_query(
        query_id: u16,
        domain: &str,
        query_type: &QueryType,
        recursion: bool,
    ) -> Result<DnsPacket, DnsError> {
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
                crate::network::util::ipv4_to_ptr(ipv4)
            } else if let Ok(ipv6) = domain.parse::<Ipv6Addr>() {
                crate::network::util::ipv6_to_ptr(&ipv6)
            } else {
                domain.to_owned()
            }
        } else {
            domain.to_owned()
        };

        let mut packet = DnsPacket::new();
        packet.header.id = query_id;
        packet.header.questions = 1;
        packet.header.recursion_desired = recursion;
        packet
            .questions
            .push(DnsQuestion::new(domain, query_type.clone()));

        Ok(packet)
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}
