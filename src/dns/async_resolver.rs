use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, atomic},
    time::Duration,
};

use dashmap::DashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, broadcast, oneshot},
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
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1500); // Default request timeout (UDP/TCP)
const UDP_BUFFER_SIZE: usize = 512; // Standard DNS UDP buffer size for receiving
const TCP_BUFFER_SIZE: usize = 65535; // Max DNS TCP message size
const DNS_PORT: u16 = 53; // Standard DNS port

#[derive(Clone)]
pub struct AsyncResolver {
    udp_sockets: Vec<Arc<UdpSocket>>,
    tcp_sockets: Arc<DashMap<SocketAddr, Arc<Mutex<TcpStream>>>>,
    next_query_id: Arc<atomic::AtomicU16>,
    pending_queries: Arc<DashMap<u16, QueryResultSender>>,
    next_udp_socket_index: Arc<atomic::AtomicUsize>,
    shutdown_tx: Arc<broadcast::Sender<()>>,
}

impl AsyncResolver {
    pub async fn new(udp_pool_size: Option<usize>) -> Result<Self, DnsError> {
        let udp_pool_size = udp_pool_size.unwrap_or(DEFAULT_POOL_SIZE);

        let mut udp_sockets: Vec<Arc<UdpSocket>> = Vec::with_capacity(udp_pool_size);
        let pending_queries = Arc::new(DashMap::<u16, QueryResultSender>::new());
        let (shutdown_tx, _) = broadcast::channel(1);
        let shutdown_tx_arc = Arc::new(shutdown_tx);

        for i in 0..udp_pool_size {
            let udp_socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| DnsError::Network(format!("Failed to bind UDP socket {i}: {e}")))?;
            let udp_socket_arc = Arc::new(udp_socket);
            udp_sockets.push(udp_socket_arc.clone());

            let pq_clone = pending_queries.clone();
            let mut shutdown_rx = shutdown_tx_arc.subscribe();
            let local_addr = udp_socket_arc.local_addr().ok();

            tokio::spawn(async move {
                let mut recv_buffer = [0u8; UDP_BUFFER_SIZE];
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.recv() => { break; },
                        result = udp_socket_arc.recv_from(&mut recv_buffer) => {
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
            udp_sockets,
            tcp_sockets: Arc::new(DashMap::new()),
            next_query_id: Arc::new(atomic::AtomicU16::new(0)),
            pending_queries,
            next_udp_socket_index: Arc::new(atomic::AtomicUsize::new(0)),
            shutdown_tx: shutdown_tx_arc,
        })
    }

    async fn get_or_create_tcp_connection(
        &self,
        target_addr: SocketAddr,
    ) -> Result<Arc<Mutex<TcpStream>>, DnsError> {
        if let Some(entry) = self.tcp_sockets.get(&target_addr) {
            return Ok(entry.value().clone());
        }

        let tcp_stream = match timeout(DEFAULT_TIMEOUT, TcpStream::connect(target_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(DnsError::Network(format!(
                    "Failed to connect to {target_addr}: {e}"
                )));
            }
            Err(_) => {
                return Err(DnsError::Network(format!(
                    "Timeout connecting to {target_addr}"
                )));
            }
        };

        let connection = Arc::new(Mutex::new(tcp_stream));
        self.tcp_sockets.insert(target_addr, connection.clone());
        Ok(connection)
    }

    pub async fn resolve(
        &self,
        dns_resolver: &Ipv4Addr,
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
            // Check if this id is currently in use. If not, reserve it by breaking with it.
            if !self.pending_queries.contains_key(&id) {
                break id;
            }
            attempts += 1;
            // If we've tried all possible u16 values, give up.
            if attempts >= 65536 {
                return Err(DnsError::Internal("No available query IDs".to_string()));
            }
        };
        let query_packet = Self::build_dns_query(query_id, domain, query_type, recursion)?;

        match protocol {
            TransportProtocol::UDP => self.resolve_udp(dns_resolver, query_packet).await,
            TransportProtocol::TCP => self.resolve_tcp(dns_resolver, query_packet).await,
        }
    }

    async fn resolve_udp(
        &self,
        dns_resolver: &Ipv4Addr,
        mut query_packet: DnsPacket,
    ) -> Result<DnsPacket, DnsError> {
        if self.udp_sockets.is_empty() {
            return Err(DnsError::Internal(
                "Cannot resolve UDP, pool size is 0".to_string(),
            ));
        }

        let query_id = query_packet.header.id;

        // Serialize packet
        let mut udp_req_buffer = PacketBuffer::new();
        query_packet
            .write(&mut udp_req_buffer)
            .map_err(|e| DnsError::Internal(format!("UDP: Failed to serialize query: {e}")))?;
        let udp_request_data = udp_req_buffer.get_buffer_to_pos().to_vec();

        // Prepare for response via oneshot channel
        let (tx, rx) = oneshot::channel::<PendingQueryResult>();
        if self.pending_queries.insert(query_id, tx).is_some() {
            return Err(DnsError::Internal(format!(
                "UDP: Query ID collision: {query_id}"
            )));
        }

        // Select socket and send
        let udp_socket_index = self
            .next_udp_socket_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.udp_sockets.len();
        let udp_socket = &self.udp_sockets[udp_socket_index];

        let target_sock_addr = SocketAddr::new((*dns_resolver).into(), DNS_PORT);

        if let Err(e) = udp_socket
            .send_to(&udp_request_data, target_sock_addr)
            .await
        {
            self.pending_queries.remove(&query_id);
            return Err(DnsError::Network(format!(
                "UDP: Failed to send query to {target_sock_addr}: {e}"
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
                // Remove the pending query entry
                self.pending_queries.remove(&query_id);
                Err(DnsError::Timeout(dns_resolver.to_string()))
            }
        }
    }

    async fn resolve_tcp(
        &self,
        dns_resolver: &Ipv4Addr,
        mut query_packet: DnsPacket,
    ) -> Result<DnsPacket, DnsError> {
        let target_sock_addr = SocketAddr::new((*dns_resolver).into(), DNS_PORT);

        let tcp_connection_mutex = self.get_or_create_tcp_connection(target_sock_addr).await?;
        let mut tcp_connection_guard = tcp_connection_mutex.lock().await;

        let query_id = query_packet.header.id;

        let result: Result<DnsPacket, DnsError> = async {
            // Serialize packet
            let mut request_buffer = PacketBuffer::new();
            query_packet
                .write(&mut request_buffer)
                .map_err(|e| DnsError::Internal(format!("TCP: Failed to serialize query: {e}")))?;
            let request_bytes = request_buffer.get_buffer_to_pos();

            // Prepend 2-byte length field (Big Endian)
            let query_len = u16::try_from(request_bytes.len()).map_err(|_| {
                DnsError::InvalidData("TCP: Query data length exceeds 65535 bytes".to_string())
            })?;
            if query_len == 0 {
                return Err(DnsError::InvalidData(
                    "TCP: Serialized query data is empty".to_string(),
                ));
            }
            let mut tcp_request_data = Vec::with_capacity(2 + request_bytes.len());
            tcp_request_data.extend_from_slice(&query_len.to_be_bytes());
            tcp_request_data.extend_from_slice(request_bytes);

            // Write request
            match timeout(
                DEFAULT_TIMEOUT,
                tcp_connection_guard.write_all(&tcp_request_data),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    return Err(DnsError::Network(format!(
                        "Failed to write request to {target_sock_addr}: {e}"
                    )));
                }
                Err(_) => {
                    return Err(DnsError::Timeout(dns_resolver.to_string()));
                }
            }

            // Read response length (2 bytes) with timeout
            let mut response_len_buffer = [0u8; 2];
            match timeout(
                DEFAULT_TIMEOUT,
                tcp_connection_guard.read_exact(&mut response_len_buffer),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    return Err(DnsError::Network(format!(
                        "Failed to read response length from {target_sock_addr}: {e}"
                    )));
                }
                Err(_) => {
                    return Err(DnsError::Timeout(dns_resolver.to_string()));
                }
            }
            let response_len = u16::from_be_bytes(response_len_buffer) as usize;

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
            let mut response_body_buffer = vec![0u8; response_len];
            match timeout(
                DEFAULT_TIMEOUT,
                tcp_connection_guard.read_exact(&mut response_body_buffer),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    return Err(DnsError::Network(format!(
                        "Failed to read response from {target_sock_addr}: {e}"
                    )));
                }
                Err(_) => {
                    return Err(DnsError::Timeout(dns_resolver.to_string()));
                }
            }

            let mut response_packet_buffer = PacketBuffer::from_slice(&response_body_buffer)
                .map_err(|e| DnsError::Internal(format!("Failed to create PacketBuffer: {e}")))?;
            let response_packet = DnsPacket::from_buffer(&mut response_packet_buffer)?;

            // Verify response ID matches query ID
            if response_packet.header.id != query_id {
                return Err(DnsError::InvalidData(format!(
                    "DNS: Response ID {} does not match query ID {}",
                    response_packet.header.id, query_id
                )));
            }

            Self::process_dns_result(response_packet)
        }
        .await;

        if result.is_err() {
            self.tcp_sockets.remove(&target_sock_addr);
        }

        result
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

impl Drop for AsyncResolver {
    fn drop(&mut self) {
        self.shutdown();
    }
}
