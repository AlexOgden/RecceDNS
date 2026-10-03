use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{self, Ordering},
    },
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
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1500); // Default request timeout (UDP/TCP)
const UDP_BUFFER_SIZE: usize = 512; // Standard DNS UDP buffer size for receiving
const TCP_BUFFER_SIZE: usize = 65535; // Max DNS TCP message size

struct UdpSocketEntry {
    socket: Arc<UdpSocket>,
    pending_queries: Arc<DashMap<u16, QueryResultSender>>,
    next_query_id: atomic::AtomicU16,
}

impl UdpSocketEntry {
    fn allocate_query_id(&self, tx: QueryResultSender) -> Result<u16, DnsError> {
        let mut attempts = 0;
        loop {
            let id = self.next_query_id.fetch_add(1, Ordering::Relaxed);
            match self.pending_queries.entry(id) {
                dashmap::Entry::Vacant(vacant) => {
                    vacant.insert(tx);
                    return Ok(id);
                }
                dashmap::Entry::Occupied(_) => {
                    attempts += 1;
                    if attempts >= 65536 {
                        return Err(DnsError::Internal(
                            "All query IDs in use for socket".to_string(),
                        ));
                    }
                }
            }
        }
    }
}

struct ResolverInner {
    udp_entries: Box<[UdpSocketEntry]>,
    tcp_sockets: DashMap<SocketAddr, Arc<Mutex<TcpStream>>>,
    next_udp_socket_index: atomic::AtomicUsize,
    next_tcp_query_id: atomic::AtomicU16,
    shutdown_tx: broadcast::Sender<()>,
}

impl Drop for ResolverInner {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[derive(Clone)]
pub struct AsyncResolver {
    inner: Arc<ResolverInner>,
}

impl AsyncResolver {
    pub async fn new(udp_pool_size: Option<usize>) -> Result<Self, DnsError> {
        let default_pool_size = crate::cpu::count().clamp(4, 16);
        let udp_pool_size = udp_pool_size.map_or(default_pool_size, |s| s.clamp(1, 16));

        let mut udp_entries = Vec::with_capacity(udp_pool_size);
        let (shutdown_tx, _) = broadcast::channel(1);

        for i in 0..udp_pool_size {
            let udp_socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| DnsError::Network(format!("Failed to bind UDP socket {i}: {e}")))?;
            let udp_socket_arc = Arc::new(udp_socket);
            let pending_queries = Arc::new(DashMap::<u16, QueryResultSender>::new());

            let pq_clone = pending_queries.clone();
            let udp_socket_clone = udp_socket_arc.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();
            let local_addr = udp_socket_arc.local_addr().ok();
            let addr_str = local_addr.map_or_else(|| "unknown".to_string(), |a| a.to_string());

            tokio::spawn(async move {
                let mut recv_buffer = [0u8; UDP_BUFFER_SIZE];
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.recv() => { break; }
                        result = udp_socket_clone.recv_from(&mut recv_buffer) => {
                            match result {
                                Ok((len, _src_addr)) => {
                                    if len >= 2 {
                                        let query_id = u16::from_be_bytes([recv_buffer[0], recv_buffer[1]]);
                                        if let Some((_id, sender)) = pq_clone.remove(&query_id) {
                                            let mut packet_buffer = PacketBuffer::new();
                                            if packet_buffer.set_data(&recv_buffer[..len]).is_ok() {
                                                match DnsPacket::from_buffer(&mut packet_buffer) {
                                                    Ok(dns_packet) => { let _ = sender.send(Ok(dns_packet)); }
                                                    Err(e) => {
                                                        log_error!(format!("Failed UDP parse (ID: {query_id}) on {addr_str}: {e}"));
                                                        let _ = sender.send(Err(DnsError::ProtocolData(e.to_string())));
                                                    }
                                                }
                                            } else {
                                                 log_error!(format!("Failed UDP set_data (ID: {query_id}) on {addr_str}"));
                                                 let _ = sender.send(Err(DnsError::Internal("UDP Buffer handling error".to_string())));
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log_error!(format!("ERROR: UDP Recv: {e}"));
                                }
                            }
                        }
                    }
                }
            });

            udp_entries.push(UdpSocketEntry {
                socket: udp_socket_arc,
                pending_queries,
                next_query_id: atomic::AtomicU16::new(0),
            });
        }

        Ok(Self {
            inner: Arc::new(ResolverInner {
                udp_entries: udp_entries.into_boxed_slice(),
                tcp_sockets: DashMap::new(),
                next_udp_socket_index: atomic::AtomicUsize::new(0),
                next_tcp_query_id: atomic::AtomicU16::new(0),
                shutdown_tx,
            }),
        })
    }

    async fn get_or_create_tcp_connection(
        &self,
        target_addr: SocketAddr,
    ) -> Result<Arc<Mutex<TcpStream>>, DnsError> {
        if let Some(entry) = self.inner.tcp_sockets.get(&target_addr) {
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
        self.inner
            .tcp_sockets
            .insert(target_addr, connection.clone());
        Ok(connection)
    }

    pub async fn resolve(
        &self,
        dns_resolver: SocketAddr,
        domain: &str,
        query_type: &QueryType,
        protocol: &TransportProtocol,
        recursion: bool,
    ) -> Result<DnsPacket, DnsError> {
        match protocol {
            TransportProtocol::UDP => {
                self.resolve_udp(dns_resolver, domain, query_type, recursion)
                    .await
            }
            TransportProtocol::TCP => {
                let query_id = self.inner.next_tcp_query_id.fetch_add(1, Ordering::Relaxed);
                let query_packet = Self::build_dns_query(query_id, domain, *query_type, recursion)?;
                self.resolve_tcp(dns_resolver, query_packet).await
            }
        }
    }

    async fn resolve_udp(
        &self,
        dns_resolver: SocketAddr,
        domain: &str,
        query_type: &QueryType,
        recursion: bool,
    ) -> Result<DnsPacket, DnsError> {
        if self.inner.udp_entries.is_empty() {
            return Err(DnsError::Internal(
                "Cannot resolve UDP, pool size is 0".to_string(),
            ));
        }

        let socket_index = self
            .inner
            .next_udp_socket_index
            .fetch_add(1, Ordering::Relaxed)
            % self.inner.udp_entries.len();
        let entry = &self.inner.udp_entries[socket_index];

        let (tx, rx) = oneshot::channel::<PendingQueryResult>();
        let query_id = entry.allocate_query_id(tx)?;

        let mut query_packet = match Self::build_dns_query(query_id, domain, *query_type, recursion)
        {
            Ok(p) => p,
            Err(e) => {
                entry.pending_queries.remove(&query_id);
                return Err(e);
            }
        };

        // Serialize packet
        let mut udp_req_buffer = PacketBuffer::new();
        if let Err(e) = query_packet.write(&mut udp_req_buffer) {
            entry.pending_queries.remove(&query_id);
            return Err(DnsError::Internal(format!(
                "UDP: Failed to serialize query: {e}"
            )));
        }
        let udp_request_data = udp_req_buffer.get_buffer_to_pos();

        if let Err(e) = entry.socket.send_to(udp_request_data, dns_resolver).await {
            entry.pending_queries.remove(&query_id);
            return Err(DnsError::Network(format!(
                "UDP: Failed to send query to {dns_resolver}: {e}"
            )));
        }

        // Wait for response with timeout
        match timeout(DEFAULT_TIMEOUT, rx).await {
            Ok(Ok(result_from_channel)) => match result_from_channel {
                Ok(packet) => Self::process_dns_result(packet),
                Err(e) => Err(e),
            },
            Ok(Err(_recv_error)) => {
                entry.pending_queries.remove(&query_id);
                Err(DnsError::Internal(
                    "UDP: Resolver receiver task channel closed unexpectedly".to_string(),
                ))
            }
            Err(_timeout_elapsed) => {
                entry.pending_queries.remove(&query_id);
                Err(DnsError::Timeout(dns_resolver.to_string()))
            }
        }
    }

    async fn resolve_tcp(
        &self,
        dns_resolver: SocketAddr,
        mut query_packet: DnsPacket,
    ) -> Result<DnsPacket, DnsError> {
        let tcp_connection_mutex = self.get_or_create_tcp_connection(dns_resolver).await?;
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
                        "Failed to write request to {dns_resolver}: {e}"
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
                        "Failed to read response length from {dns_resolver}: {e}"
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
                        "Failed to read response from {dns_resolver}: {e}"
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
            self.inner.tcp_sockets.remove(&dns_resolver);
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
        query_type: QueryType,
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
        let domain = if query_type == QueryType::PTR {
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
        packet.questions.push(DnsQuestion::new(domain, query_type));

        Ok(packet)
    }

    pub fn shutdown(&self) {
        let _ = self.inner.shutdown_tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{RData, ResourceRecord};

    #[tokio::test]
    async fn test_pool_size_clamping() {
        // Requested 4096 sockets must be clamped to 16
        let resolver = AsyncResolver::new(Some(4096)).await.unwrap();
        assert_eq!(resolver.inner.udp_entries.len(), 16);

        // Requested 0 sockets must be clamped to 1
        let resolver_zero = AsyncResolver::new(Some(0)).await.unwrap();
        assert_eq!(resolver_zero.inner.udp_entries.len(), 1);

        // Default pool size (None) must be between 4 and 16
        let resolver_default = AsyncResolver::new(None).await.unwrap();
        assert!(
            resolver_default.inner.udp_entries.len() >= 4
                && resolver_default.inner.udp_entries.len() <= 16
        );
    }

    #[tokio::test]
    async fn test_atomic_query_id_allocation() {
        let entry = UdpSocketEntry {
            socket: Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap()),
            pending_queries: Arc::new(DashMap::new()),
            next_query_id: atomic::AtomicU16::new(0),
        };

        // Allocate 100 query IDs concurrently
        let mut handles = Vec::new();
        let entry_arc = Arc::new(entry);

        for _ in 0..100 {
            let entry_clone = entry_arc.clone();
            handles.push(tokio::spawn(async move {
                let (tx, _rx) = oneshot::channel();
                entry_clone.allocate_query_id(tx).unwrap()
            }));
        }

        let mut allocated_ids = std::collections::HashSet::new();
        for handle in handles {
            let id = handle.await.unwrap();
            assert!(
                allocated_ids.insert(id),
                "Duplicate query ID allocated: {id}"
            );
        }
        assert_eq!(allocated_ids.len(), 100);
    }

    #[tokio::test]
    async fn test_cloned_resolver_not_killed_on_drop() {
        // Set up a mock UDP DNS server that responds to any query with a valid NOERROR A record
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = mock_socket.recv_from(&mut buf).await else {
                    break;
                };
                if len >= 12 {
                    let id = u16::from_be_bytes([buf[0], buf[1]]);
                    let mut response = DnsPacket::new();
                    response.header.id = id;
                    response.header.response = true;
                    response.header.rescode = ResultCode::NOERROR;
                    response
                        .questions
                        .push(DnsQuestion::new("example.com".to_string(), QueryType::A));
                    response.answers.push(ResourceRecord {
                        name: "example.com".to_string(),
                        class: 1,
                        ttl: 300,
                        data: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
                    });
                    let mut pb = PacketBuffer::new();
                    if response.write(&mut pb).is_ok() {
                        let _ = mock_socket.send_to(pb.get_buffer_to_pos(), src).await;
                    }
                }
            }
        });

        let resolver = AsyncResolver::new(Some(1)).await.unwrap();

        // Clone the resolver and immediately drop the clone
        let clone = resolver.clone();
        drop(clone);

        // Resolving on the original resolver MUST succeed and not hang or fail
        let res = resolver
            .resolve(
                mock_addr,
                "example.com",
                &QueryType::A,
                &TransportProtocol::UDP,
                true,
            )
            .await;

        server_task.abort();

        assert!(
            res.is_ok(),
            "Resolving after clone drop failed: {:?}",
            res.err()
        );
        let packet = res.unwrap();
        assert_eq!(packet.answers.len(), 1);
    }

    #[tokio::test]
    async fn test_cloned_resolver_multi_task_concurrent_drop() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = mock_socket.recv_from(&mut buf).await else {
                    break;
                };
                if len >= 12 {
                    let id = u16::from_be_bytes([buf[0], buf[1]]);
                    let mut response = DnsPacket::new();
                    response.header.id = id;
                    response.header.response = true;
                    response.header.rescode = ResultCode::NOERROR;
                    response.questions.push(DnsQuestion::new(
                        "concurrent.test".to_string(),
                        QueryType::A,
                    ));
                    response.answers.push(ResourceRecord {
                        name: "concurrent.test".to_string(),
                        class: 1,
                        ttl: 300,
                        data: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
                    });
                    let mut pb = PacketBuffer::new();
                    if response.write(&mut pb).is_ok() {
                        let _ = mock_socket.send_to(pb.get_buffer_to_pos(), src).await;
                    }
                }
            }
        });

        let resolver = AsyncResolver::new(Some(2)).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..20 {
            let clone = resolver.clone();
            handles.push(tokio::spawn(async move {
                tokio::task::yield_now().await;
                drop(clone);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Resolving on the original resolver MUST still succeed
        let res = resolver
            .resolve(
                mock_addr,
                "concurrent.test",
                &QueryType::A,
                &TransportProtocol::UDP,
                true,
            )
            .await;

        server_task.abort();

        assert!(
            res.is_ok(),
            "Resolving after multi-task clone drop failed: {:?}",
            res.err()
        );
    }

    #[tokio::test]
    async fn test_resolver_shutdown_idempotent() {
        let resolver = AsyncResolver::new(Some(1)).await.unwrap();
        resolver.shutdown();
        resolver.shutdown();
        drop(resolver);
    }
}
