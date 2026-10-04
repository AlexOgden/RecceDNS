use std::{
    borrow::Cow,
    future::Future,
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
    protocol::{DnsPacket, QueryType, ResultCode},
};

// Type aliases for clarity (UDP specific)
type PendingQueryResult = Result<PacketBuffer, DnsError>;
type QueryResultSender = oneshot::Sender<PendingQueryResult>;

// Constants for default settings
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1500); // Default request timeout (UDP/TCP)
const UDP_BUFFER_SIZE: usize = 512; // Standard DNS UDP buffer size for receiving
const TCP_BUFFER_SIZE: usize = 65535; // Max DNS TCP message size

/// RAII guard that automatically cleans up pending UDP queries if dropped before completion.
struct PendingQueryGuard<'a> {
    query_id: u16,
    pending_queries: &'a DashMap<u16, QueryResultSender>,
    active: bool,
}

impl<'a> PendingQueryGuard<'a> {
    const fn new(query_id: u16, pending_queries: &'a DashMap<u16, QueryResultSender>) -> Self {
        Self {
            query_id,
            pending_queries,
            active: true,
        }
    }

    const fn defuse(&mut self) {
        self.active = false;
    }
}

impl Drop for PendingQueryGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            self.pending_queries.remove(&self.query_id);
        }
    }
}

#[repr(align(64))]
struct UdpSocketEntry {
    socket: Arc<UdpSocket>,
    pending_queries: Arc<DashMap<u16, QueryResultSender>>,
    next_query_id: atomic::AtomicU16,
}

impl UdpSocketEntry {
    async fn bind(index: usize, shutdown_tx: &broadcast::Sender<()>) -> Result<Self, DnsError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| DnsError::Network(format!("Failed to bind UDP socket {index}: {e}")))?;
        let socket = Arc::new(socket);
        let pending_queries = Arc::new(DashMap::<u16, QueryResultSender>::new());

        spawn_udp_receiver(
            Arc::clone(&socket),
            Arc::clone(&pending_queries),
            shutdown_tx.subscribe(),
        );

        Ok(Self {
            socket,
            pending_queries,
            next_query_id: atomic::AtomicU16::new(0),
        })
    }

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

fn spawn_udp_receiver(
    socket: Arc<UdpSocket>,
    pending_queries: Arc<DashMap<u16, QueryResultSender>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let addr_str = socket
        .local_addr()
        .map_or_else(|_| "unknown".to_string(), |a| a.to_string());

    tokio::spawn(async move {
        let mut recv_buffer = [0u8; UDP_BUFFER_SIZE];
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => { break; }
                result = socket.recv_from(&mut recv_buffer) => {
                    match result {
                        Ok((len, _)) => dispatch_udp_response(&recv_buffer[..len], &pending_queries, &addr_str),
                        Err(e) => {
                            log_error!(format!("ERROR: UDP Recv: {e}"));
                        }
                    }
                }
            }
        }
    });
}

fn dispatch_udp_response(
    raw_data: &[u8],
    pending_queries: &DashMap<u16, QueryResultSender>,
    addr_str: &str,
) {
    if raw_data.len() < 2 {
        return;
    }

    let query_id = u16::from_be_bytes([raw_data[0], raw_data[1]]);
    let Some((_, sender)) = pending_queries.remove(&query_id) else {
        return;
    };

    let mut packet_buffer = PacketBuffer::new();
    if packet_buffer.set_data(raw_data).is_err() {
        log_error!(format!(
            "Failed UDP set_data (ID: {query_id}) on {addr_str}"
        ));
        let _ = sender.send(Err(DnsError::Internal(
            "UDP Buffer handling error".to_string(),
        )));
        return;
    }

    let _ = sender.send(Ok(packet_buffer));
}

fn parse_dns_packet(data: &[u8]) -> Result<DnsPacket, DnsError> {
    let mut packet_buffer = PacketBuffer::from_slice(data)
        .map_err(|e| DnsError::Internal(format!("Failed to create PacketBuffer: {e}")))?;
    DnsPacket::from_buffer(&mut packet_buffer)
}

fn format_query_domain(domain: &str, query_type: QueryType) -> Cow<'_, str> {
    if query_type == QueryType::PTR {
        if let Ok(ipv4) = domain.parse::<Ipv4Addr>() {
            return Cow::Owned(crate::network::util::ipv4_to_ptr(ipv4));
        }
        if let Ok(ipv6) = domain.parse::<Ipv6Addr>() {
            return Cow::Owned(crate::network::util::ipv6_to_ptr(&ipv6));
        }
    }
    Cow::Borrowed(domain)
}

fn serialize_query(
    query_id: u16,
    domain: &str,
    query_type: QueryType,
    recursion: bool,
) -> Result<PacketBuffer, DnsError> {
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

    let clean_domain = domain.strip_suffix('.').unwrap_or(domain);
    let formatted_domain = format_query_domain(clean_domain, query_type);

    let mut buffer = PacketBuffer::new();
    buffer
        .write_u16(query_id)
        .map_err(|e| DnsError::Internal(format!("Failed to write query ID: {e}")))?;

    let flags_byte0 = u8::from(recursion);
    buffer
        .write_u8(flags_byte0)
        .map_err(|e| DnsError::Internal(format!("Failed to write header flags: {e}")))?;
    buffer
        .write_u8(0u8)
        .map_err(|e| DnsError::Internal(format!("Failed to write header flags: {e}")))?;

    buffer
        .write_u16(1)
        .map_err(|e| DnsError::Internal(format!("Failed to write question count: {e}")))?;
    buffer
        .write_u16(0)
        .map_err(|e| DnsError::Internal(format!("Failed to write answer count: {e}")))?;
    buffer
        .write_u16(0)
        .map_err(|e| DnsError::Internal(format!("Failed to write auth count: {e}")))?;
    buffer
        .write_u16(0)
        .map_err(|e| DnsError::Internal(format!("Failed to write additional count: {e}")))?;

    buffer
        .write_qname(&formatted_domain)
        .map_err(|e| DnsError::InvalidData(format!("Failed to encode QNAME: {e}")))?;

    buffer
        .write_u16(query_type as u16)
        .map_err(|e| DnsError::Internal(format!("Failed to write QTYPE: {e}")))?;

    buffer
        .write_u16(1)
        .map_err(|e| DnsError::Internal(format!("Failed to write QCLASS: {e}")))?;

    Ok(buffer)
}

async fn io_timeout<F, T>(
    duration: Duration,
    target: SocketAddr,
    action_name: &str,
    future: F,
) -> Result<T, DnsError>
where
    F: Future<Output = std::io::Result<T>>,
{
    match timeout(duration, future).await {
        Ok(Ok(val)) => Ok(val),
        Ok(Err(e)) => Err(DnsError::Network(format!(
            "Failed to {action_name} {target}: {e}"
        ))),
        Err(_) => Err(DnsError::Timeout(target.to_string())),
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
        let pool_size = udp_pool_size.map_or(default_pool_size, |s| s.clamp(1, 16));

        let (shutdown_tx, _) = broadcast::channel(1);
        let mut udp_entries = Vec::with_capacity(pool_size);

        for i in 0..pool_size {
            udp_entries.push(UdpSocketEntry::bind(i, &shutdown_tx).await?);
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
        timeout_duration: Duration,
    ) -> Result<Arc<Mutex<TcpStream>>, DnsError> {
        if let Some(entry) = self.inner.tcp_sockets.get(&target_addr) {
            return Ok(entry.value().clone());
        }

        let tcp_stream = io_timeout(
            timeout_duration,
            target_addr,
            "connect to",
            TcpStream::connect(target_addr),
        )
        .await?;

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
        self.resolve_with_timeout(
            dns_resolver,
            domain,
            query_type,
            protocol,
            recursion,
            DEFAULT_TIMEOUT,
        )
        .await
    }

    pub async fn resolve_with_timeout(
        &self,
        dns_resolver: SocketAddr,
        domain: &str,
        query_type: &QueryType,
        protocol: &TransportProtocol,
        recursion: bool,
        timeout_duration: Duration,
    ) -> Result<DnsPacket, DnsError> {
        match protocol {
            TransportProtocol::UDP => {
                self.resolve_udp(
                    dns_resolver,
                    domain,
                    query_type,
                    recursion,
                    timeout_duration,
                )
                .await
            }
            TransportProtocol::TCP => {
                let query_id = self.inner.next_tcp_query_id.fetch_add(1, Ordering::Relaxed);
                let request_buffer = serialize_query(query_id, domain, *query_type, recursion)?;
                self.resolve_tcp(dns_resolver, query_id, &request_buffer, timeout_duration)
                    .await
            }
        }
    }

    async fn resolve_udp(
        &self,
        dns_resolver: SocketAddr,
        domain: &str,
        query_type: &QueryType,
        recursion: bool,
        timeout_duration: Duration,
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
        let mut guard = PendingQueryGuard::new(query_id, &entry.pending_queries);

        let request_buffer = serialize_query(query_id, domain, *query_type, recursion)?;

        entry
            .socket
            .send_to(request_buffer.get_buffer_to_pos(), dns_resolver)
            .await
            .map_err(|e| {
                DnsError::Network(format!("UDP: Failed to send query to {dns_resolver}: {e}"))
            })?;

        let mut response_buffer = match timeout(timeout_duration, rx).await {
            Ok(Ok(result)) => {
                guard.defuse();
                result?
            }
            Ok(Err(_)) => {
                return Err(DnsError::Internal(
                    "UDP: Resolver receiver task channel closed unexpectedly".to_string(),
                ));
            }
            Err(_) => return Err(DnsError::Timeout(dns_resolver.to_string())),
        };

        let response = DnsPacket::from_buffer(&mut response_buffer)
            .map_err(|e| DnsError::ProtocolData(e.to_string()))?;

        Self::process_dns_result(response)
    }

    async fn resolve_tcp(
        &self,
        dns_resolver: SocketAddr,
        query_id: u16,
        request_buffer: &PacketBuffer,
        timeout_duration: Duration,
    ) -> Result<DnsPacket, DnsError> {
        let tcp_connection_mutex = self
            .get_or_create_tcp_connection(dns_resolver, timeout_duration)
            .await?;
        let mut tcp_stream = tcp_connection_mutex.lock().await;

        let result = Self::exchange_tcp(
            &mut tcp_stream,
            dns_resolver,
            query_id,
            request_buffer,
            timeout_duration,
        )
        .await;
        drop(tcp_stream);

        if result.is_err() {
            self.inner.tcp_sockets.remove(&dns_resolver);
        }

        result
    }

    async fn exchange_tcp(
        stream: &mut TcpStream,
        dns_resolver: SocketAddr,
        query_id: u16,
        request_buffer: &PacketBuffer,
        timeout_duration: Duration,
    ) -> Result<DnsPacket, DnsError> {
        let request_bytes = request_buffer.get_buffer_to_pos();

        let query_len = u16::try_from(request_bytes.len()).map_err(|_| {
            DnsError::InvalidData("TCP: Query data length exceeds 65535 bytes".to_string())
        })?;
        if query_len == 0 {
            return Err(DnsError::InvalidData(
                "TCP: Serialized query data is empty".to_string(),
            ));
        }

        let mut framed_request = [0u8; 2 + 512];
        let total_len = 2 + request_bytes.len();
        if total_len > framed_request.len() {
            return Err(DnsError::InvalidData(
                "TCP: Query exceeds maximum buffer size".to_string(),
            ));
        }
        framed_request[..2].copy_from_slice(&query_len.to_be_bytes());
        framed_request[2..total_len].copy_from_slice(request_bytes);

        io_timeout(
            timeout_duration,
            dns_resolver,
            "write request to",
            stream.write_all(&framed_request[..total_len]),
        )
        .await?;

        let mut response_len_buf = [0u8; 2];
        io_timeout(
            timeout_duration,
            dns_resolver,
            "read response length from",
            stream.read_exact(&mut response_len_buf),
        )
        .await?;

        let response_len = usize::from(u16::from_be_bytes(response_len_buf));
        if response_len == 0 {
            return Err(DnsError::InvalidData(
                "TCP: Received zero length response".to_string(),
            ));
        }
        if response_len > TCP_BUFFER_SIZE {
            return Err(DnsError::InvalidData(format!(
                "TCP: Response length too large: {response_len} bytes (max: {TCP_BUFFER_SIZE})"
            )));
        }

        let mut response_body = vec![0u8; response_len];
        io_timeout(
            timeout_duration,
            dns_resolver,
            "read response from",
            stream.read_exact(&mut response_body),
        )
        .await?;

        let response_packet = parse_dns_packet(&response_body)?;
        if response_packet.header.id != query_id {
            return Err(DnsError::InvalidData(format!(
                "DNS: Response ID {} does not match query ID {query_id}",
                response_packet.header.id
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

    pub fn shutdown(&self) {
        let _ = self.inner.shutdown_tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{DnsQuestion, RData, ResourceRecord};

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

    #[tokio::test]
    async fn test_resolve_with_timeout_times_out() {
        let non_responding_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let non_responding_addr = non_responding_socket.local_addr().unwrap();

        let resolver = AsyncResolver::new(Some(1)).await.unwrap();
        let start = std::time::Instant::now();
        let short_timeout = Duration::from_millis(40);

        let res = resolver
            .resolve_with_timeout(
                non_responding_addr,
                "timeout.test",
                &QueryType::A,
                &TransportProtocol::UDP,
                true,
                short_timeout,
            )
            .await;

        let elapsed = start.elapsed();
        assert!(matches!(res, Err(DnsError::Timeout(_))));
        assert!(elapsed < Duration::from_millis(500));
    }

    #[tokio::test]
    async fn test_resolve_with_timeout_succeeds() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((len, src)) = mock_socket.recv_from(&mut buf).await
                && len >= 12
            {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let mut response = DnsPacket::new();
                response.header.id = id;
                response.header.response = true;
                response.header.rescode = ResultCode::NOERROR;
                response.answers.push(ResourceRecord {
                    name: "fast.test".to_string(),
                    class: 1,
                    ttl: 300,
                    data: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
                });
                let mut pb = PacketBuffer::new();
                if response.write(&mut pb).is_ok() {
                    let _ = mock_socket.send_to(pb.get_buffer_to_pos(), src).await;
                }
            }
        });

        let resolver = AsyncResolver::new(Some(1)).await.unwrap();
        let res = resolver
            .resolve_with_timeout(
                mock_addr,
                "fast.test",
                &QueryType::A,
                &TransportProtocol::UDP,
                true,
                Duration::from_millis(500),
            )
            .await;

        server_task.abort();
        assert!(res.is_ok());
    }

    #[test]
    fn test_format_query_domain() {
        assert_eq!(
            format_query_domain("example.com", QueryType::A),
            "example.com"
        );
        assert_eq!(
            format_query_domain("192.0.2.1", QueryType::PTR),
            "1.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            format_query_domain("2001:db8::1", QueryType::PTR),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert_eq!(
            format_query_domain("not-an-ip", QueryType::PTR),
            "not-an-ip"
        );
    }

    #[test]
    fn test_serialize_query_direct_wire_format() {
        assert!(serialize_query(1, "", QueryType::A, true).is_err());
        let long_domain = "a".repeat(254);
        assert!(serialize_query(1, &long_domain, QueryType::A, true).is_err());

        // Test normal domain
        let mut valid_query_buffer =
            serialize_query(42, "example.com", QueryType::A, true).unwrap();
        valid_query_buffer.set_pos(0).unwrap();
        let packet = DnsPacket::from_buffer(&mut valid_query_buffer).unwrap();
        assert_eq!(packet.header.id, 42);
        assert!(packet.header.recursion_desired);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "example.com");
        assert_eq!(packet.questions[0].qtype, QueryType::A);
        assert_eq!(packet.questions[0].qclass, 1);

        // Test trailing dot
        let mut trailing_dot_buffer =
            serialize_query(43, "example.com.", QueryType::A, false).unwrap();
        trailing_dot_buffer.set_pos(0).unwrap();
        let packet_trailing = DnsPacket::from_buffer(&mut trailing_dot_buffer).unwrap();
        assert_eq!(packet_trailing.header.id, 43);
        assert!(!packet_trailing.header.recursion_desired);
        assert_eq!(packet_trailing.questions.len(), 1);
        assert_eq!(packet_trailing.questions[0].name, "example.com");

        // Test 63-byte label boundary (valid)
        let label_63 = "a".repeat(63);
        let domain_63 = format!("{label_63}.com");
        assert!(serialize_query(44, &domain_63, QueryType::A, true).is_ok());

        // Test 64-byte label boundary (rejected)
        let label_64 = "a".repeat(64);
        let domain_64 = format!("{label_64}.com");
        assert!(serialize_query(45, &domain_64, QueryType::A, true).is_err());
    }

    #[test]
    fn test_udp_socket_entry_alignment() {
        use std::mem::align_of;
        assert_eq!(align_of::<UdpSocketEntry>(), 64);
    }

    #[test]
    fn test_dispatch_udp_response_short_packet() {
        let pending = DashMap::new();
        // Packets shorter than 2 bytes should be discarded without panicking
        dispatch_udp_response(&[0], &pending, "127.0.0.1:53");
        assert!(pending.is_empty());
    }
}
