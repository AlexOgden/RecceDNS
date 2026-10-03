use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    dns::{
        async_resolver::AsyncResolver,
        error::DnsError,
        protocol::{DnsPacket, QueryType},
        resolver_selector::{self, ResolverPool},
    },
    network::types::TransportProtocol,
    timing::delay,
};

#[derive(Clone)]
pub struct QueryPlan {
    pub primary: QueryType,
    pub follow_ups: Vec<QueryType>,
    pub gate_followups_on_primary_hit: bool,
}

#[derive(Clone)]
pub struct LookupContext {
    pool: AsyncResolver,
    resolver_pool: Arc<ResolverPool>,
    transport: TransportProtocol,
    delay: Option<delay::Delay>,
    pub query_plan: QueryPlan,
    recursion: bool,
    query_counter: Arc<AtomicU64>,
    pub max_retries: usize,
}

#[derive(Debug)]
pub struct QueryFailure {
    pub resolver: SocketAddr,
    pub error: DnsError,
}

impl QueryPlan {
    #[must_use]
    pub fn new(query_types: &[QueryType]) -> Self {
        if query_types.is_empty() {
            return Self {
                primary: QueryType::A,
                follow_ups: Vec::new(),
                gate_followups_on_primary_hit: false,
            };
        }

        query_types
            .iter()
            .position(|t| *t == QueryType::A)
            .map_or_else(
                || {
                    let mut iter = query_types.iter();
                    let primary = iter.next().copied().unwrap_or(QueryType::A);
                    let follow_ups = iter.copied().collect();
                    Self {
                        primary,
                        follow_ups,
                        gate_followups_on_primary_hit: false,
                    }
                },
                |pos| {
                    let mut follow_ups = Vec::new();
                    for (idx, query_type) in query_types.iter().enumerate() {
                        if idx != pos {
                            follow_ups.push(*query_type);
                        }
                    }
                    Self {
                        primary: QueryType::A,
                        follow_ups,
                        gate_followups_on_primary_hit: true,
                    }
                },
            )
    }
}

impl LookupContext {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        pool: AsyncResolver,
        resolver_pool: Arc<ResolverPool>,
        transport: TransportProtocol,
        delay: Option<delay::Delay>,
        query_plan: QueryPlan,
        recursion: bool,
    ) -> Self {
        Self {
            pool,
            resolver_pool,
            transport,
            delay,
            query_plan,
            recursion,
            query_counter: Arc::new(AtomicU64::new(0)),
            max_retries: 1,
        }
    }

    #[must_use]
    pub const fn with_retries(mut self, retries: usize) -> Self {
        self.max_retries = retries;
        self
    }

    #[must_use]
    pub fn total_queries(&self) -> u64 {
        self.query_counter.load(Ordering::Relaxed)
    }

    pub async fn execute_query(
        &self,
        fqdn: &str,
        query_type: QueryType,
    ) -> Result<(SocketAddr, DnsPacket), QueryFailure> {
        self.perform_query(fqdn, query_type).await
    }

    async fn perform_query(
        &self,
        fqdn: &str,
        query_type: QueryType,
    ) -> Result<(SocketAddr, DnsPacket), QueryFailure> {
        let mut tried_stack = [resolver_selector::DEFAULT_RESOLVER; 4];
        let mut tried_count = 0;
        let mut tried_heap: Option<Vec<SocketAddr>> = None;
        let mut last_failure = None;

        for attempt in 0..=self.max_retries {
            let resolver = if attempt == 0 {
                self.resolver_pool
                    .select()
                    .unwrap_or(resolver_selector::DEFAULT_RESOLVER)
            } else {
                let excluded = tried_heap
                    .as_ref()
                    .map_or_else(|| &tried_stack[..tried_count], Vec::as_slice);
                self.resolver_pool
                    .select_excluding(excluded)
                    .unwrap_or_else(|| {
                        self.resolver_pool
                            .select()
                            .unwrap_or(resolver_selector::DEFAULT_RESOLVER)
                    })
            };

            if tried_count < tried_stack.len() && tried_heap.is_none() {
                tried_stack[tried_count] = resolver;
                tried_count += 1;
            } else {
                let heap = tried_heap.get_or_insert_with(|| {
                    let mut v = Vec::with_capacity(self.max_retries + 1);
                    v.extend_from_slice(&tried_stack[..tried_count]);
                    v
                });
                heap.push(resolver);
            }

            // Item 5: Per-resolver in-flight caps (bounded concurrency, avoids bursts and drops)
            let permit = self.resolver_pool.acquire_permit(resolver).await;

            // Item 5: Per-resolver throttling / pacing
            if let Some(delay) = &self.delay {
                let millis = delay.get_delay();
                if millis > 0 {
                    self.resolver_pool
                        .pace_resolver(resolver, Duration::from_millis(millis))
                        .await;
                }
            }

            // Item 7: Adaptive/tuned RTO based on EWMA latency
            let base_rto = self.resolver_pool.rto(resolver);
            let rto = if attempt == 0 {
                base_rto
            } else {
                (base_rto.saturating_mul(3) / 2).min(Duration::from_millis(1500))
            };

            let start = Instant::now();
            let result = self
                .pool
                .resolve_with_timeout(
                    resolver,
                    fqdn,
                    &query_type,
                    &self.transport,
                    self.recursion,
                    rto,
                )
                .await;
            let latency = start.elapsed();

            drop(permit);
            self.query_counter.fetch_add(1, Ordering::Relaxed);

            match result {
                Ok(packet) => {
                    self.resolver_pool
                        .record_success_with_latency(resolver, latency);
                    if let Some(delay) = &self.delay {
                        delay.report_query_result(true);
                    }
                    return Ok((resolver, packet));
                }
                Err(error) => {
                    let is_resolver_failure = match &error {
                        DnsError::Network(_) | DnsError::Timeout(_) => true,
                        DnsError::Nameserver(msg) => {
                            msg.contains("SERVFAIL") || msg.contains("REFUSED")
                        }
                        _ => false,
                    };

                    if is_resolver_failure {
                        self.resolver_pool.record_failure(resolver);
                    }

                    if let Some(delay) = &self.delay {
                        delay.report_query_result(!is_resolver_failure);
                    }

                    let retryable = is_resolver_failure && attempt < self.max_retries;
                    last_failure = Some(QueryFailure { resolver, error });

                    if !retryable {
                        break;
                    }
                }
            }
        }

        Err(last_failure.unwrap_or_else(|| QueryFailure {
            resolver: resolver_selector::DEFAULT_RESOLVER,
            error: DnsError::Internal("No queries attempted".to_string()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{DnsQuestion, RData, ResourceRecord, ResultCode};
    use crate::io::packet_buffer::PacketBuffer;
    use std::net::Ipv4Addr;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_in_query_retry_alternate_resolver() {
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr1 = s1.local_addr().unwrap();

        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr2 = s2.local_addr().unwrap();

        let s2_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((len, src)) = s2.recv_from(&mut buf).await
                && len >= 12
            {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let mut response = DnsPacket::new();
                response.header.id = id;
                response.header.response = true;
                response.header.rescode = ResultCode::NOERROR;
                response
                    .questions
                    .push(DnsQuestion::new("retry.test".to_string(), QueryType::A));
                response.answers.push(ResourceRecord {
                    name: "retry.test".to_string(),
                    class: 1,
                    ttl: 300,
                    data: RData::A(Ipv4Addr::new(10, 0, 0, 1)),
                });
                let mut pb = PacketBuffer::new();
                if response.write(&mut pb).is_ok() {
                    let _ = s2.send_to(pb.get_buffer_to_pos(), src).await;
                }
            }
        });

        let resolver_pool = Arc::new(ResolverPool::new(vec![addr1, addr2], false));
        resolver_pool.record_success_with_latency(addr1, Duration::from_millis(5));

        let pool = AsyncResolver::new(Some(1)).await.unwrap();
        let query_plan = QueryPlan::new(&[QueryType::A]);
        let ctx = LookupContext::new(
            pool,
            resolver_pool.clone(),
            TransportProtocol::UDP,
            None,
            query_plan,
            true,
        );

        let result = ctx.execute_query("retry.test", QueryType::A).await;
        s2_task.abort();

        assert!(result.is_ok(), "Retry should succeed with addr2");
        let (resolved_addr, packet) = result.unwrap();
        assert_eq!(resolved_addr, addr2);
        assert_eq!(packet.answers.len(), 1);
    }

    #[tokio::test]
    async fn test_no_retry_when_disabled() {
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr1 = s1.local_addr().unwrap();

        let resolver_pool = Arc::new(ResolverPool::new(vec![addr1], false));
        resolver_pool.record_success_with_latency(addr1, Duration::from_millis(5));

        let pool = AsyncResolver::new(Some(1)).await.unwrap();
        let query_plan = QueryPlan::new(&[QueryType::A]);
        let ctx = LookupContext::new(
            pool,
            resolver_pool,
            TransportProtocol::UDP,
            None,
            query_plan,
            true,
        )
        .with_retries(0);

        let result = ctx.execute_query("fail.test", QueryType::A).await;
        assert!(result.is_err());
        assert_eq!(ctx.total_queries(), 1);
    }
}
