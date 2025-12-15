use rand::Rng;
use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::time;

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
}

pub struct QueryFailure {
    pub resolver: Ipv4Addr,
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
                    let primary = iter.next().cloned().unwrap_or(QueryType::A);
                    let follow_ups = iter.cloned().collect();
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
                            follow_ups.push(query_type.clone());
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
        }
    }

    #[must_use]
    pub fn total_queries(&self) -> u64 {
        self.query_counter.load(Ordering::Relaxed)
    }

    async fn apply_delay(&self) {
        if let Some(delay) = &self.delay {
            let millis = delay.get_delay();
            if millis > 0 {
                time::sleep(Duration::from_millis(millis)).await;
            }
        }
    }

    pub async fn execute_query(
        &self,
        fqdn: &str,
        query_type: QueryType,
        first_query: &mut bool,
    ) -> Result<(Ipv4Addr, DnsPacket), QueryFailure> {
        let should_wait = !*first_query;
        if *first_query {
            *first_query = false;
        }
        if should_wait {
            self.apply_delay().await;
        }
        self.perform_query(fqdn, query_type).await
    }

    async fn perform_query(
        &self,
        fqdn: &str,
        query_type: QueryType,
    ) -> Result<(Ipv4Addr, DnsPacket), QueryFailure> {
        // Lock-free resolver selection
        let resolver = self
            .resolver_pool
            .select()
            .unwrap_or(resolver_selector::DEFAULT_RESOLVER);

        let result = self
            .pool
            .resolve(
                &resolver,
                fqdn,
                &query_type,
                &self.transport,
                self.recursion,
            )
            .await;

        self.query_counter.fetch_add(1, Ordering::Relaxed);

        match &result {
            Ok(packet) => {
                if let Some(delay) = &self.delay {
                    let has_answers = !packet.answers.is_empty();
                    delay.report_query_result(has_answers);
                }
            }
            Err(error) => {
                if let Some(delay) = &self.delay {
                    let treat_as_failure = matches!(
                        error,
                        DnsError::Network(_)
                            | DnsError::Timeout(_)
                            | DnsError::Nameserver(_)
                            | DnsError::InvalidData(_)
                            | DnsError::ProtocolData(_)
                            | DnsError::Internal(_)
                    );
                    delay.report_query_result(!treat_as_failure);
                }
                // Disable failing resolver (lock-free operation)
                if matches!(error, DnsError::Network(_) | DnsError::Timeout(_)) {
                    let disable_for = Duration::from_secs(rand::rng().random_range(2..=30));
                    self.resolver_pool.disable(resolver, disable_for);
                }
            }
        }

        result
            .map(|packet| (resolver, packet))
            .map_err(|error| QueryFailure { resolver, error })
    }
}
