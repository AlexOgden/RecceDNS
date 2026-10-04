use std::{
    collections::HashSet,
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, ensure};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngExt;
use rand::distr::Alphanumeric;
use tokio::task::JoinSet;

use crate::dns::async_resolver::AsyncResolver;
use crate::dns::protocol::QueryType;
use crate::io::validation::parse_ipv4_with_port;
use crate::network::types::TransportProtocol;

const ROOT_SERVER: &str = "root-servers.net";

/// Max resolvers probed at once (each probe sends 2 queries).
/// Bounds open sockets/TCP connections and in-flight query IDs.
const MAX_CONCURRENT_CHECKS: usize = 256;

/// Spinner tick characters for the progress bar.
const PROGRESS_TICK_CHARS: &str = "/|\\- ";

/// Outcome of probing a single DNS resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    Ok,
    Hijacking,
    NoResponse,
}

/// Statistics collected during DNS resolver health checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResolverCheckStats {
    pub total: usize,
    pub working: usize,
    pub failed: usize,
    pub hijacked: usize,
    pub no_response: usize,
    pub duration: Duration,
}

impl ResolverCheckStats {
    #[must_use]
    pub const fn new(total: usize) -> Self {
        Self {
            total,
            working: 0,
            failed: 0,
            hijacked: 0,
            no_response: 0,
            duration: Duration::ZERO,
        }
    }

    pub const fn record(&mut self, outcome: CheckOutcome) {
        match outcome {
            CheckOutcome::Ok => self.working += 1,
            CheckOutcome::Hijacking => {
                self.failed += 1;
                self.hijacked += 1;
            }
            CheckOutcome::NoResponse => {
                self.failed += 1;
                self.no_response += 1;
            }
        }
    }

    /// Calculates operational resolver percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Total resolver count fits comfortably within 53-bit mantissa.
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.working as f64 / self.total as f64) * 100.0
        }
    }

    /// Formats a concise colored breakdown of failure reasons.
    #[must_use]
    pub fn format_failure_details(&self) -> String {
        match (self.no_response, self.hijacked) {
            (nr, hj) if nr > 0 && hj > 0 => format!(
                "{} no response, {} NXDOMAIN hijacking",
                nr.to_string().yellow().bold(),
                hj.to_string().yellow().bold()
            ),
            (nr, 0) if nr > 0 => format!("{} no response", nr.to_string().yellow().bold()),
            (0, hj) if hj > 0 => format!("{} NXDOMAIN hijacking", hj.to_string().yellow().bold()),
            _ => "unknown error".to_string(),
        }
    }

    /// Prints a concise, colored summary of resolver check results.
    pub fn print_summary(&self) {
        if self.total == 0 {
            return;
        }

        if self.failed == 0 {
            if self.total == 1 {
                crate::log_success!(format!(
                    "DNS Resolver: {} in {:.2?}",
                    "operational".green().bold(),
                    self.duration
                ));
            } else {
                crate::log_success!(format!(
                    "DNS Resolvers: all {} operational in {:.2?}",
                    self.working.to_string().green().bold(),
                    self.duration
                ));
            }
        } else if self.working > 0 {
            crate::log_info!(format!(
                "DNS Resolvers: {}/{} operational ({:.1}%) in {:.2?}",
                self.working.to_string().green().bold(),
                self.total.to_string().bold(),
                self.success_rate(),
                self.duration
            ));
            let failure_details = self.format_failure_details();
            let resolver_word = if self.failed == 1 {
                "resolver"
            } else {
                "resolvers"
            };
            crate::log_warn!(format!(
                "Removed {} non-working {resolver_word}: {failure_details}",
                self.failed.to_string().red().bold()
            ));
        } else {
            crate::log_warn!(format!(
                "DNS Resolvers: {}/{} operational in {:.2?}",
                "0".red().bold(),
                self.total.to_string().bold(),
                self.duration
            ));
            let failure_details = self.format_failure_details();
            crate::log_error!(format!("All resolvers failed: {failure_details}"));
        }
    }
}

/// Strips comments (`#` or `//`) from a string slice without heap allocations.
#[must_use]
pub fn strip_comment(s: &str) -> &str {
    let without_hash = s.find('#').map_or(s, |idx| &s[..idx]);
    without_hash
        .find("//")
        .map_or(without_hash, |idx| &without_hash[..idx])
}

/// Parses a comma-separated list of resolver strings into trimmed, non-empty elements,
/// ignoring comments starting with `#` or `//` (both full-line and inline).
#[must_use]
pub fn parse_resolver_list(input: &str) -> Vec<String> {
    input
        .lines()
        .flat_map(|line| {
            line.split(',')
                .map(strip_comment)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .collect()
}

/// Parses resolver entries directly into `SocketAddr`s without intermediate `String` allocations.
/// Handles multi-line input, comma-separated entries, comments (`#` or `//`), and whitespace.
pub fn parse_resolvers_str(input: &str) -> Result<Vec<SocketAddr>> {
    let mut resolvers = Vec::new();
    for line in input.lines() {
        for entry in line.split(',') {
            let entry = strip_comment(entry).trim();
            if entry.is_empty() {
                continue;
            }
            resolvers.push(parse_ipv4_with_port(entry)?);
        }
    }
    Ok(resolvers)
}

/// Loads resolver entries from a file and parses them directly into `SocketAddr`s.
pub fn load_resolvers_from_file(path: &str) -> Result<Vec<SocketAddr>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read DNS resolvers file '{path}': {e}"))?;
    parse_resolvers_str(&content)
}

/// Removes duplicate resolvers in place, keeping the first occurrence of each.
/// Comparison is on the parsed socket address, so `8.8.8.8` and `8.8.8.8:53` are duplicates.
/// Returns the number of duplicates removed.
pub fn dedup_resolvers(resolvers: &mut Vec<SocketAddr>) -> usize {
    let original_len = resolvers.len();
    let mut seen = HashSet::with_capacity(original_len);
    resolvers.retain(|addr| seen.insert(*addr));
    original_len - resolvers.len()
}

/// Loads and parses DNS resolvers from a file path or comma-separated string,
/// parses each address with an optional port, and deduplicates the list in-place.
pub fn load_resolvers(input: &str) -> Result<Vec<SocketAddr>> {
    let input = input.trim();
    let mut resolvers = if Path::new(input).exists() {
        load_resolvers_from_file(input)?
    } else {
        parse_resolvers_str(input)?
    };

    let duplicates = dedup_resolvers(&mut resolvers);
    if duplicates > 0 {
        crate::log_info!(format!(
            "Removed {duplicates} duplicate DNS resolver(s), {} remaining",
            resolvers.len()
        ));
    }

    Ok(resolvers)
}

fn generate_random_domain() -> String {
    let random_string: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    format!("{random_string}.example.com")
}

async fn check_nxdomain_hijacking(
    resolver_pool: &AsyncResolver,
    server_address: SocketAddr,
    transport_protocol: &TransportProtocol,
) -> bool {
    let random_domain = generate_random_domain();
    resolver_pool
        .resolve(
            server_address,
            &random_domain,
            &QueryType::A,
            transport_protocol,
            true,
        )
        .await
        .is_ok()
}

/// Runs the hijack probe and the liveness probe for a single resolver concurrently.
async fn check_resolver(
    resolver_pool: &AsyncResolver,
    server: SocketAddr,
    transport_protocol: &TransportProtocol,
) -> CheckOutcome {
    let root_server_letter = rand::rng().random_range(b'a'..=b'm') as char;
    let domain = format!("{root_server_letter}.{ROOT_SERVER}");

    let (hijacking, normal_query) = tokio::join!(
        check_nxdomain_hijacking(resolver_pool, server, transport_protocol),
        resolver_pool.resolve(server, &domain, &QueryType::A, transport_protocol, true),
    );

    if hijacking {
        CheckOutcome::Hijacking
    } else if normal_query.is_err() {
        CheckOutcome::NoResponse
    } else {
        CheckOutcome::Ok
    }
}

/// Configures a progress bar styled specifically for DNS resolver checks.
#[allow(clippy::literal_string_with_formatting_args)] // Template placeholders are indicatif syntax, not std::fmt formatting args.
fn create_resolver_progress_bar(total: usize) -> ProgressBar {
    let pb_len = u64::try_from(total).unwrap_or(u64::MAX);
    let pb = ProgressBar::new(pb_len);
    let style = ProgressStyle::default_bar()
        .template("[{spinner:.cyan}] [{pos}/{len}] {wide_msg} [{bar:30.cyan/blue}] ETA {eta:.bold}")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("##-")
        .tick_chars(PROGRESS_TICK_CHARS);
    pb.set_style(style);
    pb.set_message("Checking DNS resolvers...".to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

/// Checks all resolvers concurrently, displaying an active progress bar, and returns
/// the operational resolvers along with the check statistics.
pub async fn check_dns_resolvers_with_stats(
    dns_resolvers: &[SocketAddr],
    transport_protocol: &TransportProtocol,
) -> (Vec<SocketAddr>, ResolverCheckStats) {
    if dns_resolvers.is_empty() {
        return (Vec::new(), ResolverCheckStats::default());
    }

    let resolver_pool = match AsyncResolver::new(None).await {
        Ok(pool) => pool,
        Err(e) => {
            crate::log_error!(format!(
                "Failed to create DNS resolver for health check: {e}"
            ));
            return (Vec::new(), ResolverCheckStats::default());
        }
    };

    let total = dns_resolvers.len();
    let pb = create_resolver_progress_bar(total);

    let start_time = Instant::now();
    let mut tasks = JoinSet::new();
    let mut iter = dns_resolvers.iter().copied().enumerate();

    let initial_batch = MAX_CONCURRENT_CHECKS.min(total);
    for _ in 0..initial_batch {
        if let Some((index, server)) = iter.next() {
            let pool = resolver_pool.clone();
            let proto = transport_protocol.clone();
            tasks.spawn(async move {
                let outcome = check_resolver(&pool, server, &proto).await;
                (index, server, outcome)
            });
        }
    }

    let mut outcomes: Vec<Option<CheckOutcome>> = vec![None; total];
    let mut stats = ResolverCheckStats::new(total);

    while let Some(joined) = tasks.join_next().await {
        let outcome = match joined {
            Ok((index, _server, outcome)) => {
                outcomes[index] = Some(outcome);
                outcome
            }
            Err(_) => CheckOutcome::NoResponse,
        };

        stats.record(outcome);

        let label = if total == 1 { "resolver" } else { "resolvers" };
        pb.set_message(format!(
            "Checking {label} ({} operational, {} failed)",
            stats.working.to_string().green(),
            stats.failed.to_string().red()
        ));
        pb.inc(1);

        if let Some((index, server)) = iter.next() {
            let pool = resolver_pool.clone();
            let proto = transport_protocol.clone();
            tasks.spawn(async move {
                let outcome = check_resolver(&pool, server, &proto).await;
                (index, server, outcome)
            });
        }
    }

    resolver_pool.shutdown();
    stats.duration = start_time.elapsed();
    pb.finish_and_clear();

    let working_resolvers = dns_resolvers
        .iter()
        .zip(outcomes)
        .filter_map(|(&server, outcome)| {
            matches!(outcome, Some(CheckOutcome::Ok)).then_some(server)
        })
        .collect();

    (working_resolvers, stats)
}

/// Checks all resolvers concurrently with a progress bar, reports stats to stdout,
/// and returns the working resolvers in their original order.
pub async fn check_dns_resolvers(
    dns_resolvers: &[SocketAddr],
    transport_protocol: &TransportProtocol,
) -> Vec<SocketAddr> {
    let (working, stats) = check_dns_resolvers_with_stats(dns_resolvers, transport_protocol).await;
    stats.print_summary();
    println!();
    working
}

/// Filters working resolvers, skipping the health check if `no_dns_check` is true.
pub async fn filter_working_resolvers(
    no_dns_check: bool,
    transport_protocol: &TransportProtocol,
    dns_resolvers: &[SocketAddr],
) -> Vec<SocketAddr> {
    if no_dns_check || dns_resolvers.is_empty() {
        return dns_resolvers.to_vec();
    }

    check_dns_resolvers(dns_resolvers, transport_protocol).await
}

/// Full initialization pipeline for DNS resolvers:
/// loads from file or comma-separated string, parses and deduplicates,
/// checks resolvers concurrently (unless `no_dns_check` is true), reports stats,
/// and ensures at least one working resolver is available.
pub async fn initialize_resolvers(
    dns_resolvers_arg: &str,
    no_dns_check: bool,
    transport_protocol: &TransportProtocol,
) -> Result<Vec<SocketAddr>> {
    let resolvers = load_resolvers(dns_resolvers_arg)?;
    ensure!(
        !resolvers.is_empty(),
        "No DNS resolvers provided! At least one resolver must be specified."
    );

    let working_resolvers =
        filter_working_resolvers(no_dns_check, transport_protocol, &resolvers).await;

    ensure!(
        !working_resolvers.is_empty(),
        "No working DNS resolvers found! At least one resolver must be operational."
    );

    Ok(working_resolvers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn make_addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            port,
        ))
    }

    #[test]
    fn test_parse_resolver_list_basic() {
        let list = parse_resolver_list("1.1.1.1, 8.8.8.8 , 9.9.9.9");
        assert_eq!(list, vec!["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    }

    #[test]
    fn test_parse_resolver_list_empty_and_spaces() {
        let list = parse_resolver_list(" , 1.1.1.1, , , 8.8.8.8, ");
        assert_eq!(list, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn test_parse_resolver_list_ignores_comments() {
        let list = parse_resolver_list("# comment, 1.1.1.1, // other, 8.8.8.8");
        assert_eq!(list, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn test_parse_resolvers_str_with_comments_and_ports() {
        let input = "
            # Primary resolvers
            1.1.1.1:53, 8.8.8.8:853
            // Secondary
            9.9.9.9
            # Trailing comment
        ";
        let parsed = parse_resolvers_str(input).unwrap();
        assert_eq!(
            parsed,
            vec![
                make_addr([1, 1, 1, 1], 53),
                make_addr([8, 8, 8, 8], 853),
                make_addr([9, 9, 9, 9], 53),
            ]
        );
    }

    #[test]
    fn test_load_resolvers_from_file_with_comments() {
        let tmp = std::env::temp_dir().join(format!("reccedns_test_{}.txt", rand::random::<u32>()));
        std::fs::write(&tmp, "# Test resolvers\n1.1.1.1\n\n8.8.8.8:5353\n// done\n").unwrap();
        let loaded = load_resolvers_from_file(tmp.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(
            loaded,
            vec![make_addr([1, 1, 1, 1], 53), make_addr([8, 8, 8, 8], 5353),]
        );
    }

    #[test]
    fn test_dedup_resolvers() {
        let mut resolvers = vec![
            make_addr([1, 1, 1, 1], 53),
            make_addr([8, 8, 8, 8], 53),
            make_addr([1, 1, 1, 1], 53),
            make_addr([9, 9, 9, 9], 53),
            make_addr([8, 8, 8, 8], 53),
        ];
        let removed = dedup_resolvers(&mut resolvers);
        assert_eq!(removed, 2);
        assert_eq!(
            resolvers,
            vec![
                make_addr([1, 1, 1, 1], 53),
                make_addr([8, 8, 8, 8], 53),
                make_addr([9, 9, 9, 9], 53),
            ]
        );
    }

    #[test]
    fn test_stats_all_ok() {
        let mut stats = ResolverCheckStats::new(3);
        stats.record(CheckOutcome::Ok);
        stats.record(CheckOutcome::Ok);
        stats.record(CheckOutcome::Ok);

        assert_eq!(stats.working, 3);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.hijacked, 0);
        assert_eq!(stats.no_response, 0);
        assert!((stats.success_rate() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_stats_mixed() {
        let mut stats = ResolverCheckStats::new(4);
        stats.record(CheckOutcome::Ok);
        stats.record(CheckOutcome::Hijacking);
        stats.record(CheckOutcome::NoResponse);
        stats.record(CheckOutcome::Ok);

        assert_eq!(stats.working, 2);
        assert_eq!(stats.failed, 2);
        assert_eq!(stats.hijacked, 1);
        assert_eq!(stats.no_response, 1);
        assert!((stats.success_rate() - 50.0).abs() < f64::EPSILON);
        assert_eq!(
            stats.format_failure_details(),
            format!(
                "{} no response, {} NXDOMAIN hijacking",
                "1".yellow().bold(),
                "1".yellow().bold()
            )
        );
    }

    #[test]
    fn test_stats_only_no_response() {
        let mut stats = ResolverCheckStats::new(2);
        stats.record(CheckOutcome::NoResponse);
        stats.record(CheckOutcome::NoResponse);

        assert_eq!(stats.working, 0);
        assert_eq!(stats.failed, 2);
        assert_eq!(stats.no_response, 2);
        assert_eq!(stats.hijacked, 0);
        assert!((stats.success_rate() - 0.0).abs() < f64::EPSILON);
        assert_eq!(
            stats.format_failure_details(),
            format!("{} no response", "2".yellow().bold())
        );
    }

    #[test]
    fn test_stats_only_hijacking() {
        let mut stats = ResolverCheckStats::new(1);
        stats.record(CheckOutcome::Hijacking);

        assert_eq!(stats.working, 0);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.no_response, 0);
        assert_eq!(stats.hijacked, 1);
        assert_eq!(
            stats.format_failure_details(),
            format!("{} NXDOMAIN hijacking", "1".yellow().bold())
        );
    }

    #[test]
    fn test_load_resolvers_from_string() {
        let res = load_resolvers("1.1.1.1:53, 8.8.8.8, 1.1.1.1:53").unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0], make_addr([1, 1, 1, 1], 53));
        assert_eq!(res[1], make_addr([8, 8, 8, 8], 53));
    }

    #[test]
    fn test_stats_print_summary_does_not_panic() {
        let mut stats = ResolverCheckStats::new(3);
        stats.duration = Duration::from_millis(150);
        stats.print_summary(); // total with 0 recorded (failed=0, working=0)

        stats.record(CheckOutcome::Ok);
        stats.record(CheckOutcome::Ok);
        stats.record(CheckOutcome::Ok);
        stats.print_summary(); // all ok

        let mut single = ResolverCheckStats::new(1);
        single.duration = Duration::from_millis(20);
        single.record(CheckOutcome::Ok);
        single.print_summary(); // single ok

        let mut mixed = ResolverCheckStats::new(2);
        mixed.duration = Duration::from_millis(200);
        mixed.record(CheckOutcome::Ok);
        mixed.record(CheckOutcome::NoResponse);
        mixed.print_summary(); // mixed

        let mut all_failed = ResolverCheckStats::new(1);
        all_failed.duration = Duration::from_millis(50);
        all_failed.record(CheckOutcome::Hijacking);
        all_failed.print_summary(); // all failed

        let empty = ResolverCheckStats::new(0);
        empty.print_summary(); // empty
    }

    #[test]
    fn test_format_failure_details_unknown_when_zero() {
        let stats = ResolverCheckStats::new(0);
        assert_eq!(stats.format_failure_details(), "unknown error");
    }

    #[test]
    fn test_strip_comment() {
        assert_eq!(strip_comment("1.1.1.1 # Cloudflare"), "1.1.1.1 ");
        assert_eq!(strip_comment("8.8.8.8 // Google"), "8.8.8.8 ");
        assert_eq!(strip_comment("9.9.9.9"), "9.9.9.9");
        assert_eq!(strip_comment("# whole comment"), "");
        assert_eq!(strip_comment("// whole comment"), "");
    }

    #[test]
    fn test_parse_resolver_list_inline_comments() {
        let input = "1.1.1.1 # Cloudflare, 8.8.8.8 // Google, 9.9.9.9";
        let parsed = parse_resolver_list(input);
        assert_eq!(parsed, vec!["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    }

    #[test]
    fn test_parse_resolvers_str_inline_comments() {
        let input = "
            1.1.1.1:53 # primary
            8.8.8.8:853 // secondary
        ";
        let parsed = parse_resolvers_str(input).unwrap();
        assert_eq!(
            parsed,
            vec![make_addr([1, 1, 1, 1], 53), make_addr([8, 8, 8, 8], 853),]
        );
    }
}
