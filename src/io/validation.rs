use anyhow::{Context, Result, anyhow, ensure};
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr};

use crate::network::{check, types::TransportProtocol};
use std::sync::LazyLock;

static DOMAIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap()
});

pub fn validate_target(input: &str) -> Result<String> {
    let input = input.trim();

    // Check for valid domain name
    if DOMAIN_REGEX.is_match(input) {
        return Ok(input.to_string());
    }

    // Check for valid IP address (IPv4 or IPv6)
    if input.parse::<IpAddr>().is_ok() {
        return Ok(input.to_string());
    }

    // Check for CIDR notation (IPv4 or IPv6)
    if let Some((ip_part, mask_part)) = input.split_once('/') {
        let ip_part = ip_part.trim();
        let mask_part = mask_part.trim();

        if ip_part.is_empty() || mask_part.is_empty() {
            return Err(anyhow!("Invalid CIDR notation: {}", input));
        }

        if let Ok(ip) = ip_part.parse::<IpAddr>() {
            if let Ok(mask) = mask_part.parse::<u8>() {
                match ip {
                    IpAddr::V4(_) if mask <= 32 => return Ok(input.to_string()),
                    IpAddr::V6(_) if mask <= 128 => return Ok(input.to_string()),
                    _ => {}
                }
            }
        }
    }

    // Check for IP address range
    if let Some((start_ip, end_ip)) = input.split_once('-') {
        let start_ip = start_ip.trim();
        let end_ip = end_ip.trim();

        if start_ip.is_empty() || end_ip.is_empty() {
            return Err(anyhow!("Invalid IP range format: {}", input));
        }

        let start_parse = start_ip.parse::<IpAddr>();
        let end_parse = end_ip.parse::<IpAddr>();

        match (start_parse, end_parse) {
            (Ok(start_addr), Ok(end_addr)) => {
                if start_addr.is_ipv4() == end_addr.is_ipv4() {
                    return Ok(input.to_string());
                }
                return Err(anyhow!(
                    "IP range must consist of the same IP version: {}",
                    input
                ));
            }
            _ => {
                return Err(anyhow!("Invalid IP range: {}", input));
            }
        }
    }

    // Check for CSV list of IP addresses
    if input.contains(',') {
        let ips: Vec<&str> = input.split(',').collect();
        if ips.iter().all(|&ip| ip.parse::<IpAddr>().is_ok()) {
            return Ok(input.to_string());
        }
    }

    Err(anyhow!("Invalid input: {}", input))
}

pub fn validate_dns_resolvers(servers: &str) -> Result<String> {
    let server_list: Vec<&str> = servers.split(',').collect();

    let invalid: Vec<&str> = server_list
        .iter()
        .filter(|&&server| validate_ipv4(server).is_err())
        .copied()
        .collect();

    ensure!(
        invalid.is_empty(),
        "DNS Resolver(s) invalid. Comma-separated IPv4 only. Invalid: {}",
        invalid.join(", ")
    );

    Ok(servers.to_string())
}

pub fn validate_ipv4(ip: &str) -> Result<String> {
    ip.parse::<Ipv4Addr>()
        .with_context(|| format!("Invalid IPv4 address: {ip}"))
        .map(|_| ip.to_string())
}

pub async fn filter_working_resolvers(
    no_dns_check: bool,
    transport_protocol: &TransportProtocol,
    dns_resolvers: &[Ipv4Addr],
) -> Vec<Ipv4Addr> {
    if no_dns_check {
        return dns_resolvers.to_vec();
    }

    let working_resolvers = check::check_dns_resolvers(dns_resolvers, transport_protocol).await;

    dns_resolvers
        .iter()
        .copied()
        .filter(|resolver| working_resolvers.contains(resolver))
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valid_ipv4() {
        let valid_ips = [
            "192.168.0.1",
            "127.0.0.1",
            "172.0.1.1",
            "111.111.111.111",
            "0.0.0.0",
        ];
        for ip in valid_ips {
            assert_eq!(validate_ipv4(ip).unwrap(), ip);
        }
    }

    #[test]
    fn invalid_ipv4() {
        assert!(validate_ipv4("256.0.0.1").is_err());
        assert!(validate_ipv4("127.0.0.1234").is_err());
    }

    #[test]
    fn empty_ip() {
        assert!(validate_ipv4("").is_err());
    }

    #[test]
    fn ipv4_with_invalid_characters() {
        assert!(validate_ipv4("192.0.2.abc").is_err());
    }

    #[test]
    fn valid_dns_resolver_list() {
        assert_eq!(
            validate_dns_resolvers("192.0.2.1,8.8.8.8").unwrap(),
            "192.0.2.1,8.8.8.8"
        );
    }

    #[test]
    fn invalid_dns_resolver_list() {
        // Test with invalid IP address
        assert!(validate_dns_resolvers("192.0.2.1,256.0.0.1").is_err());

        // Test with non-IPv4 address
        assert!(validate_dns_resolvers("192.0.2.1,example.com").is_err());

        // Test with invalid format
        assert!(validate_dns_resolvers("192.0.2.1,8.8.8.8,invalid").is_err());
    }

    #[test]
    fn empty_dns_resolver_list() {
        assert!(validate_dns_resolvers("").is_err());
    }

    #[test]
    fn valid_domain_names() {
        let valid_domains = [
            "example.com",
            "sub.example.com",
            "example.co.uk",
            "a.com",
            "a-b.com",
        ];
        for domain in valid_domains {
            assert_eq!(validate_target(domain).unwrap(), domain);
        }
    }

    #[test]
    fn invalid_domain_names() {
        let invalid_domains = [
            "-example.com",
            "example-.com",
            "exa_mple.com",
            "example..com",
            "example.com-",
        ];
        for domain in invalid_domains {
            assert!(validate_target(domain).is_err());
        }
    }

    #[test]
    fn valid_cidr_notations() {
        let valid_cidrs = [
            "192.168.0.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "2001:db8::/32",
            "fe80::/10",
        ];
        for cidr in valid_cidrs {
            assert_eq!(validate_target(cidr).unwrap(), cidr);
        }
    }

    #[test]
    fn invalid_cidr_notations() {
        let invalid_cidrs = [
            "192.168.0.0/33",
            "10.0.0.0/-1",
            "172.16.0.0/abc",
            "2001:db8::/129",
            "fe80::/130",
        ];
        for cidr in invalid_cidrs {
            assert!(validate_target(cidr).is_err());
        }
    }

    #[test]
    fn valid_ip_ranges() {
        let valid_ranges = ["192.168.0.1-192.168.0.255", "10.0.0.1-10.0.0.255"];
        for range in valid_ranges {
            assert_eq!(validate_target(range).unwrap(), range);
        }
    }

    #[test]
    fn invalid_ip_ranges() {
        let invalid_ranges = [
            "192.168.0.1-192.168.0.256",
            "192.168.0.1-",
            "-192.168.0.255",
            "a-b",
            "192.168.v.2-192.168.7.2",
        ];
        for range in invalid_ranges {
            println!("{range}");
            assert!(validate_target(range).is_err());
        }
    }
}
