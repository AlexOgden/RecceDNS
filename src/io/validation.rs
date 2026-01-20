use anyhow::{Context, Result, anyhow, ensure};
use regex::Regex;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use crate::network::{check, types::TransportProtocol};
use std::sync::LazyLock;

static DOMAIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Label rules: start with alnum/underscore, can contain hyphens in middle, end with alnum/underscore
    // Each label 1-63 chars, TLD must be 2+ alpha chars
    Regex::new(r"^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}\.?$").unwrap()
});

const MAX_LABEL_LENGTH: usize = 63;
const MAX_DOMAIN_LENGTH: usize = 253;

fn parse_csv(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn validate_target(input: &str) -> Result<String> {
    let input = input.trim();

    // Check for valid domain name
    if DOMAIN_REGEX.is_match(input) {
        // Validate total domain length
        let domain_without_trailing_dot = input.trim_end_matches('.');
        if domain_without_trailing_dot.len() > MAX_DOMAIN_LENGTH {
            return Err(anyhow!(
                "Domain name exceeds maximum length of {MAX_DOMAIN_LENGTH} characters: {input}"
            ));
        }

        // Validate individual label lengths
        for label in domain_without_trailing_dot.split('.') {
            if label.len() > MAX_LABEL_LENGTH {
                return Err(anyhow!(
                    "Domain label '{label}' exceeds maximum length of {MAX_LABEL_LENGTH} characters"
                ));
            }
        }

        // Normalize to lowercase for DNS case-insensitivity
        return Ok(input.to_lowercase());
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
            return Err(anyhow!("Invalid CIDR notation: {input}"));
        }

        if let Ok(ip) = ip_part.parse::<IpAddr>()
            && let Ok(mask) = mask_part.parse::<u8>()
        {
            match ip {
                IpAddr::V4(_) if mask <= 32 => return Ok(input.to_string()),
                IpAddr::V6(_) if mask <= 128 => return Ok(input.to_string()),
                _ => {}
            }
        }
    }

    // Check for IP address range
    if let Some((start_ip, end_ip)) = input.split_once('-') {
        let start_ip = start_ip.trim();
        let end_ip = end_ip.trim();

        if start_ip.is_empty() || end_ip.is_empty() {
            return Err(anyhow!("Invalid IP range format: {input}"));
        }

        let start_parse = start_ip.parse::<IpAddr>();
        let end_parse = end_ip.parse::<IpAddr>();

        match (start_parse, end_parse) {
            (Ok(IpAddr::V4(s)), Ok(IpAddr::V4(e))) if s <= e => return Ok(input.to_string()),
            (Ok(IpAddr::V6(s)), Ok(IpAddr::V6(e))) if s <= e => return Ok(input.to_string()),
            (Ok(IpAddr::V4(_)), Ok(IpAddr::V4(_))) | (Ok(IpAddr::V6(_)), Ok(IpAddr::V6(_))) => {
                return Err(anyhow!("Invalid IP range (start must be <= end): {input}"));
            }
            (Ok(_), Ok(_)) => {
                return Err(anyhow!(
                    "IP range must consist of the same IP version: {input}"
                ));
            }
            _ => return Err(anyhow!("Invalid IP range: {input}")),
        }
    }

    // Check for CSV list of IP addresses (single-pass with early exit on invalid IP)
    if input.contains(',') {
        let result: Result<Vec<_>, _> = input
            .split(',')
            .map(|ip| {
                let trimmed = ip.trim();
                trimmed.parse::<IpAddr>().map(|_| trimmed)
            })
            .collect();

        if let Ok(ips) = result {
            return Ok(ips.join(","));
        }
    }

    Err(anyhow!("Invalid input: {input}"))
}

pub fn validate_dns_resolvers(servers: &str) -> Result<String> {
    let server_list: Vec<String> = if Path::new(servers).exists() {
        let contents = fs::read_to_string(servers)
            .map_err(|e| anyhow!("Failed to read DNS resolver file: {e}"))?;
        contents.lines().flat_map(parse_csv).collect()
    } else {
        parse_csv(servers)
    };

    if server_list.is_empty() {
        return Err(anyhow!("No DNS resolvers provided."));
    }

    let invalid: Vec<String> = server_list
        .iter()
        .filter(|server| validate_ipv4(server).is_err())
        .cloned()
        .collect();

    ensure!(
        invalid.is_empty(),
        "DNS Resolver(s) invalid. Comma-separated IPv4 only. Invalid: {}",
        invalid.join(", ")
    );

    Ok(server_list.join(","))
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
            "a.bb.com",
            "a-b.com",
            "example.com.",          // trailing dot (FQDN)
            "_dmarc.example.com",    // underscore prefix (DMARC)
            "_srv.example.com",      // underscore prefix (SRV)
            "test_host.example.com", // underscore in subdomain
            "a1.example.com",        // alphanumeric
            "1a.example.com",        // starts with number
            "very-long-subdomain-name.example.com",
            "a.b.c.d.example.com", // deep nesting
        ];
        for domain in valid_domains {
            assert!(validate_target(domain).is_ok(), "Expected valid: {domain}");
        }
    }

    #[test]
    fn invalid_domain_names() {
        let invalid_domains = [
            "-example.com", // starts with hyphen
            "example-.com", // label ends with hyphen
            "example..com", // double dot
            ".example.com", // starts with dot
            "example",      // no TLD
            "",             // empty
            "a]b.com",      // invalid character
            "exam ple.com", // space in domain
        ];
        for domain in invalid_domains {
            assert!(
                validate_target(domain).is_err(),
                "Expected invalid: {domain}"
            );
        }
    }

    #[test]
    fn domain_with_whitespace() {
        // Should trim, validate, and lowercase
        assert_eq!(validate_target("  example.com  ").unwrap(), "example.com");
        assert_eq!(validate_target("\texample.com\n").unwrap(), "example.com");
    }

    #[test]
    fn domain_normalized_to_lowercase() {
        assert_eq!(validate_target("EXAMPLE.COM").unwrap(), "example.com");
        assert_eq!(validate_target("Example.Com").unwrap(), "example.com");
        assert_eq!(
            validate_target("SUB.EXAMPLE.COM").unwrap(),
            "sub.example.com"
        );
    }

    #[test]
    fn domain_label_length_validation() {
        // Label at exactly 63 chars should be valid
        let label_63 = "a".repeat(63);
        let domain_63 = format!("{label_63}.com");
        assert!(validate_target(&domain_63).is_ok());

        // Label at 64 chars should be invalid
        let label_64 = "a".repeat(64);
        let domain_64 = format!("{label_64}.com");
        assert!(validate_target(&domain_64).is_err());
    }

    #[test]
    fn csv_ip_list_normalized() {
        // Should trim whitespace from individual IPs
        assert_eq!(
            validate_target("1.1.1.1 , 8.8.8.8 , 9.9.9.9").unwrap(),
            "1.1.1.1,8.8.8.8,9.9.9.9"
        );
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
        let valid_ranges = [
            "192.168.0.1-192.168.0.255",
            "10.0.0.1-10.0.0.255",
            "1.1.1.1-1.1.1.1", // same IP (edge case)
            "::1-::ffff",      // IPv6 range
            "2001:db8::1-2001:db8::ff",
        ];
        for range in valid_ranges {
            assert!(validate_target(range).is_ok(), "Expected valid: {range}");
        }
    }

    #[test]
    fn invalid_ip_ranges() {
        let invalid_ranges = [
            "192.168.0.1-192.168.0.256", // invalid IP
            "192.168.0.1-",              // missing end
            "-192.168.0.255",            // missing start
            "a-b",                       // not IPs
            "192.168.v.2-192.168.7.2",   // invalid octet
        ];
        for range in invalid_ranges {
            assert!(validate_target(range).is_err(), "Expected invalid: {range}");
        }
    }

    #[test]
    fn ip_range_mixed_versions() {
        // IPv4 start with IPv6 end
        let result = validate_target("192.168.0.1-::1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("same IP version"));

        // IPv6 start with IPv4 end
        let result = validate_target("::1-192.168.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("same IP version"));
    }

    #[test]
    fn ip_range_start_greater_than_end() {
        // IPv4: start > end
        let result = validate_target("192.168.1.100-192.168.1.1");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("start must be <= end")
        );

        // IPv6: start > end
        let result = validate_target("::ffff-::1");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("start must be <= end")
        );
    }

    #[test]
    fn valid_ipv4_addresses() {
        let valid = ["192.168.1.1", "0.0.0.0", "255.255.255.255", "8.8.8.8"];
        for ip in valid {
            assert!(validate_target(ip).is_ok(), "Expected valid: {ip}");
        }
    }

    #[test]
    fn valid_ipv6_addresses() {
        let valid = [
            "::1",
            "2001:db8::1",
            "fe80::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        ];
        for ip in valid {
            assert!(validate_target(ip).is_ok(), "Expected valid: {ip}");
        }
    }

    #[test]
    fn valid_csv_ip_list() {
        assert!(validate_target("1.1.1.1,8.8.8.8,9.9.9.9").is_ok());
        assert!(validate_target("::1,::2").is_ok());
    }

    #[test]
    fn invalid_csv_ip_list() {
        // Mixed valid/invalid
        assert!(validate_target("1.1.1.1,invalid,8.8.8.8").is_err());
        // All invalid
        assert!(validate_target("foo,bar,baz").is_err());
    }

    #[test]
    fn dns_resolver_with_whitespace() {
        // Should handle whitespace around IPs
        assert_eq!(
            validate_dns_resolvers("8.8.8.8 , 1.1.1.1").unwrap(),
            "8.8.8.8,1.1.1.1"
        );
    }

    #[test]
    fn dns_resolver_single() {
        assert_eq!(validate_dns_resolvers("8.8.8.8").unwrap(), "8.8.8.8");
    }

    #[test]
    fn dns_resolver_rejects_ipv6() {
        // Currently only IPv4 is supported
        assert!(validate_dns_resolvers("2001:4860:4860::8888").is_err());
    }
}
