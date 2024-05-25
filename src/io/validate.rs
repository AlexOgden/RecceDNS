use anyhow::{Context, Result, anyhow};
use lazy_static::lazy_static;
use regex::Regex;
use std::net::Ipv4Addr;

lazy_static! {
    static ref DOMAIN_REGEX: Regex =
        Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
            .expect("Failed to create domain regex");
}

pub fn validate_domain(domain: &str) -> Result<String> {
    if DOMAIN_REGEX.is_match(domain) {
        Ok(domain.to_string())
    } else {
        Err(anyhow!("Invalid domain name"))
    }
}

pub fn validate_dns_resolver_list(servers: &str) -> Result<String> {
    let server_list: Vec<&str> = servers.split(',').collect();

    if server_list
        .iter()
        .all(|&server| validate_ipv4(server).is_ok())
    {
        Ok(servers.to_string())
    } else {
        Err(anyhow!(
            "DNS Resolver(s) invalid. Comma-seperated IPv4 only."
        ))
    }
}

pub fn validate_ipv4(ip: &str) -> Result<String> {
    ip.parse::<Ipv4Addr>()
        .with_context(|| format!("Invalid IPv4 address: {}", ip))
        .map(|_| ip.to_string())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valid_ipv4() {
        let valid_ips = ["192.168.0.1", "127.0.0.1", "172.0.1.1", "111.111.111.111", "0.0.0.0"];
        for ip in valid_ips {
            assert_eq!(
                validate_ipv4(ip).unwrap(),
                ip
            );
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
            validate_dns_resolver_list("192.0.2.1,8.8.8.8").unwrap(),
            "192.0.2.1,8.8.8.8"
        );
    }

    #[test]
    fn invalid_dns_resolver_list() {
        // Test with invalid IP address
        assert!(validate_dns_resolver_list("192.0.2.1,256.0.0.1").is_err());

        // Test with non-IPv4 address
        assert!(validate_dns_resolver_list("192.0.2.1,example.com").is_err());

        // Test with invalid format
        assert!(validate_dns_resolver_list("192.0.2.1,8.8.8.8,invalid").is_err());
    }

    #[test]
    fn empty_dns_resolver_list() {
        assert!(validate_dns_resolver_list("").is_err());
    }

    #[test]
    fn valid_domain() {
        assert_eq!(
            validate_domain("example.com").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn valid_subdomain() {
        assert_eq!(
            validate_domain("subdomain.example.com").unwrap(),
            "subdomain.example.com"
        );
    }

    #[test]
    fn invalid_domain() {
        // Test with invalid characters
        assert!(validate_domain("example!.com").is_err());

        // Test with missing TLD
        assert!(validate_domain("example").is_err());

        // Test with too short TLD
        assert!(validate_domain("example.a").is_err());

        // Test with too long domain name
        assert!(validate_domain("a".repeat(256).as_str()).is_err());
    }

    #[test]
    fn invalid_subdomain() {
        // Test with invalid characters in subdomain
        assert!(validate_domain("sub!domain.example.com").is_err());

        // Test with too long subdomain
        let long_subdomain = "sub".repeat(64) + ".example.com";
        assert!(validate_domain(&long_subdomain).is_err());
    }

}
