use anyhow::{anyhow, Context, Result};
use lazy_static::lazy_static;
use regex::Regex;
use std::net::Ipv4Addr;

lazy_static! {
    static ref DOMAIN_REGEX: Regex =
        Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap();
}

pub fn domain(domain: &str) -> Result<String> {
    if DOMAIN_REGEX.is_match(domain) {
        Ok(domain.to_owned())
    } else {
        Err(anyhow!("Invalid domain name: {}", domain))
    }
}

pub fn parse_dns_resolvers(servers: &str) -> Result<Vec<Ipv4Addr>> {
    if servers.is_empty() {
        return Err(anyhow!("No DNS resolvers provided"));
    }

    let server_list = servers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<&str>>();

    let mut validated_resolvers = Vec::with_capacity(server_list.len());

    for server in server_list {
        validated_resolvers.push(ipv4(server)?);
    }

    Ok(validated_resolvers)
}

pub fn ipv4(ip: &str) -> Result<Ipv4Addr> {
    ip.parse::<Ipv4Addr>()
        .with_context(|| format!("Invalid IPv4 address: {ip}"))
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
            assert_eq!(ipv4(ip).unwrap(), ip.parse::<Ipv4Addr>().unwrap());
        }
    }

    #[test]
    fn invalid_ipv4() {
        assert!(ipv4("256.0.0.1").is_err());
        assert!(ipv4("127.0.0.1234").is_err());
    }

    #[test]
    fn empty_ip() {
        assert!(ipv4("").is_err());
    }

    #[test]
    fn ipv4_with_invalid_characters() {
        assert!(ipv4("192.0.2.abc").is_err());
    }

    #[test]
    fn valid_dns_resolver_list() {
        assert_eq!(
            parse_dns_resolvers("192.0.2.1,8.8.8.8").unwrap(),
            vec![
                "192.0.2.1".parse::<Ipv4Addr>().unwrap(),
                "8.8.8.8".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn invalid_dns_resolver_list() {
        // Test with invalid IP address
        assert!(parse_dns_resolvers("192.0.2.1,256.0.0.1").is_err());

        // Test with non-IPv4 address
        assert!(parse_dns_resolvers("192.0.2.1,example.com").is_err());

        // Test with invalid format
        assert!(parse_dns_resolvers("192.0.2.1,8.8.8.8,invalid").is_err());
    }

    #[test]
    fn empty_dns_resolver_list() {
        assert!(parse_dns_resolvers("").is_err());
    }

    #[test]
    fn valid_domain() {
        assert_eq!(domain("example.com").unwrap(), "example.com");
    }

    #[test]
    fn valid_subdomain() {
        assert_eq!(
            domain("subdomain.example.com").unwrap(),
            "subdomain.example.com"
        );
    }

    #[test]
    fn invalid_domain() {
        // Test with invalid characters
        assert!(domain("example!.com").is_err());

        // Test with missing TLD
        assert!(domain("example").is_err());

        // Test with too short TLD
        assert!(domain("example.a").is_err());

        // Test with too long domain name
        assert!(domain("a".repeat(256).as_str()).is_err());
    }

    #[test]
    fn invalid_subdomain() {
        // Test with invalid characters in subdomain
        assert!(domain("sub!domain.example.com").is_err());

        // Test with too long subdomain
        let long_subdomain = "sub".repeat(64) + ".example.com";
        assert!(domain(&long_subdomain).is_err());
    }
}
