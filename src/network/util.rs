use std::net::{Ipv4Addr, Ipv6Addr};

#[must_use]
pub fn ipv4_to_ptr(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

#[must_use]
pub fn ipv6_to_ptr(ip: &Ipv6Addr) -> String {
    // Convert IPv6 to its expanded hex representation without colons
    let mut expanded = String::with_capacity(32); // 8 segments × 4 chars each
    for segment in ip.segments() {
        use std::fmt::Write;
        let _ = write!(expanded, "{segment:04x}");
    }

    let reversed = expanded.chars().rev().fold(String::new(), |mut acc, c| {
        acc.push(c);
        acc.push('.');
        acc
    });

    // Add the ip6.arpa suffix
    format!("{reversed}ip6.arpa")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_to_ptr_standard() {
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        assert_eq!(ipv4_to_ptr(ip), "10.1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_ipv4_to_ptr_loopback() {
        let ip = Ipv4Addr::LOCALHOST;
        assert_eq!(ipv4_to_ptr(ip), "1.0.0.127.in-addr.arpa");
    }

    #[test]
    fn test_ipv4_to_ptr_zero() {
        let ip = Ipv4Addr::UNSPECIFIED;
        assert_eq!(ipv4_to_ptr(ip), "0.0.0.0.in-addr.arpa");
    }

    #[test]
    fn test_ipv4_to_ptr_broadcast() {
        let ip = Ipv4Addr::BROADCAST;
        assert_eq!(ipv4_to_ptr(ip), "255.255.255.255.in-addr.arpa");
    }

    #[test]
    fn test_ipv6_to_ptr_loopback() {
        let ip = Ipv6Addr::LOCALHOST;
        assert_eq!(
            ipv6_to_ptr(&ip),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        );
    }

    #[test]
    fn test_ipv6_to_ptr_unspecified() {
        let ip = Ipv6Addr::UNSPECIFIED;
        assert_eq!(
            ipv6_to_ptr(&ip),
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        );
    }

    #[test]
    fn test_ipv6_to_ptr_documentation() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            ipv6_to_ptr(&ip),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }
}
