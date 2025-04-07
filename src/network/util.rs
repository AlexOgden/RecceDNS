use std::net::{Ipv4Addr, Ipv6Addr};

pub fn ipv4_to_ptr(ip: Ipv4Addr) -> String {
    ip.octets()
        .iter()
        .rev()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
        + ".in-addr.arpa"
}

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
