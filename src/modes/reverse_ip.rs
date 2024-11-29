use anyhow::Result;
use colored::Colorize;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::Ordering,
    thread,
    time::Duration,
    vec,
};
use thiserror::Error;

use crate::{
    dns::{
        error::DnsError,
        protocol::{QueryType, RData},
        resolver::resolve_domain,
        resolver_selector,
    },
    io::{
        cli::{self, CommandArgs},
        interrupt,
    },
    timing::stats::QueryTimer,
};

pub fn reverse_ip(cmd_args: &CommandArgs, dns_resolver_list: &[&str]) -> Result<()> {
    let interrupted = interrupt::initialize_interrupt_handler()?;

    let target_ips = parse_ip(&cmd_args.target)?;
    let total_ips = target_ips.len() as u64;

    let mut resolver_selector = resolver_selector::get_selector(cmd_args, dns_resolver_list);
    let mut query_timer = QueryTimer::new(!cmd_args.no_query_stats);
    let mut found_count = 0;

    let progress_bar = cli::setup_progress_bar(total_ips);
    progress_bar.set_message("Performing reverse PTR lookup...");
    progress_bar.println(format!(
        "[{}] Performing reverse PTR lookup for {} IP addresses\n",
        "~".green(),
        target_ips.len()
    ));

    for (index, ip) in target_ips.iter().enumerate() {
        if interrupted.load(Ordering::SeqCst) {
            cli::clear_line();
            progress_bar.println(format!("[{}] Interrupted by user", "!".red()));
            break;
        }

        let resolver = resolver_selector.select()?;
        query_timer.start();
        let query_result = resolve_domain(
            resolver,
            &ip.to_string(),
            &QueryType::PTR,
            &cmd_args.transport_protocol,
            !&cmd_args.no_recursion,
        );
        query_timer.stop();

        cli::update_progress_bar(&progress_bar, index, total_ips);

        match query_result {
            Ok(response) => {
                let ptr_records: Vec<String> = response
                    .answers
                    .iter()
                    .filter_map(|answer| {
                        if let RData::PTR(ptr) = &answer.data {
                            Some(ptr.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                let display_record = if ptr_records.is_empty() {
                    "No PTR record found".to_string()
                } else {
                    ptr_records.join(", ")
                };
                progress_bar.println(format!("[{}] {} [{}]", "+".green(), ip, display_record));
                found_count += 1;
            }
            Err(error) => {
                if cmd_args.verbose
                    || (!matches!(
                        error,
                        DnsError::NoRecordsFound | DnsError::NonExistentDomain
                    ))
                {
                    progress_bar.println(format!("[{}] {} [{}]", "-".red(), ip, error));
                }
            }
        }

        if let Some(delay_ms) = &cmd_args.delay {
            let sleep_delay = delay_ms.get_delay();
            if sleep_delay > 0 {
                thread::sleep(Duration::from_millis(sleep_delay));
            }
        }
    }

    progress_bar.finish_with_message("Reverse PTR lookup completed.");
    cli::clear_line();

    println!("[{}] Found {} PTR records", "~".green(), found_count);
    if let Some(avg) = query_timer.average() {
        println!(
            "[{}] Average query time: {} ms",
            "~".green(),
            avg.to_string().bold().bright_yellow()
        );
    }
    Ok(())
}

// Check if a string is a valid IPv4 or IPv6 address, eithe single or in CIDR notation
// If the IP is in CIDR notation, expand it to a list of IPs
#[derive(Error, Debug)]
pub enum ParseIpError {
    #[error("Invalid CIDR notation")]
    InvalidCidr,
    #[error("Invalid IP address")]
    InvalidIp,
    #[error("CIDR prefix out of range for IPv4")]
    CidrOutOfRangeV4,
    #[error("CIDR prefix out of range for IPv6")]
    CidrOutOfRangeV6,
    #[error("CIDR prefix too small, resulting in too many IPs")]
    CidrPrefixTooSmall,
    #[error("Invalid IP range")]
    InvalidRange,
    #[error("Start IP is greater than end IP in range")]
    StartIpGreaterThanEndIp,
}

fn parse_ip(ip: &str) -> Result<Vec<IpAddr>, ParseIpError> {
    if let Some((start, end)) = ip.split_once('-') {
        expand_ip_range(start.trim(), end.trim())
    } else if let Some((ip_str, cidr_str)) = ip.split_once('/') {
        expand_cidr(ip_str.trim(), cidr_str.trim())
    } else {
        let ip = ip.parse().map_err(|_| ParseIpError::InvalidIp)?;
        Ok(vec![ip])
    }
}

fn expand_cidr(ip_str: &str, cidr_str: &str) -> Result<Vec<IpAddr>, ParseIpError> {
    let cidr: u8 = cidr_str.parse().map_err(|_| ParseIpError::InvalidCidr)?;
    let ip: IpAddr = ip_str.parse().map_err(|_| ParseIpError::InvalidIp)?;

    match ip {
        IpAddr::V4(ipv4) => {
            if cidr > 32 {
                return Err(ParseIpError::CidrOutOfRangeV4);
            }
            let mask = if cidr == 0 {
                0
            } else {
                u32::MAX << (32 - cidr)
            };
            let ip_num = u32::from(ipv4) & mask;
            let range = 32 - cidr;
            if range > 24 {
                return Err(ParseIpError::CidrPrefixTooSmall);
            }
            let ips = (0..2u32.pow(range.into()))
                .map(|i| IpAddr::V4(Ipv4Addr::from(ip_num + i)))
                .collect();
            Ok(ips)
        }
        IpAddr::V6(ipv6) => {
            if cidr > 128 {
                return Err(ParseIpError::CidrOutOfRangeV6);
            }
            let mask = if cidr == 0 {
                0
            } else {
                u128::MAX << (128 - cidr)
            };
            let ip_num = u128::from_be_bytes(ipv6.octets()) & mask;
            let range = 128 - cidr;
            if range > 16 {
                return Err(ParseIpError::CidrPrefixTooSmall);
            }
            let ips = (0..2u128.pow(range.into()))
                .map(|i| {
                    let addr = ip_num + i;
                    IpAddr::V6(Ipv6Addr::from(addr.to_be_bytes()))
                })
                .collect();
            Ok(ips)
        }
    }
}

fn expand_ip_range(start: &str, end: &str) -> Result<Vec<IpAddr>, ParseIpError> {
    let start_ip: IpAddr = start.parse().map_err(|_| ParseIpError::InvalidIp)?;
    let end_ip: IpAddr = end.parse().map_err(|_| ParseIpError::InvalidIp)?;

    match (start_ip, end_ip) {
        (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
            let start_num = u32::from(start_v4);
            let end_num = u32::from(end_v4);
            if start_num > end_num {
                return Err(ParseIpError::StartIpGreaterThanEndIp);
            }
            Ok((start_num..=end_num)
                .map(|num| IpAddr::V4(Ipv4Addr::from(num)))
                .collect())
        }
        (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
            let start_num = u128::from_be_bytes(start_v6.octets());
            let end_num = u128::from_be_bytes(end_v6.octets());
            if start_num > end_num {
                return Err(ParseIpError::StartIpGreaterThanEndIp);
            }
            Ok((start_num..=end_num)
                .map(|num| {
                    let octets = num.to_be_bytes();
                    IpAddr::V6(Ipv6Addr::from(octets))
                })
                .collect())
        }
        _ => Err(ParseIpError::InvalidRange),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_single_ipv4() {
        let ip = "192.168.1.1";
        let result = parse_ip(ip).unwrap();
        assert_eq!(result, vec![IpAddr::V4("192.168.1.1".parse().unwrap())]);
    }

    #[test]
    fn test_parse_ip_single_ipv6() {
        let ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let result = parse_ip(ip).unwrap();
        assert_eq!(
            result,
            vec![IpAddr::V6(
                "2001:0db8:85a3::8a2e:0370:7334".parse().unwrap()
            )]
        );
    }

    #[test]
    fn test_parse_ip_cidr_ipv4() {
        let ip = "192.168.1.0/30";
        let result = parse_ip(ip).unwrap();
        let expected = vec![
            IpAddr::V4("192.168.1.0".parse().unwrap()),
            IpAddr::V4("192.168.1.1".parse().unwrap()),
            IpAddr::V4("192.168.1.2".parse().unwrap()),
            IpAddr::V4("192.168.1.3".parse().unwrap()),
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_ip_cidr_ipv6() {
        let ip = "2001:db8::/126";
        let result = parse_ip(ip).unwrap();
        let expected = vec![
            IpAddr::V6("2001:db8::".parse().unwrap()),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            IpAddr::V6("2001:db8::2".parse().unwrap()),
            IpAddr::V6("2001:db8::3".parse().unwrap()),
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_ip_range_ipv4() {
        let ip = "192.168.1.1 - 192.168.1.3";
        let result = parse_ip(ip).unwrap();
        let expected = vec![
            IpAddr::V4("192.168.1.1".parse().unwrap()),
            IpAddr::V4("192.168.1.2".parse().unwrap()),
            IpAddr::V4("192.168.1.3".parse().unwrap()),
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_ip_invalid_ip() {
        let ip = "999.999.999.999";
        let result = parse_ip(ip);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid IP address");
    }

    #[test]
    fn test_parse_ip_invalid_cidr() {
        let ip = "192.168.1.0/33";
        let result = parse_ip(ip);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "CIDR prefix out of range for IPv4"
        );
    }

    #[test]
    fn test_parse_range_invalid_range() {
        let start = "192.168.1.10";
        let end = "192.168.1.5";
        let result = expand_ip_range(start, end);
        assert!(matches!(result, Err(ParseIpError::StartIpGreaterThanEndIp)));
    }

    #[test]
    fn test_parse_cidr_too_small_ipv4() {
        let ip_str = "192.168.1.0";
        let cidr_str = "7";
        let result = expand_cidr(ip_str, cidr_str);
        assert!(matches!(result, Err(ParseIpError::CidrPrefixTooSmall)));
    }

    #[test]
    fn test_parse_cidr_too_small_ipv6() {
        let ip_str = "2001:db8::";
        let cidr_str = "110";
        let result = expand_cidr(ip_str, cidr_str);
        assert!(matches!(result, Err(ParseIpError::CidrPrefixTooSmall)));
    }
}
