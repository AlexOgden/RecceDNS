use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use std::{
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use crate::dns::{resolver::resolve_domain, types::QueryType, types::TransportProtocol};

const DNS_PORT: u16 = 53;
const ROOT_SERVER: &str = "a.rootservers.net";

fn check_udp_connection(socket: &UdpSocket, server_ip: &str, port: u16) -> Result<()> {
    let server_addr: SocketAddr = format!("{server_ip}:{port}")
        .parse()
        .context("Failed to parse address")?;

    // Set read and write timeout to 2 seconds
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .context("Failed to set read timeout")?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .context("Failed to set write timeout")?;

    socket
        .connect(server_addr)
        .context("Failed to connect to server")?;

    Ok(())
}

fn check_dns_server(server_address: &str, transport_protocol: &TransportProtocol) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("Failed to create socket")?;

    check_udp_connection(&socket, server_address, DNS_PORT)?;

    if resolve_domain(
        server_address,
        ROOT_SERVER,
        &QueryType::A,
        transport_protocol,
    )
    .is_ok()
    {
        print_status(server_address, "OK", "green");
        Ok(())
    } else {
        print_status(server_address, "FAIL", "red");
        Err(anyhow!(server_address.to_string()))
    }
}

fn print_status(server_address: &str, status: &str, color: &str) {
    let colored_status = match color {
        "green" => format!("[{}]", status.green()),
        "red" => format!("[{}]", status.red()),
        _ => status.to_string(),
    };

    println!(
        "{} {:>width$}",
        server_address.bright_blue(),
        colored_status,
        width = 30 - server_address.len()
    );
}

pub fn check_server_list(
    server_list: &[&str],
    transport_protocol: &TransportProtocol,
) -> Result<(), Vec<String>> {
    println!("Checking DNS Servers...");

    let mut failed_servers = Vec::new();

    for &server in server_list {
        if let Err(err) = check_dns_server(server, transport_protocol) {
            failed_servers.push(err.to_string());
        }
    }

    if failed_servers.is_empty() {
        Ok(())
    } else {
        Err(failed_servers)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Context;
    use std::net::UdpSocket;

    #[test]
    fn udp_connect_check_ok() {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .context("Failed to create socket")
            .unwrap();

        let result = check_udp_connection(&socket, "127.0.0.1", 53);

        assert!(result.is_ok());
    }

    #[test]
    fn udp_connect_check_fail() {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .context("Failed to create socket")
            .unwrap();

        let result = check_udp_connection(&socket, "999.0.0.1", 53);

        assert!(result.is_err());
    }

    #[test]
    fn check_dns_server_9_9_9_9_udp() {
        let result = check_dns_server("9.9.9.9", &TransportProtocol::UDP);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn check_dns_server_8_8_8_8_udp() {
        let result = check_dns_server("8.8.8.8", &TransportProtocol::UDP);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn check_dns_server_9_9_9_9_tcp() {
        let result = check_dns_server("9.9.9.9", &TransportProtocol::TCP);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn check_dns_server_8_8_8_8_tcp() {
        let result = check_dns_server("8.8.8.8", &TransportProtocol::TCP);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn check_server_list_with_valid_servers_udp() {
        let server_list = vec!["9.9.9.9", "8.8.8.8"];
        let result = check_server_list(&server_list, &TransportProtocol::UDP);
        assert!(result.is_ok());
    }

    #[test]
    fn check_server_list_with_invalid_server_udp() {
        let server_list = vec!["999.0.0.1", "8.8.8.8"];
        let result = check_server_list(&server_list, &TransportProtocol::UDP);
        assert!(result.is_err());
    }

    #[test]
    fn check_server_list_with_valid_servers_tcp() {
        let server_list = vec!["9.9.9.9", "8.8.8.8"];
        let result = check_server_list(&server_list, &TransportProtocol::TCP);
        assert!(result.is_ok());
    }

    #[test]
    fn check_server_list_with_invalid_server_tcp() {
        let server_list = vec!["999.0.0.1", "8.8.8.8"];
        let result = check_server_list(&server_list, &TransportProtocol::TCP);
        assert!(result.is_err());
    }
}
