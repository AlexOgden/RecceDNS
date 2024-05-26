use colored::Colorize;

use crate::dns::resolver::resolve_domain;
use crate::dns::types::QueryType;
use std::{
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

fn check_udp_connection(socket: &UdpSocket, server_ip: &str, port: u16) -> Result<(), String> {
    let server_addr: SocketAddr = format!("{}:{}", server_ip, port)
        .parse()
        .map_err(|e| format!("Failed to parse address: {}", e))?;

    // Set read and write timeout to 2 seconds
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("Failed to set read timeout: {}", e))?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    socket
        .connect(server_addr)
        .map_err(|e| format!("Failed to connect to server: {}", e))?;

    Ok(())
}

fn check_dns_server(server_address: &str) -> Result<(), String> {
    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to create socket: {}", e))?;

    check_udp_connection(&socket, server_address, 53)?;

    match resolve_domain(&socket, server_address, "a.rootservers.net", &QueryType::A) {
        Ok(_) => {
            let status = format!("[{}]", "OK".green());
            println!(
                "{} {:>width$}",
                server_address.bright_blue(),
                status,
                width = 30 - server_address.len()
            );
            Ok(())
        }
        Err(_) => {
            let status = format!("[{}]", "FAIL".red());
            println!(
                "{} {:>width$}",
                server_address.bright_blue(),
                status,
                width = 30 - server_address.len()
            );
            Err(server_address.to_string())
        }
    }
}

pub fn check_server_list(server_list: &mut Vec<&str>) -> Result<(), Vec<String>> {
    println!("Checking DNS Resolvers...");

    let mut failed_servers = Vec::new();
    let mut i = 0;

    while i < server_list.len() {
        match check_dns_server(server_list[i]) {
            Ok(_) => i += 1,
            Err(dead_server) => {
                failed_servers.push(dead_server);
                server_list.remove(i);
            }
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

    #[test]
    fn udp_connect_check_ok() {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to create socket: {}", e))
            .unwrap();

        let result = check_udp_connection(&socket, "127.0.0.1", 53);

        assert!(result.is_ok());
    }

    #[test]
    fn udp_connect_check_fail() {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to create socket: {}", e))
            .unwrap();

        let result = check_udp_connection(&socket, "999.0.0.1", 53);

        assert!(result.is_err());
    }
}
