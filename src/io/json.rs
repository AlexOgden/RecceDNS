use anyhow::Result;
use serde::Serialize;
use std::fs::File;
use std::path::Path;

use crate::dns::protocol::ResourceRecord;
use crate::log_info;

pub trait Output {
    fn write_to_file(&self, output_file: &str) -> Result<()>;
}

#[derive(Serialize)]
pub struct DnsEnumerationOutput {
    pub target_domain: String,
    pub results: Vec<ResourceRecord>,
}

#[derive(Serialize)]
pub struct CertSearchOutput {
    pub target_domain: String,
    pub subdomains: Vec<String>,
}

impl Output for DnsEnumerationOutput {
    fn write_to_file(&self, output_file: &str) -> Result<()> {
        write_json(&self, output_file)
    }
}

impl Output for CertSearchOutput {
    fn write_to_file(&self, output_file: &str) -> Result<()> {
        write_json(&self, output_file)
    }
}

fn write_json<T: Serialize>(data: &T, output_file: &str) -> Result<()> {
    let output_file = if Path::new(output_file)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        output_file.to_string()
    } else {
        format!("{output_file}.json")
    };

    let file = File::create(&output_file)?;
    serde_json::to_writer_pretty(file, data)?;

    log_info!(format!("JSON output written to: {}", output_file));

    Ok(())
}

impl DnsEnumerationOutput {
    pub const fn new(target_domain: String) -> Self {
        Self {
            target_domain,
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: ResourceRecord) {
        self.results.push(result);
    }
}

impl CertSearchOutput {
    pub const fn new(target_domain: String) -> Self {
        Self {
            target_domain,
            subdomains: Vec::new(),
        }
    }

    pub fn add_result(&mut self, subdomain: String) {
        self.subdomains.push(subdomain);
    }
}
