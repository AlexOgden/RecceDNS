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
pub struct RecceOutput {
    pub target: String,
    pub results: Vec<RecceResult>,
}

#[derive(Serialize)]
pub struct RecceResult {
    pub domain: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<ResourceRecord>,
}

impl Output for RecceOutput {
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

impl RecceOutput {
    pub const fn new(target: String) -> Self {
        Self {
            target,
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, domain: String, records: Vec<ResourceRecord>) {
        self.results.push(RecceResult { domain, records });
    }
}
