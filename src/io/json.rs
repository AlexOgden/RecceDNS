use crate::dns::protocol::DnsQueryResponse;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
pub struct EnumerationJsonOuput {
    pub target_domain: String,
    pub results: Vec<DnsQueryResponse>,
}

impl EnumerationJsonOuput {
    pub const fn new(target_domain: String) -> Self {
        Self {
            target_domain,
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: DnsQueryResponse) {
        self.results.push(result);
    }

    pub fn write_to_file(&self, output_file: &str) -> Result<()> {
        let file = std::fs::File::create(output_file)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }
}
