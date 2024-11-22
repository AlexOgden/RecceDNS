use crate::dns::protocol::ResourceRecord;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
pub struct EnumerationOutput {
    pub target_domain: String,
    pub results: Vec<ResourceRecord>,
}

impl EnumerationOutput {
    pub const fn new(target_domain: String) -> Self {
        Self {
            target_domain,
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: ResourceRecord) {
        self.results.push(result);
    }

    pub fn write_to_file(&self, output_file: &str) -> Result<()> {
        let output_file = if std::path::Path::new(output_file)
            .extension()
            .map_or(false, |ext| ext.eq_ignore_ascii_case("json"))
        {
            output_file.to_string()
        } else {
            format!("{output_file}.json")
        };

        let file = std::fs::File::create(output_file)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }
}
