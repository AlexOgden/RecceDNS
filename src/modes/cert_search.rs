use std::collections::HashSet;

use crate::io::{
    cli::CommandArgs,
    json::{CertSearchOutput, Output},
};
use anyhow::Result;
use colored::Colorize;
use thiserror::Error;

const CRTSH_URL: &str = "https://crt.sh/json?q=";

#[derive(Error, Debug)]
pub enum SearchError {
    #[error("HTTP request failed: {0}")]
    HttpRequestError(#[from] reqwest::Error),

    #[error("Failed to parse JSON response: {0}")]
    JsonParseError(#[from] serde_json::Error),

    #[error("Received empty JSON data")]
    EmptyJsonData,
}

pub fn search_certificates(cmd_args: &CommandArgs) -> Result<()> {
    println!(
        "Searching subdomain certificates for target domain: {}\n",
        cmd_args.target.bold().bright_blue()
    );

    let mut results_output = cmd_args.json.as_ref().map(|_| CertSearchOutput::new(cmd_args.target.clone()));
    let target_domain = cmd_args.target.as_str();

    match get_results_json(target_domain) {
        Ok(data) => {
            let subdomains = get_subdomains(&data, target_domain)?;

            for subdomain in &subdomains {
                println!(
                    "[{}] {}.{}",
                    "+".green(),
                    subdomain.cyan().bold(),
                    target_domain.blue().italic()
                );
            }

            if let Some(output) = &mut results_output {
                for subdomain in &subdomains {
                    output.add_result(subdomain.clone());
                }
            }

            println!(
                "\n[{}] Found {} subdomains for target domain: {}",
                "+".green(),
                subdomains.len(),
                target_domain
            );

            if let Some(output) = results_output {
                let json_path = cmd_args.json.clone().ok_or_else(|| anyhow::anyhow!("JSON output path is missing."))?;
                output.write_to_file(&json_path)?;
            }

            Ok(())
        }
        Err(error) => {
            if matches!(error, SearchError::EmptyJsonData) {
                println!(
                    "[{}] No subdomains found for domain: {}",
                    "~".green(),
                    target_domain
                );
                Ok(())
            } else {
                eprintln!("[{}] API Request failed! {}", "!".red(), error);
                Err(error.into())
            }
        }
    }
}

fn get_results_json(target_domain: &str) -> Result<serde_json::Value, SearchError> {
    let url = format!("{CRTSH_URL}{target_domain}");

    let response = reqwest::blocking::get(&url).map_err(SearchError::HttpRequestError)?;
    let json: serde_json::Value = response.json()?;

    if json.as_array().map_or(true, Vec::is_empty) {
        return Err(SearchError::EmptyJsonData);
    }

    Ok(json)
}

fn get_subdomains(json: &serde_json::Value, target_domain: &str) -> Result<HashSet<String>> {
    let names: HashSet<String> = json
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Expected a JSON array"))?
        .iter()
        .filter_map(|entry| entry.get("common_name").and_then(|v| v.as_str()))
        .filter(|s| *s != target_domain)
        .map(|s| s.split('.').next().unwrap_or("").to_string())
        .collect();

    Ok(names)
}
