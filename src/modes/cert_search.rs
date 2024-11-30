use std::collections::HashSet;
use std::time::Duration;

use crate::io::{
    cli::CommandArgs,
    json::{CertSearchOutput, Output},
};
use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Client, StatusCode};
use thiserror::Error;

const CRTSH_URL: &str = "https://crt.sh/json?q=";

#[derive(Error, Debug)]
pub enum SearchError {
    #[error("HTTP request failed: {0}")]
    HttpRequestError(#[from] reqwest::Error),

    #[error("Received non-success status code: {0}")]
    NonSuccessStatus(StatusCode),

    #[error("Failed to parse JSON response: {0}")]
    JsonParseError(#[from] serde_json::Error),

    #[error("Received empty JSON data")]
    EmptyJsonData,
}

pub async fn search_certificates(cmd_args: &CommandArgs) -> Result<()> {
    println!(
        "Searching subdomain certificates for target domain: {}\n",
        cmd_args.target.bold().bright_blue()
    );

    let mut results_output = cmd_args
        .json
        .as_ref()
        .map(|_| CertSearchOutput::new(cmd_args.target.clone()));
    let target_domain = cmd_args.target.as_str();

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("[{spinner:.cyan}] Fetching certificate records...")
            .expect("Invalid template")
            .tick_chars("/|\\- "),
    );
    spinner.enable_steady_tick(Duration::from_millis(100));

    match get_results_json(target_domain).await {
        Ok(data) => {
            spinner.set_message("Searching...");
            let subdomains = get_subdomains(&data, target_domain)?;
            spinner.finish_and_clear();

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
                let json_path = cmd_args
                    .json
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("JSON output path is missing."))?;
                output.write_to_file(&json_path)?;
            }
        }
        Err(error) => {
            spinner.finish_and_clear();
            if matches!(error, SearchError::EmptyJsonData) {
                println!(
                    "[{}] No subdomains found for domain: {}",
                    "~".green(),
                    target_domain.bold()
                );
            } else {
                eprintln!("[{}] {}", "!".red(), error);
            }
        }
    }
    Ok(())
}

async fn get_results_json(target_domain: &str) -> Result<serde_json::Value, SearchError> {
    let url = format!("{CRTSH_URL}{target_domain}");
    let client = Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(SearchError::HttpRequestError)?;

    let status = response.status();
    if !status.is_success() {
        return Err(SearchError::NonSuccessStatus(status));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(SearchError::HttpRequestError)?;

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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_get_subdomains_with_valid_json() {
        let sample_json = json!([
            {"common_name": "sub1.example.com"},
            {"common_name": "sub2.example.com"},
            {"common_name": "example.com"}
        ]);

        let target_domain = "example.com";
        let subdomains = get_subdomains(&sample_json, target_domain).unwrap();

        let mut expected = HashSet::new();
        expected.insert("sub1".to_string());
        expected.insert("sub2".to_string());

        assert_eq!(subdomains, expected);
    }

    #[test]
    fn test_get_subdomains_with_invalid_json() {
        let invalid_json = serde_json::Value::String("invalid".to_string());
        let target_domain = "example.com";
        let result = get_subdomains(&invalid_json, target_domain);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_subdomains_with_empty_json() {
        let sample_json = json!([]);
        let target_domain = "example.com";
        let result = get_subdomains(&sample_json, target_domain);

        assert!(result.unwrap().is_empty());
    }
}
