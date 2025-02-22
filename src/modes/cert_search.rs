use std::collections::HashSet;

use crate::{
    io::{
        cli::{self, CommandArgs},
        json::{CertSearchOutput, Output},
    },
    log_error, log_success,
};
use anyhow::Result;
use colored::Colorize;
use lazy_static::lazy_static;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use thiserror::Error;

const CRTSH_URL: &str = "https://crt.sh/json?q=";

lazy_static! {
    static ref HTTP_CLIENT: Client = Client::new();
}

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

    let max_retries = if cmd_args.no_retry { 1 } else { 3 };

    for attempt in 1..=max_retries {
        let spinner = cli::setup_basic_spinner();

        match get_results_json(&HTTP_CLIENT, target_domain).await {
            Ok(data) => {
                spinner.set_message("Searching...");
                let subdomains = get_subdomains(&data, target_domain)?;
                spinner.finish_and_clear();

                for subdomain in &subdomains {
                    log_success!(format!(
                        "{}.{}",
                        subdomain.cyan().bold(),
                        target_domain.blue().italic()
                    ));
                }

                if let Some(output) = &mut results_output {
                    for subdomain in &subdomains {
                        output.add_result(subdomain.clone());
                    }
                }

                log_success!(
                    format!(
                        "Found {} subdomains for target domain: {}",
                        subdomains.len(),
                        target_domain
                    ),
                    true
                );

                if let Some(output) = results_output {
                    let json_path = cmd_args
                        .json
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("JSON output path is missing."))?;
                    output.write_to_file(&json_path)?;
                }
                break;
            }
            Err(error) => {
                spinner.finish_and_clear();
                if attempt < max_retries && matches!(error, SearchError::NonSuccessStatus(_)) {
                    log_error!(format!(
                        "Attempt {}/{} failed: {}. Retrying...",
                        attempt, max_retries, error
                    ));
                    tokio::time::sleep(tokio::time::Duration::from_secs(attempt + 1)).await;
                } else {
                    log_error!(format!(
                        "Attempt {}/{} failed: {}.",
                        attempt, max_retries, error
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn get_results_json(http_client: &Client, target_domain: &str) -> Result<Value, SearchError> {
    let url = format!("{CRTSH_URL}{target_domain}");
    let response = http_client
        .get(&url)
        .send()
        .await
        .map_err(SearchError::HttpRequestError)?;

    if !response.status().is_success() {
        return Err(SearchError::NonSuccessStatus(response.status()));
    }

    let json = response
        .json::<Value>()
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
