use std::{collections::HashSet, sync::LazyLock};

use crate::{
    io::{
        cli::{self, CommandArgs},
        json::{CertSearchOutput, Output},
    },
    log_error, log_success,
};
use anyhow::Result;
use bytes::Bytes;
use colored::Colorize;
use http_body_util::{BodyExt, Empty};
use hyper::{Method, Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde_json::Value;
use thiserror::Error;

const CRTSH_URL: &str = "https://crt.sh/json?q=";

static HTTP_CLIENT: LazyLock<
    Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Empty<Bytes>,
    >,
> = LazyLock::new(|| {
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();

    Client::builder(TokioExecutor::new()).build(https)
});

#[derive(Error, Debug)]
pub enum SearchError {
    #[error("HTTP request failed: {0}")]
    HttpRequestError(String),

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
        spinner.set_message("Searching...");
        match get_results_json(target_domain).await {
            Ok(data) => {
                spinner.set_message("Processing...");
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
                log_error!(format!(
                    "Attempt {}/{} failed: {}. Retrying...",
                    attempt, max_retries, error
                ));
                if attempt < max_retries && matches!(error, SearchError::NonSuccessStatus(_)) {
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

async fn get_results_json(target_domain: &str) -> Result<Value, SearchError> {
    let url = format!("{CRTSH_URL}{target_domain}");
    let request = Request::builder()
        .method(Method::GET)
        .uri(&url)
        .body(Empty::<Bytes>::new())
        .map_err(|e| SearchError::HttpRequestError(e.to_string()))?;

    let response = HTTP_CLIENT
        .request(request)
        .await
        .map_err(|e| SearchError::HttpRequestError(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(SearchError::NonSuccessStatus(status));
    }

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| SearchError::HttpRequestError(e.to_string()))?
        .to_bytes();

    let json: Value = serde_json::from_slice(&body_bytes).map_err(SearchError::JsonParseError)?;

    if json.as_array().is_none_or(std::vec::Vec::is_empty) {
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
