use std::collections::HashSet;

use crate::io::cli::CommandArgs;
use anyhow::Result;
use colored::Colorize;

const CRTSH_URL: &str = "https://crt.sh/json?q=";

pub fn search_certificates(cmd_args: &CommandArgs) -> Result<()> {
    println!(
        "Searching subdomain certificates for target domain: {}\n",
        cmd_args.target.bold().bright_blue()
    );

    let target_domain = cmd_args.target.as_str();
    let api_response = get_results_json(target_domain);

    match api_response {
        Ok(data) => {
            let subdomains = get_subdomains(&data, target_domain)?;

            for subdomain in &subdomains {
                println!("[{}] {}.{}", "+".green(), subdomain, target_domain);
            }

            println!(
                "\n[{}] Found {} subdomains for target domain: {}",
                "+".green(),
                subdomains.len(),
                target_domain
            );

            Ok(())
        }
        Err(error) => {
            eprintln!("[{}] API Request failed! {}", "!".red(), error);
            Err(error)
        }
    }
}

fn get_results_json(target_domain: &str) -> Result<serde_json::Value> {
    let url = format!("{CRTSH_URL}{target_domain}");

    let response = reqwest::blocking::get(&url)?;
    let json: serde_json::Value = response.json()?;

    if json.as_array().map_or(true, Vec::is_empty) {
        return Err(anyhow::anyhow!("Received empty JSON data"));
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
