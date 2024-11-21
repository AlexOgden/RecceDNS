use crate::{dns::protocol::QueryType, network::types::TransportProtocol, timing::delay::Delay};
use clap::{Parser, ValueEnum};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

use super::validate::{self, dns_resolver_list};

const PROGRESS_TICK_CHARS: &str = "⡈⠔⠢⢁";

/// Command-line arguments for the program
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
#[command(
	name = "RecceDNS",
    author = "Alex Ogden",
    version = env!("CARGO_PKG_VERSION"),
    about = "A DNS reconnaissance tool for enumerating subdomains and DNS records",
)]
pub struct CommandArgs {
    /// The operation mode to run, bruteforce subdomains or enumerate records
    #[arg(short = 'm', long = "mode", required = true)]
    pub operation_mode: OperationMode,

    /// The target base domain name to probe
    #[arg(short, long, required = true, value_parser = validate::domain)]
    pub target_domain: String,

    /// IPv4 Address of the DNS resolver(s) to use (comma-seperated). Multiple resolvers will selected either randomly or sequentially
    #[arg(short, long, default_value = "1.1.1.1", value_parser = dns_resolver_list, required = false)]
    pub dns_resolvers: String,

    /// Transport protocol to use for DNS queries
    #[arg(short = 'p', long, value_enum, default_value_t = TransportProtocol::UDP, required = false)]
    pub transport_protocol: TransportProtocol,

    /// Path to subdomain wordlist
    #[arg(short, long, required = false)]
    pub wordlist: Option<String>,

    /// Print extra information
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// What resource-record to query
    #[arg(short, long, value_enum, default_value_t = QueryType::ANY)]
    pub query_type: QueryType,

    /// Output format to use for results output
    /// Options: json, csv
    #[arg(long, value_enum, required = false)]
    pub output_format: Option<OutputFormat>,

    /// Name of output file to write results to
    #[arg(long, required = false)]
    pub output_file: Option<String>,

    /// Don't show the welcome ASCII art
    #[arg(long)]
    pub no_welcome: bool,

    /// Don't check if the DNS servers are working
    #[arg(long)]
    pub no_dns_check: bool,

    /// Don't retry failed queries
    #[arg(long)]
    pub no_retry: bool,

    /// Don't print the DNS records in subdomain enumeration, only show the subdomains
    #[arg(long)]
    pub no_print_records: bool,

    /// Don't calculate average query time and print it at the end
    #[arg(long)]
    pub no_query_stats: bool,

    /// Print which resolver was used for each query
    #[arg(long)]
    pub show_resolver: bool,

    /// Delay in milliseconds between DNS requests for subdomain enumeration
    #[arg(long, required = false, value_parser = parse_delay)]
    pub delay: Option<Delay>,

    /// Use a random resolver for each query, otherwise use them sequentially
    #[arg(short = 'r', long, required = false, default_value_t = false)]
    pub use_random: bool,
}

impl CommandArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.operation_mode == OperationMode::SubdomainEnumeration && self.wordlist.is_none() {
            return Err("The argument '--wordlist <WORDLIST>' is required when the operation mode is 'subdomain'".to_string());
        }
        Ok(())
    }
}

fn parse_delay(s: &str) -> Result<Delay, String> {
    s.parse()
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum OperationMode {
    #[value(name = "b")]
    BasicEnumeration,
    #[value(name = "s")]
    SubdomainEnumeration,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    #[value(name = "json")]
    Json,
    #[value(name = "csv")]
    Csv,
}

pub fn get_parsed_args() -> CommandArgs {
    let args = CommandArgs::parse();
    if let Err(e) = args.validate() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    args
}

pub fn print_ascii_art() {
    let title_art = r"
    ____                      ____  _   _______
   / __ \___  _____________  / __ \/ | / / ___/
  / /_/ / _ \/ ___/ ___/ _ \/ / / /  |/ /\__ \ 
 / _, _/  __/ /__/ /__/  __/ /_/ / /|  /___/ / 
/_/ |_|\___/\___/\___/\___/_____/_/ |_//____/                                               
";
    println!("{}", title_art.cyan());
    println!(
        "Version: {} | github.com/AlexOgden/RecceDNS\n",
        env!("CARGO_PKG_VERSION")
    );
}

pub fn setup_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    let style = ProgressStyle::default_bar()
        .template("{prefix:.bold.dim} {spinner:.cyan} {wide_msg:.white} [{bar:50.cyan/blue}] ETA {eta:.bold}")
        .unwrap()
        .progress_chars("##-")
        .tick_chars(PROGRESS_TICK_CHARS);
    pb.set_style(style);
    pb.set_prefix(format!("[{}/{}]", 0, total));
    pb.set_message("Enumerating...");
    pb
}

pub fn update_progress_bar(pb: &ProgressBar, index: usize, total: u64) {
    pb.set_prefix(format!("[{}/{}]", index + 1, total));
    pb.inc(1);
}
