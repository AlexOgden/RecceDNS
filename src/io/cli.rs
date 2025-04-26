use std::time::Duration;

use clap::{Parser, ValueEnum};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

use super::validation::{self, validate_dns_resolvers};
use crate::{dns::protocol::QueryType, network::types::TransportProtocol, timing::delay::Delay};

const PROGRESS_TICK_CHARS: &str = "/|\\- ";

/// Operation modes for the program
#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum OperationMode {
    #[value(name = "b")]
    BasicEnumeration,
    #[value(name = "s")]
    SubdomainEnumeration,
    #[value(name = "r")]
    ReverseIp,
    #[value(name = "c")]
    CertSearch,
    #[value(name = "t")]
    TldExpansion,
}

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
    #[arg(short = 'm', long = "mode", required = true, env = "RECCEDNS_MODE")]
    pub operation_mode: OperationMode,

    /// The target base domain name or IP address (single, CIDR, or range)
    #[arg(short, long, required = true, value_parser = validation::validate_target, env = "RECCEDNS_TARGET")]
    pub target: String,

    /// IPv4 Address of the DNS resolver(s) to use (comma-separated). Multiple resolvers will be selected either randomly or sequentially
    #[arg(short, long, value_parser = validate_dns_resolvers, required = false, env = "RECCEDNS_DNS_RESOLVERS")]
    pub dns_resolvers: String,

    /// Transport protocol to use for DNS queries
    #[arg(short = 'p', long = "protocol", value_enum, default_value_t = TransportProtocol::UDP, required = false, ignore_case = true, env = "RECCEDNS_PROTOCOL")]
    pub transport_protocol: TransportProtocol,

    /// Path to subdomain wordlist
    #[arg(short, long, required = false, env = "RECCEDNS_WORDLIST")]
    pub wordlist: Option<String>,

    /// Print extra information
    #[arg(short, long, default_value_t = false, env = "RECCEDNS_VERBOSE")]
    pub verbose: bool,

    /// Query type(s) to use for DNS queries
    #[arg(
        short,
        long,
        value_enum,
        value_delimiter = ',',
        default_values_t = vec![QueryType::ANY],
        ignore_case = true,
        env = "RECCEDNS_QUERY_TYPES"
    )]
    pub query_types: Vec<QueryType>,

    /// Delay in milliseconds between DNS requests for subdomain enumeration. Fixed value, range, or adaptive delay.
    /// Fixed: '1000', Range: '500-1000', Adaptive: 'A:500-1000', or default adaptive delay: 'A'
    #[arg(short = 'D', long, required = false, value_parser = parse_delay, env = "RECCEDNS_DELAY")]
    pub delay: Option<Delay>,

    /// Number of threads to use for subdomain enumeration
    /// Default is the number of logical CPUs minus one
    #[arg(short = 'T', long, required = false, env = "RECCEDNS_THREADS")]
    pub threads: Option<usize>,

    /// Use a random resolver for each query, otherwise use them sequentially
    #[arg(
        short = 'r',
        long,
        required = false,
        default_value_t = false,
        env = "RECCEDNS_USE_RANDOM"
    )]
    pub use_random: bool,

    /// Path of output file to write JSON results to. Extension is optional.
    #[arg(long, required = false, env = "RECCEDNS_JSON_OUTPUT")]
    pub json: Option<String>,

    /// Don't print results to the console, only write to the output file
    #[arg(short = 'Q', long, required = false, env = "RECCEDNS_QUIET")]
    pub quiet: bool,

    /// Don't show the welcome ASCII art
    #[arg(long, env = "RECCEDNS_NO_WELCOME")]
    pub no_welcome: bool,

    /// Don't check if the DNS servers are working
    #[arg(long, env = "RECCEDNS_NO_DNS_CHECK")]
    pub no_dns_check: bool,

    /// Don't request recursion in DNS queries
    #[arg(long, env = "RECCEDNS_NO_RECURSION")]
    pub no_recursion: bool,

    /// Don't retry failed queries
    #[arg(long, env = "RECCEDNS_NO_RETRY")]
    pub no_retry: bool,

    /// Don't print the DNS records in subdomain enumeration, only show the subdomains
    #[arg(long, env = "RECCEDNS_NO_PRINT_RECORDS")]
    pub no_print_records: bool,

    /// Don't print errors for failed queries during subdomain enumeration
    #[arg(long, env = "RECCEDNS_NO_PRINT_ERRORS")]
    pub no_print_errors: bool,

    /// Don't calculate average query time and print it at the end
    #[arg(long, env = "RECCEDNS_NO_QUERY_STATS")]
    pub no_query_stats: bool,

    /// Print which resolver was used for each query
    #[arg(long, env = "RECCEDNS_SHOW_RESOLVER")]
    pub show_resolver: bool,
}

impl CommandArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.operation_mode == OperationMode::SubdomainEnumeration && self.wordlist.is_none() {
            return Err("The argument '--wordlist <WORDLIST>' is required when the operation mode is 'subdomain'".to_string());
        }

        if self.quiet && self.json.is_none() {
            return Err("The argument '--quiet' requires '--json <OUTPUT_FILE>'".to_string());
        }

        Ok(())
    }
}

/// Parses delay from a string
fn parse_delay(s: &str) -> Result<Delay, String> {
    s.parse()
}

/// Retrieves and validates the parsed command-line arguments
pub fn get_parsed_args() -> CommandArgs {
    let args = CommandArgs::parse();
    if let Err(e) = args.validate() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    args
}

/// Prints the ASCII art banner
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

/// Sets up the progress bar with the given total
#[allow(clippy::literal_string_with_formatting_args)]
pub fn setup_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    let style = ProgressStyle::default_bar()
        .template("[{spinner:.cyan}] {prefix:.bold} {wide_msg:.white} [{bar:50.cyan/blue}] ETA {eta:.bold}")
        .unwrap()
        .progress_chars("##-")
        .tick_chars(PROGRESS_TICK_CHARS);
    pb.set_style(style);
    pb.set_prefix(format!("[{}/{}]", 0, total));
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

// Sets up a basic spinner progress bar
pub fn setup_basic_spinner() -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("[{spinner:.cyan}] Fetching...")
            .expect("Invalid template")
            .tick_chars("/|\\- "),
    );
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner
}

pub fn update_progress_bar(
    pb: &ProgressBar,
    index: usize,
    total: u64,
    failed_count: Option<usize>,
    delay: Option<&Delay>,
) {
    // Set message based on delay
    if let Some(d) = delay {
        let delay_str = format!("{}ms", d.get_delay());
        pb.set_message(format!("[Delay: {delay_str}]"));
    } else {
        // Clear message if no delay is provided
        pb.set_message("");
    }

    // Set prefix with failed count
    let failed_count = failed_count.unwrap_or(0);
    let failed_str = if failed_count > 0 {
        format!("[{}]", failed_count.to_string().red())
    } else {
        String::new()
    };
    pb.set_prefix(format!("[{}/{}] {}", index + 1, total, failed_str));

    // Increment progress bar
    pb.inc(1);
}
