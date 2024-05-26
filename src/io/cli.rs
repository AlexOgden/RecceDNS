use crate::{
    dns::types::QueryType, io::validate::{validate_dns_resolver_list, validate_domain}
};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

const PROGRESS_TICK_CHARS: &str = "⡿⣟⣯⣷⣾⣽⣻⢿";

/// Command-line arguments for the program
#[derive(Parser, Debug)]
#[command(
	name = "RecceDNS",
    author = "Alex Ogden",
    version = env!("CARGO_PKG_VERSION"),
    about = "DNS Enumeration tool with advanced features",
)]
pub struct CliArgs {
    /// The target base domain name to probe
    #[arg(short, long, required = true, value_parser = validate_domain)]
    pub target_domain: String,

    /// IPv4 Address of the DNS resolver(s) to use (comma-seperated). Multiple resolvers will be randomly selected for each query
    #[arg(short, long, default_value = "1.1.1.1", value_parser = validate_dns_resolver_list, required = false)]
    pub dns_resolvers: String,

    /// Path to subdomain wordlist
    #[arg(short, long, required = true)]
    pub wordlist: String,

    /// Print extra information
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// What resource-record to query
    #[arg(short, long, value_enum, default_value_t = QueryType::Any)]
    pub query_type: QueryType,

    /// Don't show the welcome ASCII art
    #[arg(long)]
    pub no_welcome: bool,

    /// Don't check if the DNS servers are working
    #[arg(long)]
    pub no_dns_check: bool,

    /// Don't print a summary of selected options
    #[arg(long)]
    pub no_print_options: bool,

    /// Print which resolver was used for each query
    #[arg(long)]
    pub show_resolver: bool
}

pub fn get_parsed_args() -> CliArgs {
    CliArgs::parse()
}

pub fn print_options(args: &CliArgs) {
    if args.no_print_options {
        return;
    }
    println!("Starting with options:");
    println!("{}: {}", "domain".bright_blue(), args.target_domain);
    println!("{}: {}", "wordlist".bright_blue(), args.wordlist);
    println!("{}: {}", "records".bright_blue(), args.query_type);
    println!("{}: {}", "resolvers".bright_blue(), args.dns_resolvers);
    println!(
        "{}: {}\n",
        "show-resolver".bright_blue(),
        args.show_resolver
    );
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
    println!("Version: {}\n", env!("CARGO_PKG_VERSION"));
}

pub fn setup_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    let style = ProgressStyle::default_bar()
        .template("{prefix:.bold.dim} {spinner} {wide_msg}")
        .unwrap()
        .tick_chars(PROGRESS_TICK_CHARS);
    pb.set_style(style);
    pb.set_prefix(format!("[{}/{}]", 0, total));
    pb.set_message("Enumerating subdomains...");
    pb
}

pub fn update_progress_bar(pb: &ProgressBar, index: &usize, total: &u64) {
    pb.set_prefix(format!("[{}/{}]", index + 1, total));
    pb.inc(1);
}
