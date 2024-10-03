mod dns;
mod io;
mod modes;

use anyhow::Result;

fn main() -> Result<()> {
    let args = io::cli::get_parsed_args();

    if !args.no_welcome {
        io::cli::print_ascii_art();
        io::cli::print_options(&args);
    }

    modes::subdomain_enumerator::enumerate_subdomains(&args)
}
