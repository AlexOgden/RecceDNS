mod dns;
mod io;

use anyhow::Result;

fn main() -> Result<()> {
    let args = io::cli::get_parsed_args();

    if !args.no_welcome {
        io::cli::print_ascii_art();
        io::cli::print_options(&args);
    }

    dns::enumeration::enumerate_subdomains(&args)
}
