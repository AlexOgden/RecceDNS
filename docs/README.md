# RecceDNS 

RecceDNS is a DNS enumeration/OSINT tool written in Rust 
that provides functionality to gather information about domain names. It performs various DNS queries to discover subdomains, IP addresses, and other DNS records associated with a target domain. The tool is designed to be fast, efficient, and easy to use, leveraging the performance benefits of Rust.

I originally started working on this project to learn Rust, improve on network programming, and gain a deeper understanding of DNS. This software includes its own stub resolver built from scratch, it is not a fully-featured DNS implementation and only supports the functionality required of it. I am still learning/improving my Rust skills, if you're experienced in Rust and think something could be improved, be more idomatic, or any other suggestions, feel free to let me know or submit a pull request!

### Features

- Enumerate the following DNS records:
	- `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `PTR`
- Check if domain is using DNSSEC.
- Check for wildcard domains.
- Check resolver(s) for NXDOMAIN hijacking.
- Support for multiple resolvers.
	- Select sequentially or randomly.
- Support for both `UDP` and `TCP`.
- Bruteforce subdomains with a wordlist.
	- Show the resource record data for each subdomain or simply just show the domain.
	- Retry failed queries. If a query fails for networking/protocol issues, retry at the end of enumeration or disable.
	- Use an optional delay between queries (Fixed, Random Range, and Adaptive)
- SRV enumeration, use a wordlist with the query argument set to SRV to find common SRV records.
- Reverse IP PTR for a single IP address, CIDR notation, or range.
- Search for subdomains based Certificate Transparency using crt.sh.
- Expland TLD enumeration for a given domain on the full IANA TLD list.
- Coloured output with progress reporting on bruteforce subdomain enumeration.
- Output results to a JSON file.
- High Performance Features:
	- Multi-Threaded bruteforce enumeration
	- Use multiple DNS resolvers
	- Dynamically disable resolver for random time if rate limited
	- Adaptive delay (increases and decreases dynamically within bounds to reduce rate-limiting)

## Cloning and Building

To clone the repository and build the software, follow these steps:

1. **Clone the repository**:
	```sh
	git clone --depth 1 git@github.com:AlexOgden/RecceDNS.git
	cd reccedns
	```

2. **Build the project**:
	Ensure you have Rust installed. If not, you can install it from [rust-lang.org](https://www.rust-lang.org/).

	```sh
	cargo build --release
	```

3. **Run the tests** (optional):
	```sh
	cargo test
	```

After building, you can find the executable in the `target/release` directory.

## Pre-Built Binaries

Pre-built binaries are available in the releases section for the following platforms:

- Windows (x86_64)
- macOS (x86_64, arm64)
- Linux (x86_64, arm64, armv7)

You can download these binaries directly from the releases page without having to build from source.

## Arguments

- `-m, --mode <MODE>`: The operation mode to run, bruteforce subdomains or enumerate records. Possible values are:
  - `b`: Basic Enumeration
  - `s`: Subdomain Enumeration
  - `r`: Reverse PTR IP
  - `c`: Certificate Search
  - `t`: TLD Expansion

- `-t, --target <TARGET>`: The target base domain name or IP address (single, CIDR, or range). Examples: `google.com`, `192.168.2.3`, `192.168.2.0/24`, `192.168.2.1-192.168.2.230`.

- `-d, --dns-resolvers <DNS_RESOLVERS>`: IPv4 Address of the DNS resolver(s) to use (comma-separated). Multiple resolvers will be selected either randomly or sequentially based on the presence of `-r`. Default is `1.1.1.1`.

- `-p, --protocol <TRANSPORT_PROTOCOL>`: *OPTIONAL*: Transport protocol to use for DNS queries. Possible values are:
  - `UDP`: **(default)**
  - `TCP`

- `-w, --wordlist <WORDLIST>`: Path to subdomain wordlist. Required for enumeration mode.

- `-v, --verbose`: Print extra information. Default is `false`.

- `-q, --query-types <QUERY_TYPE>`: What resource-record(s) to query. Possible values are: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `ANY` (default). Accepts a comma-seperated list. Not every query type is available for each mode.

- `--no-welcome`: Don't show the welcome ASCII art.

- `--no-dns-check`: Don't check if the DNS servers are working before starting.

- `--no-recursion`: Sets recursion-desired to false in DNS queries.

- `--no-retry`: Don't retry failed queries.

- `--no-print-records`: Don't print the DNS records in subdomain enumeration, only show the subdomains.

- `--no-query-stats`: Don't calculate and print the average query time.

- `--no-print-errors`: Don't print failed queries during subdomain enumeration. Errors will still show when failed queries are retried. To silence all output, use `-Q`.

- `--show-resolver`: Print which resolver was used for each query.

- `-D` `--delay <MS|RANGE|ADAPTIVE>`: Delay in milliseconds to use between queries in subdomain enumeration. You can specify a fixed value (e.g., `1000` for a 1-second delay) or a range (e.g., `100-200` for a random delay between 100 and 200 milliseconds), or use the dynamic adaptive mode: default `A` or specify a min and max: `A:10-750`.

- `-r` `--use-random`: When multiple resolvers are provided, randomly select from the list on each query in enumeration.

- `--json <path>` : Output the results to a JSON file. '.json' will be appended as the extension is not provided.

- `-Q` `--quiet` : Don't print any results to the terminal. Can be useful for targets with large amount of results that you are outputing to JSON.

- `-T` `--threads` : Number of threads to use for subdomain enumeration. Defaults to logical cores - 1.

## Example Usage

### Basic Enumeration

`reccedns -m b -d 1.1.1.1 -t github.com`

### Bruteforce Subdomains

Any Records

`reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com`

A (IPv4) Only

`reccedns -m s -d 1.1.1.1 -q a -w .\subdomains-top1million-5000.txt -t github.com`

SRV enumeration

`reccedns -m s -d 1.1.1.1 -q srv -w .\srv_names.txt -t github.com`

Multiple Resolvers - Sequential Selection

`reccedns -m s -d 1.1.1.1,9.9.9.9,8.8.8.8 -q a,aaaa -w .\subdomains-top1million-5000.txt -t github.com`

Multiple Resolvers - Random Selection

`reccedns -m s -d 1.1.1.1,9.9.9.9,8.8.8.8 --use-random ---show-resolver -q a -w .\subdomains-top1million-5000.txt -t github.com`

With consistent delay

`reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com --delay 50`

With random-range delay

`reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com --delay 50-900`

With adaptive delay

`reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com --delay A:5-750`

With specified thread count

`reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com -T 6`

### Reverse PTR IP Search

Single IP Address

`reccedns -m r -d 1.1.1.1 -t 192.168.0.1`

CIDR Notation

`reccedns -m r -d 1.1.1.1 -t 192.168.0.0/24`

IP Range

`reccedns -m r -d 1.1.1.1 -t 192.168.0.0-192.168.1.254`

### Certificate Search

`reccedns -m c -t github.com`

### TLD Expansion

Check 'github' with the full list of IANA TLDs

`reccedns -m t -d 8.8.8.8 -t github.com`

Don't print the actual DNS records

`reccedns -m t -d 8.8.8.8 -t github.com --no-print-records`

Only check using `A` records

`reccedns -m t -d 8.8.8.8 -t github.com -q a`

Check with `A` and `AAAA`

`reccedns -m t -d 8.8.8.8 -t github.com -q a,aaaa`

Provide a wordlist with TLDs

`reccedns -m t -d 8.8.8.8 -t github.com -w tlds.txt`