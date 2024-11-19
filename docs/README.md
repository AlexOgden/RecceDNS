# RecceDNS 

RecceDNS is a DNS enumeration/OSINT tool written in Rust 
that provides functionality to gather information about domain names. It performs various DNS queries to discover subdomains, IP addresses, and other DNS records associated with a target domain. The tool is designed to be fast, efficient, and easy to use, leveraging the performance benefits of Rust.

I originally started working on this project to learn Rust, improve on network programming, and gain a deeper understanding of DNS. This software includes its own stub resolver built from scratch, it is not a fully-featured DNS implementation and only supports the functionality required of it.

### Features

- Enumerate the following DNS records:
	- `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`
- Check if domain is using DNSSEC.
- Check for wildcard domains.
- Check resolver(s) for NXDOMAIN hijacking.
- Support for multiple resolvers.
	- Select sequentially or randomly.
- Support for both `UDP` and `TCP`.
- Bruteforce subdomains with a wordlist.
	- Show the resource record data for each subdomain or simply just show the domain.
	- Retry failed queries. If a query fails for networking/protocol issues, retry at the end of enumeration or disable.
	- Use an optional delay between queries.
- SRV enumeration, use a wordlist with the query argument set to SRV to find common SRV records.
- Coloured output with progress reporting on bruteforce subdomain enumeration.

## Cloning and Building

To clone the repository and build the software, follow these steps:

1. **Clone the repository**:
	```sh
	git clone git@github.com:AlexOgden/RecceDNS.git
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

## Arguments

- `-m, --mode <MODE>`: The operation mode to run, bruteforce subdomains or enumerate records. Possible values are:
  - `b`: Basic Enumeration
  - `s`: Subdomain Enumeration

- `-t, --target-domain <TARGET_DOMAIN>`: The target base domain name to probe.

- `-d, --dns-resolvers <DNS_RESOLVERS>`: IPv4 Address of the DNS resolver(s) to use (comma-separated). Multiple resolvers will be selected either randomly or sequentially based on the presence of `-r`. Default is `1.1.1.1`.

- `-p, --transport-protocol <TRANSPORT_PROTOCOL>`: *OPTIONAL*: Transport protocol to use for DNS queries. Possible values are:
  - `UDP`: **(default)**
  - `TCP`

- `-w, --wordlist <WORDLIST>`: Path to subdomain wordlist. Required for enumeration mode.

- `-v, --verbose`: Print extra information. Default is `false`.

- `-q, --query-type <QUERY_TYPE>`: What resource-record to query. Possible values are: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `ANY` (default). When using subdomain enumeration, `ANY` will use `A`, `AAAA`, `MX`, `TXT`.

- `--no-welcome`: Don't show the welcome ASCII art.

- `--no-dns-check`: Don't check if the DNS servers are working before starting.

- `--no-retry`: Don't retry failed queries.

- `--no-print-records`: Don't print the DNS records in subdomain enumeration, only show the subdomains.

- `--show-resolver`: Print which resolver was used for each query.

- `--delay <MS|RANGE>`: Delay in milliseconds to use between queries in subdomain enumeration. You can specify a single value (e.g., `1000` for a 1-second delay) or a range (e.g., `100-200` for a random delay between 100 and 200 milliseconds). Default: `0`

- `-r` `--use-random`: When multiple resolvers are provided, randomly select from the list on each query in enumeration.

## Example Usage

#### Basic Enumeration

`reccedns -m b -d 1.1.1.1 -t github.com`

#### Bruteforce Subdomains

Any Records

`reccedns -m s -d 1.1.1.1 -q any -w .\subdomains-top1million-5000.txt -t github.com`

A (IPv4) Only

`reccedns -m s -d 1.1.1.1 -q a -w .\subdomains-top1million-5000.txt -t github.com`

SRV enumeration

`reccedns -m s -d 1.1.1.1 -q srv -w .\srv_names.txt -t github.com`

Multiple Resolvers - Sequential Selection

`reccedns -m s -d 1.1.1.1,9.9.9.9,8.8.8.8 -q a -w .\subdomains-top1million-5000.txt -t github.com`

Multiple Resolvers - Random Selection

`reccedns -m s -d 1.1.1.1,9.9.9.9,8.8.8.8 --use-random ---show-resolver -q a -w .\subdomains-top1million-5000.txt -t github.com`

With consistent delay

`reccedns -m s -d 1.1.1.1 -q a -w .\subdomains-top1million-5000.txt -t github.com --delay 50`

With random-range delay

`reccedns -m s -d 1.1.1.1 -q a -w .\subdomains-top1million-5000.txt -t github.com --delay 50-900`