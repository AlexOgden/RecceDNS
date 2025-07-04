<p align="center">
	<h1 align="center" style="font-size:3em;">RecceDNS</h1>
</p>
<p align="center">
	<a title="Build Status" target="_blank" href="https://github.com/AlexOgden/RecceDNS/actions/workflows/cargo_test.yml"><img src="https://img.shields.io/github/actions/workflow/status/tursodatabase/limbo/rust.yml?style=flat-square"></a>
	<a title="Latest Release" target="_blank" href="https://github.com/AlexOgden/RecceDNS/releases/latest"><img src="https://img.shields.io/github/v/release/AlexOgden/RecceDNS?style=flat-square&color=aqua"></a>
	<a title="GitHub Commits" target="_blank" href="https://github.com/AlexOgden/RecceDNS/commits/master"><img src="https://img.shields.io/github/commit-activity/m/AlexOgden/RecceDNS.svg?style=flat-square"></a>
	<a title="Last Commit" target="_blank" href="https://github.com/AlexOgden/RecceDNS/commits/master"><img src="https://img.shields.io/github/last-commit/AlexOgden/RecceDNS.svg?style=flat-square&color=FF9900"></a>
</p>

---

RecceDNS is a DNS enumeration/OSINT tool written in Rust 
that provides functionality to gather information about domain names. It performs various DNS queries to discover subdomains, IP addresses, and other DNS records associated with a target domain. The tool is designed to be fast, efficient, and easy to use. This tool places emphasis on high-performance subdomain bruteforcing with advanced functionality for rapid enumeration and rate limiting mitigation.

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
	- Use an optional delay between queries (Fixed, Random Range, and Adaptive).
- SRV enumeration, use a wordlist with the query argument set to SRV to find common SRV records.
- Reverse IP PTR for a single IP address, CIDR notation, range, or list.
- Search for subdomains based Certificate Transparency using crt.sh.
- Expland TLD enumeration for a given domain on the full IANA TLD list.
- Coloured output with progress reporting on bruteforce subdomain enumeration.
- Output results to a JSON file.
- High Performance Features:
	- Multi-Threaded bruteforce enumeration.
	- Use multiple DNS resolvers.
	- Dynamically disable resolver for random time if rate limited.
	- Adaptive delay (increases and decreases dynamically within bounds to reduce rate-limiting).
	- Asyncronous UDP socket pooling - thousands of queries without locking up file resources.

## Getting Started

<details>
<summary>🔨 Cloning and Building from Source</summary>

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

</details>

<details>
<summary>📦 Pre-Built Binaries</summary>

Pre-built binaries are available in the [releases](https://github.com/AlexOgden/RecceDNS/releases) section for the following platforms:

- Windows (x86_64)
- macOS (x86_64, arm64)
- Linux (x86_64, arm64, armv7)

You can download these binaries directly from the releases page without building from source.

</details>
<details>
<summary>🐳 Docker Images</summary>

Official Docker images are available:

**Usage Examples:**

```sh
docker pull ghcr.io/alexogden/reccedns:latest
docker run --rm -it ghcr.io/alexogden/reccedns:latest -m c -d 1.1.1.1 -t github.com
```

See the [releases](https://github.com/AlexOgden/RecceDNS/releases) page for the latest versions.
</details>

## Arguments

> All command-line arguments can also be set using environment variables.  
> **CLI arguments always take precedence over environment variables.**


| Argument | Environment Variable | Description |
|----------|---------------------|-------------|
| `-m, --mode <MODE>` | `RECCEDNS_MODE` | **Operation mode**. Possible values:<br>• `b`: Basic Enumeration<br>• `s`: Subdomain Enumeration<br>• `r`: Reverse PTR IP<br>• `c`: Certificate Search<br>• `t`: TLD Expansion |
| `-t, --target <TARGET>` | `RECCEDNS_TARGET` | **Target base domain or IP** (single, CIDR, or range).<br>Examples: `google.com`, `192.168.2.3`, `192.168.2.0/24`, `192.168.2.1-192.168.2.230`, `192.168.0.1,192.168.0.4` |
| `-d, --dns-resolvers <DNS_RESOLVERS>` | `RECCEDNS_DNS_RESOLVERS` | **DNS resolver(s)** (IPv4, comma-separated, or file path).<br>Default: `1.1.1.1`.<br>You can provide a comma-separated list of IPv4 addresses, or a path to a file containing resolvers (one per line and/or CSV). Multiple resolvers can be selected randomly or sequentially (see `-r`). |
| `-p, --protocol <TRANSPORT_PROTOCOL>` | `RECCEDNS_PROTOCOL` | *(Optional)* **Transport protocol** for DNS queries.<br>Values: `UDP` (default), `TCP` |
| `-w, --wordlist <WORDLIST>` | `RECCEDNS_WORDLIST` | **Path to subdomain wordlist**. Required for enumeration mode. |
| `-v, --verbose` | `RECCEDNS_VERBOSE` | Print extra information. Default: `false` |
| `-q, --query-types <QUERY_TYPE>` | `RECCEDNS_QUERY_TYPES` | **Resource-record(s) to query**.<br>Values: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `ANY` (default).<br>Comma-separated list. Not all types available in every mode. |
| `--no-welcome` | `RECCEDNS_NO_WELCOME` | Don't show the welcome ASCII art. |
| `--no-dns-check` | `RECCEDNS_NO_DNS_CHECK` | Don't check if DNS servers are working before starting. |
| `--no-recursion` | `RECCEDNS_NO_RECURSION` | Set recursion-desired to false in DNS queries. |
| `--no-retry` | `RECCEDNS_NO_RETRY` | Don't retry failed queries. |
| `--no-print-records` | `RECCEDNS_NO_PRINT_RECORDS` | Don't print DNS records in subdomain enumeration (show only subdomains). |
| `--no-query-stats` | `RECCEDNS_NO_QUERY_STATS` | Don't calculate/print average query time. |
| `--no-print-errors` | `RECCEDNS_NO_PRINT_ERRORS` | Don't print failed queries during subdomain enumeration (errors still show on retry). Use `-Q` to silence all output. |
| `--show-resolver` | `RECCEDNS_SHOW_RESOLVER` | Print which resolver was used for each query. |
| `-D, --delay <MS\|RANGE\|ADAPTIVE>` | `RECCEDNS_DELAY` | **Delay between queries** (subdomain enumeration).<br>• Fixed: <code>1000</code> (ms)<br>• Range: <code>100-200</code> (random ms)<br>• Adaptive: <code>A</code> or <code>A:10-750</code> (dynamic, <code>A</code> alone uses <code>10-500</code> as the default range) |
| `-r, --use-random` | `RECCEDNS_USE_RANDOM` | When multiple resolvers are provided, randomly select one for each query. |
| `--json <path>` | `RECCEDNS_JSON_OUTPUT` | Output results to a JSON file. `.json` will be appended if not provided. |
| `-Q, --quiet` | `RECCEDNS_QUIET` | Don't print any results to the terminal. Useful for large targets when outputting to JSON. |
| `-T, --threads <N>` | `RECCEDNS_THREADS` | Number of threads for subdomain enumeration.<br>Defaults to (logical cores - 1), max 6 if more than 6 cores. |

## Example Usage

### Basic Enumeration

```sh
reccedns -m b -d 1.1.1.1 -t github.com
```

### Bruteforce Subdomains

**Any Records**
```sh
reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com
```

**A (IPv4) Only**
```sh
reccedns -m s -d 1.1.1.1 -q a -w .\subdomains-top1million-5000.txt -t github.com
```

**SRV Enumeration**
```sh
reccedns -m s -d 1.1.1.1 -q srv -w .\srv_names.txt -t github.com
```

**Multiple Resolvers - Sequential Selection**
```sh
reccedns -m s -d 1.1.1.1,9.9.9.9,8.8.8.8 -q a,aaaa -w .\subdomains-top1million-5000.txt -t github.com
```

**Multiple Resolvers - Random Selection**
```sh
reccedns -m s -d 1.1.1.1,9.9.9.9,8.8.8.8 --use-random --show-resolver -q a -w .\subdomains-top1million-5000.txt -t github.com
```

**With Consistent Delay**
```sh
reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com --delay 50
```

**With Random-Range Delay**
```sh
reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com --delay 50-900
```

**With Adaptive Delay**
```sh
reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com --delay A:5-750
```

**With Specified Thread Count**
```sh
reccedns -m s -d 1.1.1.1 -w .\subdomains-top1million-5000.txt -t github.com -T 6
```

**Output to JSON**
```sh
reccedns -m s -d 1.1.1.1 -w .\combined_names.txt -t github.com -T 6 -q A,AAAA,MX --json query_output
```

**Don't Print Errors During Enumeration (still prints on retry)**
```sh
reccedns -m s -d 8.8.8.8 -w .\combined_names -t github.com -T 4 --no-print-errors
```

---

### Reverse PTR IP Search

**Single IP Address**
```sh
reccedns -m r -d 1.1.1.1 -t 192.168.0.1
```

**CIDR Notation**
```sh
reccedns -m r -d 1.1.1.1 -t 192.168.0.0/24
```

**IP Range**
```sh
reccedns -m r -d 1.1.1.1 -t 192.168.0.0-192.168.1.254
```

**IP List**
```sh
reccedns -m r -d 1.1.1.1 -t 192.168.0.1,192.168.0.3,192.168.1.54
```

---

### Certificate Search

```sh
reccedns -m c -t github.com
```

---

### TLD Expansion

**Check 'github' with the full list of IANA TLDs**
```sh
reccedns -m t -d 8.8.8.8 -t github.com
```

**Don't Print the Actual DNS Records**
```sh
reccedns -m t -d 8.8.8.8 -t github.com --no-print-records
```

**Only Check Using `A` Records**
```sh
reccedns -m t -d 8.8.8.8 -t github.com -q a
```

**Check with `A` and `AAAA`**
```sh
reccedns -m t -d 8.8.8.8 -t github.com -q a,aaaa
```

**Provide a Wordlist with TLDs**
```sh
reccedns -m t -d 8.8.8.8 -t github.com -w tlds.txt
```
