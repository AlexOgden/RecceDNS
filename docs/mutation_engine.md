# RecceDNS Mutation Engine

The RecceDNS Mutation Engine dynamically generates permutations of newly discovered subdomains on-the-fly. This technique (often called alteration) allows RecceDNS to discover undocumented environments by mutating known valid subdomains with common prefixes and suffixes.

For example, if the standard enumeration wordlist discovers `api.example.com`, the mutator can instantly test variations like:
- `api-dev.example.com`
- `dev-api.example.com`
- `api.dev.example.com`
- `api1.example.com`

## How it works
The mutator uses two components:
1. **Mutation Rules:** Define the syntax for how mutations should be constructed (e.g. `[sub]-[word]`).
2. **Mutation Words:** Define the wordlist to inject into the rules (e.g. `dev`, `staging`, `prod`).

Whenever a subdomain resolves successfully, it is passed into the mutator. The mutator applies all rules and words, spawning new DNS queries instantly. These spawned queries run concurrently with the rest of your wordlist to maximize speed.

## Usage

You can enable the mutation engine using these CLI flags:
- `-M` or `--mutate` (enables built-in defaults)
- `--mutate-rules <FILE>` (custom rules file)
- `--mutate-words <FILE>` (custom wordlist file)

### Built-in Defaults
To use the built-in defaults for both rules and words, just pass the `--mutate` flag:

```sh
reccedns -m s -t example.com -w subdomains.txt --mutate
```

### Custom Rules
Create a text file containing rules. Lines starting with `#` are ignored. 

**Placeholders:**
- `[sub]` is replaced with the discovered subdomain (e.g., `api`).
- `[word]` is replaced by each word in the mutation wordlist.

Example `rules.txt`:
```text
[sub]-[word]
[word]-[sub]
[sub][word]
[sub].[word]
```

### Custom Words
Create a standard wordlist text file.

Example `words.txt`:
```text
dev
prod
staging
v1
v2
test
```

Run with custom rules:
```sh
reccedns -m s -t example.com -w subdomains.txt --mutate-rules rules.txt --mutate-words words.txt
```
