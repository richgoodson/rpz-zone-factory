# rpz-zone-factory

Threat intelligence pipeline for DNS. Fetches from 5 public feeds, builds RFC 5782 RPZ zone files for BIND, and optionally outputs Pi-hole flat blocklists.

## How It Works

Two shell scripts handle all operations:

- **`run-rpz.sh`** — the main orchestrator. Manages the Python venv, runs the pipeline, validates zones with `named-checkzone`, and reloads BIND. Run it from cron or interactively. One-time `--setup` wizard configures everything.
- **`allow.sh`** — real-time allowlist management. Adds or removes domains from the RPZ allowlist zone via TSIG-authenticated `nsupdate`, with an append-only audit log.

The Python engine (`rpz_factory/`) does the actual fetching, parsing, filtering, and zone rendering. The shell scripts call it — you don't need to invoke Python directly.

See [README-runner.md](README-runner.md) for full `run-rpz.sh` and `allow.sh` documentation.

## Quick Start

```sh
# Clone
git clone https://github.com/richgoodson/rpz-zone-factory.git
cd rpz-zone-factory

# Run the setup wizard (creates venv, installs deps, configures output/reload/validation)
./run-rpz.sh --setup

# Test interactively
./run-rpz.sh -i

# Add to cron (the wizard generates the entry for you)
crontab -e
```

### Cron examples

```cron
# Per-source RPZ zones for BIND, every 4 hours
15 */4 * * * /opt/rpz-zone-factory/run-rpz.sh

# Pi-hole flat file, daily at 3:05 AM
5 3 * * * /opt/rpz-zone-factory/run-rpz.sh -- --output pihole --output-file /var/www/rpz/block.txt
```

### Dynamic allowlist

```sh
# Allow a domain through RPZ (immediate, TSIG-authenticated)
./allow.sh example.com

# Remove it
./allow.sh -r example.com

# View the audit log
./allow.sh --audit
```

See `./allow.sh --setup` for TSIG key configuration.

## Sources

| Source | Type | URL |
|--------|------|-----|
| Abuse.ch URLhaus | Domains (RPZ feed) | https://urlhaus.abuse.ch/downloads/rpz/ |
| CISA KEV | Domains from CVE data | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| Spamhaus DROP | IP/CIDR | https://www.spamhaus.org/drop/drop.txt |
| Scam Sniffer | Domains (crypto scams) | https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json |
| CryptoScamDB | Domains (crypto phishing) | https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/urls.yaml |

## Requirements

- POSIX shell (`sh`), `cron`, `rndc`, `nsupdate` (for `allow.sh`)
- Python 3.9+ (managed automatically by `run-rpz.sh`)
- `requests` and `pyyaml` (installed into a venv by `run-rpz.sh --setup`)

> **Don't run this as root.** The pipeline needs write access to a few specific paths and read access to BIND credentials, all achievable with group permissions. See [Running as a Non-Root User](README-runner.md#running-as-a-non-root-user) in README-runner.md for the full setup.

## Python Engine Reference

You don't normally invoke the Python CLI directly — `run-rpz.sh` handles it. These are here for reference and debugging.

### Generate RPZ zone file (default)

```bash
python run.py --output rpz --zone-name rpz.local -v
```

### Generate Pi-hole blocklist

```bash
python run.py --output pihole --output-file blocklist.txt -v
```

### Select specific sources

```bash
python run.py --sources urlhaus drop scamsniffer --output rpz
```

### Per-source mode (one zone per threat source)

```bash
python run.py --per-source --output-file /etc/namedb/master/rpz/ -v
```

Creates separate zone files: `urlhaus.rpz.db`, `cisa-kev.rpz.db`, `spamhaus-drop.rpz.db`, `scamsniffer.rpz.db`, `cryptoscamdb.rpz.db`. BIND logs then show which threat list triggered each block.

### Per-source with allowlist

```bash
python run.py --per-source --output-file /etc/namedb/master/rpz/ --allowlist /etc/namedb/master/rpz/allowlist.txt -v
```

The allowlist is a plain text file (one domain per line, `#` comments). It generates `allowlist.rpz.db` with passthru CNAME records to override blocks from other zones.

### All options

```
usage: rpz-zone-factory [-h] [--output {rpz,pihole}] [--zone-name ZONE_NAME]
                        [--output-file OUTPUT_FILE]
                        [--sources {urlhaus,cisa,drop,scamsniffer,cryptoscamdb} ...]
                        [--cache-dir CACHE_DIR] [--per-source]
                        [--allowlist ALLOWLIST]
                        [-v]

  --output {rpz,pihole}     Output format (default: rpz)
  --zone-name ZONE_NAME     RPZ zone name for combined mode (default: rpz.local)
  --output-file OUTPUT_FILE Output file (combined) or directory (per-source)
  --sources                 Sources to fetch (default: all 5)
  --cache-dir CACHE_DIR     Cache directory for stale-data preservation
  --per-source              Output one zone file per source (RPZ only)
  --allowlist ALLOWLIST      Path to allowlist file (generates allowlist.rpz zone)
  -v, --verbose             Increase verbosity (-v INFO, -vv DEBUG)
```

## Features

### Conditional HTTP

All 5 feeds use `If-Modified-Since` / `ETag` headers. When upstream data hasn't changed, the pipeline skips the download and uses cached entries. Metadata is stored in `.cache/*.meta.json`.

### Source Caching

rpz-zone-factory maintains a per-source cache so that if a source is temporarily unavailable, its last-known-good data is preserved instead of being lost entirely.

- **Cache directory:** `{project_dir}/.cache/` by default (override with `--cache-dir`)
- **On successful fetch:** entries are written to `.cache/{source_name}.json`
- **On failed fetch:** the cache is consulted. If a cache file exists, its entries are used and a WARNING is logged with the cache timestamp
- **If no cache exists:** the source simply contributes nothing (same as before)

Cache files are JSON with metadata for auditability:

```json
{
  "source": "scamsniffer",
  "cached_at": "2026-03-30T22:00:00Z",
  "entry_count": 12345,
  "entries": [
    {"value": "domain.com", "entry_type": "domain", "raw_line": "..."}
  ]
}
```

### False Positive Filtering

The pipeline applies rule-based filtering to reduce false positives:

- **Safe TLDs**: `.gov`, `.mil`, `.edu` domains are never blocked
- **Critical allowlist**: ~50 top infrastructure domains (Google, Cloudflare, Amazon, Microsoft, Apple, etc.) are never blocked, including subdomain matching
- **DNS label validation**: Rejects entries with labels >63 characters, paths, or total length >253
- **Deduplication**: Entries are deduplicated across all sources
- All skipped entries are logged with reasons (use `-v` to see)

## BIND Configuration

### Per-source mode (recommended)

Define each zone in `named.conf`:

```bind
// Allowlist zone — evaluated first, passthru overrides blocks
zone "allowlist.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/allowlist.rpz.db";
    allow-query { localhost; };
    allow-transfer { none; };
};

// Threat source zones
zone "urlhaus.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/urlhaus.rpz.db";
    allow-query { localhost; };
    allow-transfer { none; };
};

zone "cisa-kev.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/cisa-kev.rpz.db";
    allow-query { localhost; };
    allow-transfer { none; };
};

zone "spamhaus-drop.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/spamhaus-drop.rpz.db";
    allow-query { localhost; };
    allow-transfer { none; };
};

zone "scamsniffer.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/scamsniffer.rpz.db";
    allow-query { localhost; };
    allow-transfer { none; };
};

zone "cryptoscamdb.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/cryptoscamdb.rpz.db";
    allow-query { localhost; };
    allow-transfer { none; };
};
```

Enable the response policy (inside `options {}`):

```bind
options {
    // ... existing options ...

    response-policy {
        zone "allowlist.rpz" policy passthru;
        zone "urlhaus.rpz";
        zone "cisa-kev.rpz";
        zone "spamhaus-drop.rpz";
        zone "scamsniffer.rpz";
        zone "cryptoscamdb.rpz";
    };
};
```

RPZ zones are evaluated in order. The allowlist zone goes first with `policy passthru` so it can override blocks from subsequent zones.

### Combined mode

If you prefer a single combined zone:

```bind
zone "block.rpz" {
    type primary;
    file "/etc/namedb/master/block.rpz.db";
    allow-query { localhost; };
    allow-transfer { none; };
};

options {
    response-policy {
        zone "block.rpz" policy given;
    };
};
```

### Deployment

```bash
# Per-source: generate all zone files
python run.py --per-source --output-file /etc/namedb/master/rpz/ -v

# Validate a zone
named-checkzone urlhaus.rpz /etc/namedb/master/rpz/urlhaus.rpz.db

# Load new zones for the first time
rndc reconfig

# Subsequent updates only need reload
rndc reload urlhaus.rpz
```

For automated deployment via cron, see the [Quick Start](#quick-start) above and [README-runner.md](README-runner.md) for full `run-rpz.sh` details.

## Pi-hole Configuration

To use the generated blocklist with Pi-hole:

1. Generate the blocklist file:
   ```bash
   python run.py --output pihole --output-file /tmp/rpz-blocklist.txt
   ```

2. In the Pi-hole admin panel:
   - Go to **Group Management** > **Adlists**
   - If hosting the file on a web server, add the URL
   - Or place the file directly and add as a local list:
     ```bash
     cp /tmp/rpz-blocklist.txt /etc/pihole/custom.list
     pihole restartdns
     ```

3. Alternatively, use Pi-hole's `--adlist` import:
   ```bash
   pihole -g  # update gravity after adding the list
   ```

> **Note:** Pi-hole only supports domain-based blocking. IP/CIDR entries from Spamhaus DROP are excluded from Pi-hole output.

## Project Structure

```
rpz-zone-factory/
├── run-rpz.sh          # Main orchestrator (cron/interactive wrapper)
├── allow.sh            # Dynamic allowlist management (TSIG + nsupdate)
├── run.py              # Python CLI entrypoint
├── README.md
├── README-runner.md    # Full run-rpz.sh and allow.sh documentation
├── requirements.txt
├── .run-rpz.conf       # Generated by --setup (not in repo)
├── rpz_factory/
│   ├── __init__.py
│   ├── cli.py          # argparse CLI, conditional HTTP, summary output
│   ├── cache.py        # Per-source cache + HTTP metadata persistence
│   ├── fetcher.py      # HTTP fetch with retry/timeout, If-Modified-Since/ETag
│   ├── filters.py      # False positive filtering logic
│   ├── models.py       # Dataclasses: ThreatEntry, FetchResult, HttpMeta, etc.
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── abusech.py       # Abuse.ch URLhaus RPZ feed parser
│   │   ├── cisa.py          # CISA KEV JSON parser
│   │   ├── cryptoscamdb.py  # CryptoScamDB YAML blacklist parser
│   │   ├── scamsniffer.py   # Scam Sniffer JSON blacklist parser
│   │   └── spamhaus.py      # Spamhaus DROP parser
│   └── renderers/
│       ├── __init__.py
│       ├── rpz.py      # RFC 5782 zone file renderer
│       └── pihole.py   # Flat domain list renderer
├── .cache/             # Per-source cached entries + HTTP metadata (auto-created)
└── allow-audit.log     # Append-only audit log from allow.sh (auto-created)
```
