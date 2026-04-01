# rpz-zone-factory

A CLI pipeline that fetches threat intelligence from multiple sources and outputs either RFC 5782 RPZ zone files (for BIND/authoritative DNS servers) or Pi-hole flat blocklist format.

## Sources

| Source | Type | URL |
|--------|------|-----|
| Abuse.ch URLhaus | Domains (RPZ feed) | https://urlhaus.abuse.ch/downloads/rpz/ |
| CISA KEV | Domains from CVE data | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| Spamhaus DROP | IP/CIDR | https://www.spamhaus.org/drop/drop.txt |
| Scam Sniffer | Domains (crypto scams) | https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json |
| CryptoScamDB | Domains (crypto phishing) | https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/urls.yaml |

## Requirements

- Python 3.9+
- `requests` library
- `pyyaml` library (for CryptoScamDB YAML feed)

```bash
pip install -r requirements.txt
```

## Usage

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

This creates separate zone files: `urlhaus.rpz.db`, `cisa-kev.rpz.db`, `spamhaus-drop.rpz.db`, `scamsniffer.rpz.db`, `cryptoscamdb.rpz.db`. BIND logs then show which threat list triggered each block.

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

## Source Caching

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

## False Positive Filtering

The pipeline applies rule-based filtering to reduce false positives:

- **Safe TLDs**: `.gov`, `.mil`, `.edu` domains are never blocked
- **Critical allowlist**: ~50 top infrastructure domains (Google, Cloudflare, Amazon, Microsoft, Apple, etc.) are never blocked, including subdomain matching
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

For automated deployment, use `run-rpz.sh` (see [README-runner.md](README-runner.md)):

```cron
15 */4 * * * /opt/rpz-zone-factory/run-rpz.sh
```

`run-rpz.sh` handles venv management, per-zone `named-checkzone` validation, and `rndc reload` for each zone automatically. Run `./run-rpz.sh --setup` for interactive configuration.

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
├── README.md
├── README-runner.md
├── requirements.txt
├── run.py
├── run-rpz.sh
├── rpz_factory/
│   ├── __init__.py
│   ├── cli.py          # argparse CLI entrypoint
│   ├── cache.py        # per-source cache for stale-data preservation
│   ├── fetcher.py      # HTTP fetch with retry/timeout per source
│   ├── filters.py      # False positive filtering logic
│   ├── models.py       # Dataclasses: ThreatEntry, FetchResult, etc.
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
└── .cache/             # per-source cached entries (auto-created)
```
