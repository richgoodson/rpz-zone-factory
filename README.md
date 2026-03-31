# rpz-zone-factory

A CLI pipeline that fetches threat intelligence from multiple sources and outputs either RFC 5782 RPZ zone files (for BIND/authoritative DNS servers) or Pi-hole flat blocklist format.

## Sources

| Source | Type | URL |
|--------|------|-----|
| Abuse.ch URLhaus | Domains (RPZ feed) | https://urlhaus.abuse.ch/downloads/rpz/ |
| CISA KEV | Domains from CVE data | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| Spamhaus DROP | IP/CIDR | https://www.spamhaus.org/drop/drop.txt |
| Spamhaus EDROP | IP/CIDR | https://www.spamhaus.org/drop/edrop.txt |
| Spamhaus DBL | Domains | https://www.spamhaus.org/drop/dbl.txt |
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
python run.py --sources urlhaus drop edrop scamsniffer --output rpz
```

### All options

```
usage: rpz-zone-factory [-h] [--output {rpz,pihole}] [--zone-name ZONE_NAME]
                        [--output-file OUTPUT_FILE]
                        [--sources {urlhaus,cisa,drop,edrop,dbl,scamsniffer,cryptoscamdb} ...]
                        [--cache-dir CACHE_DIR]
                        [-v]

  --output {rpz,pihole}     Output format (default: rpz)
  --zone-name ZONE_NAME     RPZ zone name (default: rpz.local)
  --output-file OUTPUT_FILE Write output to file (default: stdout)
  --sources                 Sources to fetch (default: all 7)
  --cache-dir CACHE_DIR     Cache directory for stale-data preservation
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

To use the generated RPZ zone file with BIND, add the following to your `named.conf`:

```bind
// Define the RPZ zone
zone "rpz.local" {
    type master;
    file "/etc/bind/zones/rpz.local.zone";
    allow-query { none; };
    allow-transfer { none; };
};

// Enable RPZ in the options or view
options {
    // ... other options ...

    response-policy {
        zone "rpz.local"
            policy given     // use the CNAME target from the zone (NXDOMAIN via ".")
            recursive-only yes;
    };
};
```

Generate and deploy the zone file:

```bash
# Generate the zone
python run.py --output rpz --zone-name rpz.local --output-file /etc/bind/zones/rpz.local.zone

# Validate the zone file
named-checkzone rpz.local /etc/bind/zones/rpz.local.zone

# Reload BIND
rndc reload rpz.local
```

Set up a cron job to refresh periodically:

```cron
0 */6 * * * /usr/bin/python3 /opt/rpz-zone-factory/run.py --output rpz --zone-name rpz.local --output-file /etc/bind/zones/rpz.local.zone -v && /usr/sbin/rndc reload rpz.local
```

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

> **Note:** Pi-hole only supports domain-based blocking. IP/CIDR entries from Spamhaus DROP/EDROP are excluded from Pi-hole output.

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
│   │   └── spamhaus.py      # Spamhaus DROP/EDROP/DBL parser
│   └── renderers/
│       ├── __init__.py
│       ├── rpz.py      # RFC 5782 zone file renderer
│       └── pihole.py   # Flat domain list renderer
└── .cache/             # per-source cached entries (auto-created)
```
