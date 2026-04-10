# rpz-zone-factory

Threat intelligence pipeline for DNS. Fetches from 5 public feeds, builds RFC 5782 RPZ zone files for BIND, and optionally outputs Pi-hole flat blocklists.

Per-source zones support **incremental updates via TSIG-authenticated `nsupdate`** so secondaries receive **NOTIFY → IXFR** with only the changed records, instead of re-AXFR'ing the whole zone on every refresh. Steady-state runs (no upstream changes) exit in seconds via a 304-aware fast-path.

## How It Works

Two shell scripts handle all operations:

- **`run-rpz.sh`** — the main orchestrator. Manages the Python venv, runs the pipeline, validates zones with `named-checkzone`, applies incremental updates via `nsupdate`, falls back to per-zone freeze/replace/thaw on full rebuilds, and (when nothing has changed) skips the entire pipeline via the v0.7.0 fast-path. Run it from cron or interactively. One-time `--setup` wizard configures everything.
- **`allow.sh`** — real-time allowlist management. Adds or removes domains from the RPZ allowlist zone via TSIG-authenticated `nsupdate`, with an append-only audit log. Preserves the journal so secondaries see the change as an IXFR delta.

The Python engine (`rpz_factory/`) does the actual fetching, parsing, filtering, and zone rendering. The shell scripts call it — you don't need to invoke Python directly.

See [README-runner.md](README-runner.md) for full `run-rpz.sh` and `allow.sh` documentation, and [ARCHITECTURE.md](ARCHITECTURE.md) for the developer reference.

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

> With the v0.7.0 fast-path, runs that find no upstream changes complete in roughly the time it takes to make 5 conditional GETs (~5s) instead of running the full pipeline. Hourly cron schedules are reasonable if your upstream feeds publish frequently.

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
| Emerging Threats | IPs (compromised hosts) | https://rules.emergingthreats.net/blockrules/compromised-ips.txt |

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

Creates separate zone files: `urlhaus.rpz.db`, `cisa-kev.rpz.db`, `spamhaus-drop.rpz.db`, `scamsniffer.rpz.db`, `cryptoscamdb.rpz.db`, `et-compromised.rpz.db`. BIND logs then show which threat list triggered each block.

### Per-source with allowlist

```bash
python run.py --per-source --output-file /etc/namedb/master/rpz/ --allowlist /etc/namedb/master/rpz/allowlist.txt -v
```

The allowlist is a plain text file (one domain per line, `#` comments). It generates `allowlist.rpz.db` with passthru CNAME records to override blocks from other zones.

### All options

Run `python run.py --help` for the canonical list. Current flags:

| Flag | Description |
|------|-------------|
| `--output {rpz,pihole}` | Output format (default: `rpz`) |
| `--zone-name NAME` | RPZ zone name for combined mode (default: `rpz.local`) |
| `--output-file PATH` | Output file (combined mode) or directory (per-source mode) |
| `--sources …` | Subset of sources to fetch (default: all 5) |
| `--cache-dir DIR` | Cache directory for stale-data preservation (default: `<project>/.cache`) |
| `--per-source` | Output one zone file per source (RPZ only) |
| `--allowlist PATH` | Allowlist text file → generates `allowlist.rpz.db` (per-source mode) |
| `--force` | Bypass the v0.7.0 304-aware fast-path and always render |
| `-v`, `--verbose` | Increase verbosity (`-v` INFO, `-vv` DEBUG) |
| `--version` | Print version and exit |

**Exit codes:** `0` = success and output written, `1` = error, `2` = success but no output written (all sources returned 304 — the v0.7.0 fast-path). `run-rpz.sh` treats exit code 2 as a successful no-op and skips its post-processing pipeline.

## Features

### Conditional HTTP + 304 fast-path (v0.7.0+)

All 5 feeds use `If-Modified-Since` / `ETag` headers. When upstream data hasn't changed, the server returns `304 Not Modified` and the pipeline:

- **In per-source mode:** skips the entire render pipeline (parse, filter, dedup, render, diff, IXFR, seed, reload) for any zone whose source returned 304 with no error and whose live `.db` already exists. Zones with new content still render normally on the same run.
- **In combined mode:** if every source returned 304, exits with code 2 and run-rpz.sh skips its entire post-processing pipeline.
- **Allowlist:** uses an mtime check (no HTTP source). If `allowlist.txt` hasn't been modified since the live `allowlist.rpz.db` was written, the allowlist render is skipped.

In a steady state where nothing upstream has changed, the run completes in roughly the time it takes to make 5 conditional GETs (~5s) instead of the full pipeline (~30s). HTTP metadata is stored in `.cache/*.meta.json`. Pass `--force` to bypass the fast-path.

### Incremental updates / IXFR (v0.6.0+)

Per-source zones listed in `CONF_INCREMENTAL_ZONES` are updated by **diffing the previously-fetched feed against the freshly generated zone** and sending only the additions/deletions via TSIG-authenticated `nsupdate`. BIND writes the delta to the zone's journal, bumps the SOA serial, and secondaries receive **NOTIFY → IXFR** instead of re-AXFR'ing the whole zone.

For a typical day where upstream feeds add/remove a handful of domains, this turns megabyte-sized AXFRs into hundred-byte IXFR deltas. A single domain add transfers as 6 records (~230 bytes) instead of the full zone (~5000+ records / ~150KB for `urlhaus.rpz`).

See [README-runner.md § Incremental Updates](README-runner.md#incremental-updates-ixfr--v060) for the full per-zone state machine, fallback rules, and BIND configuration requirements.

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

Define each zone in `named.conf`. **Every zone you want updated incrementally needs `allow-update { key "rpz-update"; };`** so that `nsupdate` (run-rpz.sh's incremental path, and `allow.sh`) can deliver TSIG-authenticated dynamic updates. Without `allow-update`, `nsupdate` will be REFUSED and the zone silently falls back to a full rebuild on every run, forcing secondaries to AXFR.

Adjust `allow-transfer` to permit your secondary nameservers (shown here as a placeholder ACL `secondaries`) and add `also-notify` so they're notified of changes.

```bind
// Allowlist zone — evaluated first, passthru overrides blocks
zone "allowlist.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/allowlist.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};

// Threat source zones — all need allow-update for v0.6.0 incremental updates
zone "urlhaus.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/urlhaus.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};

zone "cisa-kev.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/cisa-kev.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};

zone "spamhaus-drop.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/spamhaus-drop.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};

zone "scamsniffer.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/scamsniffer.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};

zone "cryptoscamdb.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/cryptoscamdb.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};

zone "et-compromised.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/et-compromised.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};
```

The TSIG key referenced by `allow-update` must be defined elsewhere in `named.conf` (typically via `include "/etc/bind/tsig/rpz-update.key";` at the top level). See `./allow.sh --setup` for the full key generation walkthrough.

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
        zone "et-compromised.rpz";
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
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};

options {
    response-policy {
        zone "block.rpz" policy given;
    };
};
```

> **Combined mode is AXFR-only.** Unlike per-source mode, combined mode rewrites the entire zone file every run instead of using `nsupdate`. There's no journal for secondaries to pull deltas from, so every refresh transfers the whole zone. `allow-update` is therefore not needed (and not useful) on the combined zone. If you want IXFR support, switch to per-source mode.

### Deployment

Use `run-rpz.sh` for automated deployment — it handles venv management, zone validation, and BIND reload:

```sh
# First time: run the setup wizard
./run-rpz.sh --setup

# Subsequent runs (cron or interactive)
./run-rpz.sh
```

See the [Quick Start](#quick-start) above and [README-runner.md](README-runner.md) for full details.

For manual one-off runs or debugging, you can invoke the Python CLI directly:

```bash
# Generate all zone files
python run.py --per-source --output-file /etc/namedb/master/rpz/ -v

# Validate a zone
named-checkzone urlhaus.rpz /etc/namedb/master/rpz/urlhaus.rpz.db

# Load new zones for the first time
rndc reconfig

# Subsequent updates only need reload
rndc reload
```

## Pi-hole Configuration

To use the generated blocklist with Pi-hole:

1. Generate the blocklist file:
   ```bash
   # Via run-rpz.sh (recommended — configure with --setup)
   ./run-rpz.sh -- --output pihole --output-file /tmp/rpz-blocklist.txt

   # Or directly via Python
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
├── Makefile            # `make deploy` → rsync to remote BIND host
├── README.md
├── README-runner.md    # Full run-rpz.sh and allow.sh documentation
├── ARCHITECTURE.md     # Developer reference (per-zone state machine, IXFR design)
├── requirements.txt
├── .run-rpz.conf       # Generated by --setup (not in repo)
├── rpz_factory/
│   ├── __init__.py     # __version__
│   ├── cli.py          # argparse CLI, conditional HTTP, fast-path, summary output
│   ├── cache.py        # Per-source cache + HTTP metadata persistence
│   ├── fetcher.py      # HTTP fetch with retry/timeout, If-Modified-Since/ETag
│   ├── filters.py      # False positive filtering logic
│   ├── models.py       # Dataclasses: ThreatEntry, FetchResult, HttpMeta, etc.
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── abusech.py       # Abuse.ch URLhaus RPZ feed parser
│   │   ├── cisa.py          # CISA KEV JSON parser
│   │   ├── cryptoscamdb.py  # CryptoScamDB YAML blacklist parser
│   │   ├── emergingthreats.py # Emerging Threats compromised-IPs parser
│   │   ├── scamsniffer.py   # Scam Sniffer JSON blacklist parser
│   │   └── spamhaus.py      # Spamhaus DROP parser
│   └── renderers/
│       ├── __init__.py
│       ├── rpz.py      # RFC 5782 zone file renderer + monotonic serial
│       └── pihole.py   # Flat domain list renderer
├── scripts/            # Legacy reference scripts (unused, kept for context)
├── .cache/             # Per-source cached entries + HTTP metadata (auto-created)
└── feeds/              # `.list.previous` baseline snapshots for incremental
                        #   diffs (auto-created next to the zone output dir)
```

`allow.sh` also creates `allow-audit.log` in the zone output directory (next to `allowlist.txt`), not in the project directory. See [README-runner.md](README-runner.md#audit-log) for details.
