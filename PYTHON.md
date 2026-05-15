# PYTHON.md — rpz-zone-factory Python engine

This document covers the Python engine (`rpz_factory/`) that powers rpz-zone-factory. Most users should drive everything through `run-rpz.sh` — see [README.md](README.md) for the operator documentation. This file is for direct-invocation use, debugging, and development.

For the full developer reference (per-zone state machine, IXFR design, internal data flow), see [ARCHITECTURE.md](ARCHITECTURE.md).

## Role in the system

rpz-zone-factory is split into two layers:

- **Python engine (`rpz_factory/`)** — a pure function from threat feeds to rendered zone files. Fetches sources with conditional HTTP, parses each format, applies false-positive filtering, deduplicates, and renders RFC 5782 RPZ zone files (or a Pi-hole flat list). Has no knowledge of BIND state, `rndc`, `nsupdate`, TSIG keys, or journals.
- **Shell orchestrator (`run-rpz.sh`)** — calls the Python engine, then handles everything downstream: per-zone freeze/replace/thaw, incremental IXFR diffs, `nsupdate` transactions, reloads, seed snapshot management, and the v0.7.0 fast-path short-circuit.

This split keeps the Python side stateless and testable while letting the shell own all BIND-state reasoning.

## Direct invocation

You normally don't run `python run.py` yourself — `run-rpz.sh` manages the venv, sets the right flags from `.run-rpz.conf`, and handles everything downstream. The examples below are for debugging, manual one-off runs, or development.

If you want to run the CLI directly, activate the venv that `run-rpz.sh --setup` created:

```sh
. .venv/bin/activate
python run.py --help
```

### Generate an RPZ zone file (default, combined mode)

```sh
python run.py --output rpz --zone-name rpz.local -v
```

### Generate a Pi-hole blocklist

```sh
python run.py --output pihole --output-file blocklist.txt -v
```

### Select specific sources

```sh
python run.py --sources urlhaus drop scamsniffer --output rpz
```

### Per-source mode (one zone per threat source)

```sh
python run.py --per-source --output-file /etc/namedb/master/rpz/ -v
```

Creates separate zone files, one per feed. As of v0.8.0 the filenames include the feed's category — `urlhaus.malware.rpz.db`, `cisa-kev.vulnerabilities.rpz.db`, `spamhaus-drop.ipreputation.rpz.db`, `scamsniffer.scam.rpz.db`, `cryptoscamdb.scam.rpz.db`, `et-compromised.ipreputation.rpz.db`, plus ads/tracking/cryptojacking zones (run `python -m rpz_factory.categories list-zones` for the live list). The category surfaces in the SOA returned with synthesized NXDOMAIN, so BIND logs and `dig` output reveal *which threat category* triggered each block.

### Per-source with allowlist

```sh
python run.py --per-source \
  --output-file /etc/namedb/master/rpz/ \
  --allowlist /etc/namedb/master/rpz/allowlist.txt -v
```

The allowlist is a plain text file (one domain per line, `#` comments). It generates `allowlist.rpz.db` with passthru CNAME records to override blocks from other zones.

## CLI options

Run `python run.py --help` for the canonical list. Current flags:

| Flag | Description |
|------|-------------|
| `--output {rpz,pihole}` | Output format (default: `rpz`) |
| `--zone-name NAME` | RPZ zone name for combined mode (default: `rpz.local`) |
| `--output-file PATH` | Output file (combined mode) or directory (per-source mode) |
| `--sources …` | Subset of sources to fetch (default: all 6) |
| `--cache-dir DIR` | Cache directory for stale-data preservation (default: `<project>/.cache`) |
| `--per-source` | Output one zone file per source (RPZ only) |
| `--allowlist PATH` | Allowlist text file → generates `allowlist.rpz.db` (per-source mode) |
| `--force` | Bypass the v0.7.0 304-aware fast-path and always render |
| `-v`, `--verbose` | Increase verbosity (`-v` INFO, `-vv` DEBUG) |
| `--version` | Print version and exit |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success — output written |
| `1` | Error |
| `2` | Success but no output written (all sources returned 304 — the v0.7.0 fast-path) |

`run-rpz.sh` treats exit code `2` as a successful no-op and skips its entire post-processing pipeline (no freeze/thaw, no reload, no diff, no nsupdate). This is how the combined-mode fast-path avoids redundant BIND work when upstream content hasn't changed.

## Conditional HTTP and the fast-path

All 6 feeds are fetched with `If-Modified-Since` / `ETag` headers. HTTP metadata is persisted to `.cache/*.meta.json` between runs. On a 304 response, the engine:

- **In per-source mode:** skips the entire render pipeline (parse, filter, dedup, render) for any zone whose source returned 304 with no error, *provided the live `.db` already exists on disk*. Zones whose source returned new content still render normally on the same run.
- **In combined mode:** if every requested source returned 304 *and* the live combined zone file exists, the engine exits with code 2 without writing anything. Any source returning real content forces a full render.
- **Allowlist:** the allowlist source is a local text file, not HTTP. The engine compares `allowlist.txt` mtime against the live `allowlist.rpz.db` mtime and skips the allowlist render if the text file is older.

Pass `--force` to bypass all of this and always render. Use after manual zone edits or when debugging.

## Source caching (robustness)

Separate from the HTTP fast-path above, the engine also maintains a per-source entry cache at `.cache/{source_name}.json`. This is a safety net for upstream outages:

- **On successful fetch:** parsed entries are persisted to the cache (with timestamp and count)
- **On failed fetch:** the cache is consulted. If a cache file exists, its entries are used and a WARNING is logged with the cache timestamp
- **If no cache exists:** the source contributes nothing (same as a hard failure)

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

## False-positive filtering

Before rendering, the engine applies rule-based filtering to reduce false positives:

- **Safe TLDs**: `.gov`, `.mil`, `.edu` domains are never blocked
- **Critical allowlist**: ~50 top infrastructure domains (Google, Cloudflare, Amazon, Microsoft, Apple, etc.) are never blocked, including subdomain matching
- **DNS label validation**: rejects entries with labels >63 characters, paths, or total length >253
- **Deduplication**: entries are deduplicated across all sources

All skipped entries are logged with reasons — use `-v` (INFO) or `-vv` (DEBUG) to see them.

## Monotonic zone serial

The RPZ renderer uses a `YYYYMMDDNN` serial format where `NN` is a per-day revision counter. On each render, the engine reads the existing zone file (from the live path, or the `.tmp/` staging directory if `run-rpz.sh` is using `named-checkzone`), parses its SOA serial, and returns either `YYYYMMDD00` (if the existing serial isn't from today) or existing+1 (if it is).

This replaces an earlier `YYYYMMDDHH` (hour-based) scheme that produced duplicate serials when two runs landed within the same hour, causing BIND to emit `zone serial unchanged. zone may fail to transfer to secondaries` warnings. The `NN` counter is guaranteed monotonic within a day and rolls over cleanly at midnight. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full history.

Incremental (`nsupdate`-based) updates don't call the Python renderer at all — they let BIND auto-bump the SOA serial in response to the dynamic update. The renderer's serial logic only runs on full rebuilds.

## Package layout

```
rpz_factory/
├── __init__.py        # __version__
├── cli.py             # argparse CLI, per-source + combined rendering, fast-path logic
├── cache.py           # Per-source cache + HTTP metadata persistence
├── fetcher.py         # HTTP fetch with retry/timeout + If-Modified-Since/ETag
├── filters.py         # Safe TLD, critical allowlist, dedup, label validation
├── models.py          # Dataclasses: ThreatEntry, FetchResult, HttpMeta, etc.
├── parsers/
│   ├── abusech.py           # URLhaus RPZ feed
│   ├── cisa.py              # CISA KEV JSON
│   ├── cryptoscamdb.py      # CryptoScamDB YAML
│   ├── emergingthreats.py   # Emerging Threats compromised-IPs
│   ├── scamsniffer.py       # Scam Sniffer JSON blacklist
│   └── spamhaus.py          # Spamhaus DROP
└── renderers/
    ├── rpz.py         # RFC 5782 zone file renderer + compute_next_serial
    └── pihole.py      # Flat domain list renderer
```

## Adding a new source

1. Add a parser in `rpz_factory/parsers/` — takes raw bytes/text, returns a list of `ThreatEntry` objects.
2. Register it in `rpz_factory/cli.py` (source name, URL, parser function, per-source zone name).
3. Add it to the sources table in `README.md`.
4. If it should participate in incremental updates, add the per-source zone to `CONF_INCREMENTAL_ZONES` in `.run-rpz.conf` and add a matching `zone` block with `allow-update` to `named.conf`.

For parser contracts, data flow, and the per-zone state machine that `run-rpz.sh` uses to decide between incremental and full-rebuild paths, read [ARCHITECTURE.md](ARCHITECTURE.md).
