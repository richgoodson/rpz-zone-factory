# PYTHON.md: rpz-zone-factory Python engine

This document covers the Python engine (`rpz_factory/`) that powers rpz-zone-factory. Most users should drive everything through `run-rpz.sh`. See [README.md](README.md) for the operator documentation. This file is for direct-invocation use, debugging, and development.

For the full developer reference (per-zone state machine, IXFR design, internal data flow), see [ARCHITECTURE.md](ARCHITECTURE.md).

## Role in the system

rpz-zone-factory is split into two layers:

- **Python engine (`rpz_factory/`)**: a pure function from threat feeds to rendered zone files. Fetches sources with conditional HTTP, parses each format, applies false-positive filtering, deduplicates, and renders RFC 5782 RPZ zone files (or a Pi-hole flat list). Has no knowledge of BIND state, `rndc`, `nsupdate`, TSIG keys, or journals.
- **Shell orchestrator (`run-rpz.sh`)**: calls the Python engine, then handles everything downstream: per-zone freeze/replace/thaw, incremental IXFR diffs, `nsupdate` transactions (single-batch or byte-bounded chunked as of v0.9.1), reloads, seed snapshot management, and the v0.7.0 fast-path short-circuit.

This split keeps the Python side stateless and testable while letting the shell own all BIND-state reasoning.

## Direct invocation

You normally don't run `python run.py` yourself. `run-rpz.sh` manages the venv, sets the right flags from `.run-rpz.conf`, and handles everything downstream. The examples below are for debugging, manual one-off runs, or development.

If you want to run the CLI directly, activate the venv that `run-rpz.sh --setup` created:

```sh
. .venv/bin/activate
python run.py --help
```

### Generate RPZ zone files

RPZ output always writes one zone file per feed into a directory:

```sh
python run.py --output rpz --output-file /etc/namedb/master/rpz/ -v
```

As of v0.8.0 the filenames include the feed's category: `urlhaus.malware.rpz.db`, `cisa-kev.vulnerabilities.rpz.db`, `spamhaus-drop.ipreputation.rpz.db`, `scamsniffer.scam.rpz.db`, `cryptoscamdb.scam.rpz.db`, `et-compromised.ipreputation.rpz.db`, plus ads/tracking/cryptojacking zones (run `python -m rpz_factory.categories list-zones` for the live list). The category surfaces in the SOA returned with synthesized NXDOMAIN, so BIND logs and `dig` output reveal *which threat category* triggered each block.

### Generate a Pi-hole blocklist

Pi-hole output is a single flat-file blocklist:

```sh
python run.py --output pihole --output-file blocklist.txt -v
```

### Select specific sources

```sh
python run.py --sources urlhaus drop scamsniffer --output rpz --output-file /etc/namedb/master/rpz/
```

Or by category:

```sh
python run.py --categories malware ads --output rpz --output-file /etc/namedb/master/rpz/
```

### RPZ with allowlist

```sh
python run.py --output rpz \
  --output-file /etc/namedb/master/rpz/ \
  --allowlist /etc/namedb/master/rpz/allowlist.txt -v
```

The allowlist is a plain text file (one domain per line, `#` comments). It generates `allowlist.rpz.db` with passthru CNAME records to override blocks from other zones.

## CLI options

Run `python run.py --help` for the canonical list. Current flags:

| Flag | Description |
|------|-------------|
| `--output {rpz,pihole}` | Output format (default: `rpz`) |
| `--output-file PATH` | Output directory (RPZ) or file path (Pi-hole). Pi-hole defaults to stdout when omitted; RPZ requires a directory. |
| `--sources …` | Subset of sources to fetch (default: every feed in the registry; run `python -m rpz_factory.categories list-feeds` for the live list) |
| `--categories …` | Fetch every feed in the listed categories. Combine with `--sources` to add individual feeds on top. |
| `--exclude-sources …` | Drop these feed keys from the resolved selection. |
| `--cache-dir DIR` | Cache directory for stale-data preservation (default: `<project>/.cache`) |
| `--allowlist PATH` | Allowlist text file. Generates `allowlist.rpz.db` (RPZ output only). |
| `--force` | Bypass the v0.7.0 304-aware fast-path and always render |
| `-v`, `--verbose` | Increase verbosity (`-v` INFO, `-vv` DEBUG) |
| `--version` | Print version and exit |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (output written) |
| `1` | Error |
| `2` | Usage error (bad/unknown CLI flag: argparse's standard exit) |
| `3` | Success but no output written (all sources returned 304: the v0.7.0 fast-path) |

Exit code `3` only applies to Pi-hole output. RPZ output handles the fast-path per zone (see below) and exits `0` even when every zone was skipped. Code `2` is reserved for argparse usage errors and is deliberately kept distinct from the no-output fast-path so a malformed argument never masquerades as a clean no-op.

## Conditional HTTP and the fast-path

Every HTTP feed is fetched with `If-Modified-Since` / `ETag` headers. HTTP metadata is persisted to `.cache/*.meta.json` between runs. On a 304 response, the engine:

- **For RPZ output:** skips the entire render pipeline (parse, filter, dedup, render) for any zone whose source returned 304 with no error, *provided the live `.db` already exists on disk*. Zones whose source returned new content still render normally on the same run.
- **For Pi-hole output:** if every requested source returned 304 *and* the live blocklist file exists, the engine exits with code 3 without writing anything. Any source returning real content forces a full render.
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

All skipped entries are logged with reasons. Use `-v` (INFO) or `-vv` (DEBUG) to see them.

## Monotonic zone serial

The RPZ renderer uses a `YYYYMMDDNN` serial format where `NN` is a per-day revision counter. On each render, the engine reads the existing zone file (from the live path, or the `.tmp/` staging directory if `run-rpz.sh` is using `named-checkzone`), parses its SOA serial, and returns either `YYYYMMDD00` (if the existing serial isn't from today) or existing+1 (if it is).

This replaces an earlier `YYYYMMDDHH` (hour-based) scheme that produced duplicate serials when two runs landed within the same hour, causing BIND to emit `zone serial unchanged. zone may fail to transfer to secondaries` warnings. The `NN` counter is guaranteed monotonic within a day and rolls over cleanly at midnight. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full history.

Incremental (`nsupdate`-based) updates don't call the Python renderer at all. They let BIND auto-bump the SOA serial in response to the dynamic update. The renderer's serial logic only runs on full rebuilds.

The 2-digit `NN` counter caps each zone at 99 increments per UTC day. For most setups with hourly cron and quiet feeds this is well clear of the ceiling, but a frequently-updated zone running under aggressive cron AND producing v0.9.1 chunked updates AND seeing heavy `allow.sh` activity can accumulate bumps fast. See README's [Serial-bump budget](README.md#serial-bump-budget-v091) for operator guidance. Tracked separately: widening the scheme to `YYMMDDVVVV` (10000/day, still fits uint32 through 2099) to permanently retire the constraint.

## Package layout

```
rpz_factory/
├── __init__.py        # __version__
├── categories.py      # Feed/zone/category registry (REGISTRY) + bind-config generator
├── cli.py             # argparse CLI, per-source RPZ + combined Pi-hole rendering, fast-path
├── cache.py           # Per-source cache + HTTP metadata persistence
├── fetcher.py         # HTTP fetch with retry/timeout + If-Modified-Since/ETag
├── filters.py         # Safe TLD, critical allowlist, dedup, label validation
├── models.py          # Dataclasses: ThreatEntry, FetchResult, HttpMeta, SourceName enum
├── parsers/
│   ├── abusech.py           # URLhaus RPZ feed
│   ├── cisa.py              # CISA KEV JSON
│   ├── cryptoscamdb.py      # CryptoScamDB YAML
│   ├── emergingthreats.py   # Emerging Threats compromised-IPs
│   ├── plaintext.py         # Generic parser for hosts-file / plain-domain feeds
│   ├── scamsniffer.py       # Scam Sniffer JSON blacklist
│   └── spamhaus.py          # Spamhaus DROP
└── renderers/
    ├── rpz.py         # RFC 5782 zone file renderer + compute_next_serial
    └── pihole.py      # Flat domain list renderer
```

## Registry CLI (`python -m rpz_factory.categories`)

The feed/category registry has its own small CLI. The shell wrapper (`run-rpz.sh`) calls these subcommands to expand category selections to zone lists. They're also useful when you're working on the project directly:

| Subcommand | Purpose |
|------------|---------|
| `list-categories` | print every category name, one per line |
| `list-feeds [--category CAT]` | print feed keys (optionally filtered to one category) |
| `list-zones [--categories ...] [--include-allowlist]` | print zone filenames |
| `resolve --categories ... --extra ... --exclude ...` | apply the same selection logic the wizard uses, print resulting feed keys (or zones with `--as-zones`) |
| `zone-for FEED` / `category-for FEED` | single-feed lookup |
| `bind-config [--categories ...] [--zone-dir ...] [--tsig-key ...]` | emit `named.conf` zone blocks and a response-policy stanza for the selected zones. See [README.md](README.md#bind-configuration) for the operator walkthrough. |
| `validate-feeds` | strictly validate `user-feeds.yaml`; print every problem and exit non-zero if any (see below) |
| `list-orphans --zone-dir DIR [--feeds-dir DIR]` | print live zone files / feed snapshots no longer backed by the registry; exit non-zero if any. Read-only, never deletes |

## User-supplied feeds (`user-feeds.yaml`)

Operators can add feeds without editing the package. `rpz_factory/userfeeds.py`
loads and validates an optional `user-feeds.yaml`; `categories.py` merges the
valid feeds into `REGISTRY` at import time, so they flow through every
registry-derived path (`cli.py`'s source maps, the shell's category expansion,
`bind-config`) with no further wiring. See [README.md](README.md#adding-your-own-feeds)
for the YAML schema and the BIND activation/removal walkthrough; this section is
the engine-level reference.

**Path resolution.** `RPZ_USER_FEEDS` if set, else `<repo-root>/user-feeds.yaml`.
Deliberately not derived from `RPZ_DIR` (the two are decoupled). A missing file
means no custom feeds and zero behavior change.

**Identity: `SourceRef`, not a dynamic enum.** A built-in feed's `ThreatEntry`
carries a `SourceName` enum member; a user feed carries a
`SourceRef("user_<key>")` value object (`models.py`). Both expose `.value`, the
only attribute any consumer reads (cache filenames, log lines, the per-source
grouping in `cli.py`), so the two are interchangeable everywhere. This avoids
extending the `SourceName` enum at import time and keeps `models.py` import-pure,
so a malformed config can never make the package unimportable.

**Validation (one pass, `userfeeds.load_user_feeds`).** Structural checks first
(key DNS-safe `^[a-z0-9][a-z0-9-]*$`, no duplicate key in the file, `kind` in
`{domain, ip}`, `url` scheme http/https), then cross-reference against the
built-in registry (`category` known; key not colliding with a built-in key or
`allowlist`; derived zone `<key>.<category>.rpz` not colliding with a built-in
zone or an earlier user feed). `categories.py` owns those registry facts and
passes them in, so `userfeeds.py` imports nothing from the package.

**Two kinds.** `domain` reuses `parsers/plaintext.parse_text`; `ip` uses
`parse_ip_text` (IPv4 only; IPv6 and unparseable lines are dropped and counted).
The IP drop-count log escalates from INFO to **WARNING when drops exceed kept**
entries, so a feed that collapses to a near-empty zone is loud at the default
log level.

**Graceful degradation (decision: never take down the built-in pipeline).** A
per-feed error drops just that feed; a file-level error (unparseable YAML, wrong
top-level shape) drops all custom feeds. Either way the built-ins still run and
the issues are recorded in `categories.USER_FEED_ISSUES`. Both entry points
surface them: `cli.main` logs the summary at WARNING, and the
`categories` module CLI prints the same line to stderr on every subcommand
except `validate-feeds` (which prints its own richer report). For deliberate
checking, `validate-feeds` re-runs validation in strict mode and exits non-zero
on any problem.

## Adding a new source

1. Add a parser in `rpz_factory/parsers/`: takes raw bytes/text, returns a list of `ThreatEntry` objects. For plain-domain or hosts-file feeds you may not need a new parser at all: `parsers/plaintext.py` is generic; pass its `make_fetcher(url, source_enum, label=...)` factory into `SOURCE_FETCHERS` in `cli.py`.
2. Add a `SourceName` enum value in `rpz_factory/models.py`.
3. Add a `FeedSpec` entry to `_BUILTIN_FEEDS` in `rpz_factory/categories.py` (`key`, `zone`, `category`, `enum_value`, `url`, and optional `kind` which defaults to `"domain"`). User feeds from `user-feeds.yaml` are appended to `_BUILTIN_FEEDS` to form `_FEEDS`; this step is only for built-in feeds. The constants in `cli.py` (`ALL_SOURCES`, `SOURCE_ZONE_NAMES`, `_SOURCE_URLS`, `_SOURCE_KEY_TO_NAME`, `_SOURCE_NAME_TO_KEY`) are derived from `REGISTRY` at import time, so no edits there are needed for those.
4. Wire the parser callable into `SOURCE_FETCHERS` in `rpz_factory/cli.py` keyed by feed key. This dict is still hand-maintained because parser callables vary in signature (some are `fetch_and_parse`, some are `plaintext.make_fetcher(...)` factories).
5. Add the feed to the sources table in `README.md`.
6. If it should participate in incremental updates, its category should be in `CONF_INCREMENTAL_CATEGORIES` (preferred) or its zone filename in the legacy `CONF_INCREMENTAL_ZONES`. Regenerate the `named.conf` snippet so the new zone has `allow-update`:
   ```sh
   python -m rpz_factory.categories bind-config --categories <your-categories>
   ```

For parser contracts, data flow, and the per-zone state machine that `run-rpz.sh` uses to decide between incremental and full-rebuild paths, read [ARCHITECTURE.md](ARCHITECTURE.md).
