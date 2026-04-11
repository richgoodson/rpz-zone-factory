# rpz-zone-factory

Threat intelligence pipeline for DNS. Fetches from 6 public feeds, builds RFC 5782 RPZ zone files for BIND, and optionally outputs Pi-hole flat blocklists.  Currently used in a FreeBSD production environment, so it works, but may be a bit confusing to set up as the project has evolved over time.  I've tried to add Linux specific options, but those have not been extensively tested.

Per-source zones support **incremental updates via TSIG-authenticated `nsupdate`** so secondaries receive **NOTIFY → IXFR** with only the changed records, instead of re-AXFR'ing the whole zone on every refresh. Steady-state runs (no upstream changes) exit in seconds via a 304-aware fast-path.

## How It Works

Two shell scripts handle all operations:

- **`run-rpz.sh`** — the main orchestrator. Manages the Python venv, runs the pipeline, validates zones with `named-checkzone`, applies incremental updates via `nsupdate`, falls back to per-zone freeze/replace/thaw on full rebuilds, and (when nothing has changed) skips the entire pipeline via the v0.7.0 fast-path. Run it from cron or interactively. One-time `--setup` wizard configures everything.
- **`allow.sh`** — real-time allowlist management. Adds or removes domains from the RPZ allowlist zone via TSIG-authenticated `nsupdate`, with an append-only audit log. Preserves the journal so secondaries see the change as an IXFR delta.

The Python engine (`rpz_factory/`) does the actual fetching, parsing, filtering, and zone rendering. The shell scripts call it — you don't need to invoke Python directly. See [PYTHON.md](PYTHON.md) for direct-invocation reference and [ARCHITECTURE.md](ARCHITECTURE.md) for the developer deep-dive.

## Quick Start

```sh
# Clone
git clone https://github.com/richgoodson/rpz-zone-factory.git /opt/rpz-zone-factory
cd /opt/rpz-zone-factory

# Run the setup wizard (creates venv, installs deps, configures everything)
./run-rpz.sh --setup

# Test interactively
./run-rpz.sh -i

# Add to cron (the wizard generates the entry for you)
crontab -e
```

The `--setup` wizard walks through output format, per-source mode, zone names, BIND reload, `named-checkzone` validation, optionally `named-compilezone`, TSIG key configuration, the feeds directory, and which zones should use the incremental IXFR update path. All choices are saved to `.run-rpz.conf` so subsequent runs (including cron) need zero arguments.

### Cron examples

After `--setup`, the script reads `.run-rpz.conf` automatically — no CLI args needed:

```cron
# Per-source RPZ zones for BIND, every 4 hours - change directory to where you have it installed
15 */4 * * * /opt/rpz-zone-factory/run-rpz.sh

# With explicit args (overrides saved config)
15 */4 * * * /opt/rpz-zone-factory/run-rpz.sh -- --output rpz --per-source --output-file /etc/namedb/master/rpz/ -v

# Pi-hole flat file, daily at 3:05 AM
5 3 * * * /opt/rpz-zone-factory/run-rpz.sh -- --output pihole --output-file /var/www/rpz/block.txt
```

> With the v0.7.0 fast-path, runs that find no upstream changes complete in roughly the time it takes to make 6 conditional GETs (~5s) instead of running the full pipeline. Hourly cron schedules are reasonable if your upstream feeds publish frequently.

### Dynamic allowlist

```sh
# Allow a domain through RPZ (immediate, TSIG-authenticated)
./allow.sh example.com

# Remove it
./allow.sh -r example.com

# View the audit log
./allow.sh --audit
```

See `./allow.sh --setup` for TSIG key configuration, or the [allow.sh section](#allowsh--dynamic-allowlist) below for full details.

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

- POSIX shell (`sh`), `cron`, `rndc`, `nsupdate`
- Python 3.9+ (managed automatically by `run-rpz.sh`)
- `requests` and `pyyaml` (installed into a venv by `run-rpz.sh --setup`)

> **Don't run this as root.** The pipeline needs write access to a few specific paths and read access to BIND credentials, all achievable with group permissions. See [Running as a Non-Root User](#running-as-a-non-root-user) below.

## run-rpz.sh Reference

### Modes

| Mode | Flag | Behavior |
|------|------|----------|
| Interactive | `-i` or `--interactive` | Output to stdout/stderr. Auto-detected when run from a terminal. |
| Cron | `-c` or `--cron` | Logs via `logger` (syslog). Auto-detected when stdin is not a terminal. |

### Options

| Option | Description |
|--------|-------------|
| `-v`, `--version` | Print version and exit |
| `-h`, `--help` | Show usage and exit |
| `-i`, `--interactive` | Force interactive mode |
| `-c`, `--cron` | Force cron mode |
| `--setup` | Interactive setup wizard: configure output, sources, BIND reload, zone validation/compilation, TSIG keys, incremental zones, and generate cron entries |
| `--reload-bind ZONE` | (Combined mode only.) After a successful run, call `rndc reload ZONE`. In per-source mode, run-rpz.sh handles per-zone reload/thaw internally and this flag is unused. |
| `--full-rebuild` | Force the full rebuild path (per-zone freeze → file replace → thaw) for every zone, bypassing the incremental IXFR path. Use for recovery, after BIND/zone config changes, or to force a clean re-seed of `.list.previous` snapshots. (v0.6.0+) |
| `--force` | Bypass the v0.7.0 fast-path that exits early when every upstream source returns 304 Not Modified. Use after manual zone edits or for debugging. (v0.7.0+) |
| `--rpz-dir DIR` | Override RPZ_DIR (can also set via environment) |
| `--python BIN` | Override Python binary (default: `python3.11`) |
| `-- ARGS...` | Everything after `--` is passed to rpz-zone-factory |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RPZ_DIR` | Script's own directory | Path to rpz-zone-factory project |
| `PYTHON_BIN` | `python3.11` | Python interpreter (setup wizard scans for 3.9–3.14) |
| `VENV_NAME` | `.venv` | Venv directory name within RPZ_DIR |
| `RNDC_BIN` | `rndc` | Path to rndc binary |

### Configuration File

The `--setup` wizard saves all choices to `.run-rpz.conf` in the project directory. Key settings:

| Setting | Description |
|---------|-------------|
| `CONF_OUTPUT` | `rpz` or `pihole` |
| `CONF_PER_SOURCE` | `yes` or `no` — one zone file per source |
| `CONF_OUTPUT_FILE` | Output file (combined) or directory (per-source) |
| `CONF_ZONE_NAME` | Zone name for combined mode |
| `CONF_ALLOWLIST_FILE` | Path to allowlist text file |
| `CONF_RELOAD` | `yes` or `no` — rndc reload after update |
| `CONF_CHECKZONE` | `yes` or `no` — validate with `named-checkzone` |
| `CONF_COMPILE_ZONE` | `yes` or `no` — compile to binary (raw) format |
| `CONF_SOURCES` | Space-separated source list, or `all` |
| `CONF_VERBOSITY` | `0` (quiet), `1` (`-v`), `2` (`-vv`) |
| `CONF_TSIG_KEY_FILE` | Path to TSIG key file (shared by `allow.sh` and the v0.6.0 incremental update path) |
| `CONF_ALLOW_SERVER` | Server for nsupdate (default: `localhost`) |
| `CONF_ALLOW_ZONE` | Allowlist zone name (default: `allowlist.rpz`) |
| `CONF_AUDIT_LOG` | Path to audit log file (default: `allow-audit.log` next to allowlist) |
| `CONF_FEEDS_DIR` | (v0.6.0+) Directory holding `.list.previous` baseline snapshots for the incremental update path. Default: `<output>/feeds`. The allowlist `.txt` source file lives here too. |
| `CONF_INCREMENTAL_ZONES` | (v0.6.0+) Space-separated list of zones that should use the IXFR-based incremental update path. Zones not listed here go through the full rebuild path. Empty = no zones use incremental updates. |

Edit `.run-rpz.conf` directly or re-run `--setup` to reconfigure.

### Logging

In cron mode, all output goes to syslog via `logger`:

- Tag: `rpz-zone-factory`
- Facility: `daemon`

View logs:

```sh
# Linux (journald)
journalctl -t rpz-zone-factory

# Linux (syslog)
grep rpz-zone-factory /var/log/syslog

# FreeBSD (daemon facility routes to daemon.log, not messages)
grep rpz-zone-factory /var/log/daemon.log
```

### Venv Lifecycle

- **Created** on first run (or via `--setup`)
- **Reused** on subsequent runs — no reinstall overhead
- **Auto-healed**: if the venv is broken (missing python, missing deps), the script recreates it
- **No activation/deactivation**: the script calls the venv's python binary directly — no `source activate` fragility

## Incremental Updates (IXFR) — v0.6.0+

Per-source zones listed in `CONF_INCREMENTAL_ZONES` are updated by **diffing the previously-fetched feed against the freshly generated zone** and sending only the additions/deletions via TSIG-authenticated `nsupdate`. BIND writes the delta to the zone's journal, bumps the SOA serial, and secondaries receive **NOTIFY → IXFR** instead of re-AXFR'ing the whole zone — turning megabyte transfers into hundred-byte deltas.

For a typical day where upstream feeds add/remove a handful of domains, a single domain add transfers as 6 records (~230 bytes) instead of the full zone (~5000+ records / ~150KB for `urlhaus.rpz`).

### How a zone goes from cold to incremental

1. **First run for a zone:** no `.list.previous` baseline exists yet, so the zone takes the full rebuild path (per-zone freeze → file replace → thaw). After the rebuild, run-rpz.sh extracts the domain list from the freshly rendered `.db` and writes it to `<feeds>/<zone>.list.previous`. This is the **seed**.
2. **Subsequent runs:** the script diffs the new feed against `.list.previous`. If `adds=0 dels=0`, nothing happens (no nsupdate, no journal entry, no secondary traffic). If there are real diffs, a single `nsupdate` transaction adds and removes only the changed records, BIND auto-bumps the serial and writes a journal entry, and secondaries pick up the delta via IXFR.
3. **`.list.previous` is refreshed** after each successful incremental run so the next diff is computed against the current state.

### Falling back to full rebuild

A zone configured for incremental updates will silently drop back to the full rebuild path if any of the following are true:

- The zone has no `.list.previous` snapshot (first-ever run, or `--full-rebuild` was used)
- TSIG is not configured (`CONF_TSIG_KEY_FILE` missing or unreadable)
- `nsupdate` itself fails for any reason
- You explicitly pass `--full-rebuild`

A full rebuild always re-seeds `.list.previous` afterward, so a zone can flip back to incremental on the next run.

### BIND configuration requirements

**Every zone in `CONF_INCREMENTAL_ZONES` must have `allow-update { key "rpz-update"; };` in its `named.conf` definition** — including the per-source threat zones, not just the allowlist. Without this, `nsupdate` will be REFUSED and the zone falls back to full rebuild on every run. See the [BIND Configuration](#bind-configuration) section below for complete zone examples.

### Per-zone freeze/thaw (full rebuild path)

When a zone IS in the full rebuild bucket (seed run, fallback, or `--full-rebuild`), run-rpz.sh handles it via **per-zone** `rndc freeze <zone>` → atomic file replace → `rndc thaw <zone>`, not a global freeze/thaw. This is required for dynamic zones (zones with `allow-update`) because:

- `rndc reload <zone>` flatly fails on dynamic zones with `'reload' failed: dynamic zone`
- A global `rndc thaw` is asynchronous and races against the freshly-replaced file, producing `zone serial has gone backwards` warnings
- Per-zone `rndc thaw <zone>` re-reads the file synchronously, eliminating the race

Static (non-dynamic) zones in the full bucket use plain `rndc reload <zone>` instead.

### Verifying IXFR is working

On a secondary, look for transfer log entries with a small record count:

```
zone urlhaus.rpz/IN: Transfer started.
transfer of 'urlhaus.rpz/IN' from <primary>#53: Transfer completed: 1 messages, 6 records, 229 bytes (serial 2026040827)
```

`6 records` is the IXFR delta for a single domain add (old SOA, new SOA, two CNAMEs for `domain` and `*.domain`). If you instead see hundreds or thousands of records for what should have been a small change, the secondary is doing AXFR — check that the primary has `allow-update` on the zone and that `nsupdate` is succeeding.

## Fast-path: skip when nothing changed — v0.7.0+

All 6 feeds use `If-Modified-Since` / `ETag` headers. When every requested source returns `304 Not Modified`, run-rpz.sh exits in roughly the time it takes to make the conditional HTTP requests (~5s for 6 sources) instead of running the full pipeline (~30s in steady state). The fast-path applies in both per-source mode (per-zone — only zones whose source returned 304 are skipped) and combined mode (whole-zone — only triggers if every source is 304).

- **Per-source mode:** any zone whose source returned 304 with no error and whose live `.db` exists is skipped entirely (no parse, no filter, no render, no diff, no IXFR, no seed, no reload). Zones with new content render normally on the same run.
- **Combined mode:** if every source returned 304 and the live combined zone exists, the Python engine exits with code 2 and run-rpz.sh skips its entire post-processing pipeline.
- **Allowlist:** the allowlist source is a local text file, not HTTP, so the fast-path uses an mtime check instead. If `allowlist.txt` hasn't been modified since the live `allowlist.rpz.db` was last written, the allowlist render is skipped.
- **`--force`** bypasses all of this and forces a full pipeline run. Use after manual zone edits or for debugging.

The fast-path is safe: 304 means upstream content is unchanged, the cached `.previous` snapshot still matches, and BIND's in-memory state is already correct. There's nothing to do. HTTP metadata is stored in `.cache/*.meta.json`.

## allow.sh — Dynamic Allowlist

`allow.sh` adds or removes domains from the RPZ allowlist zone in real time using TSIG-authenticated `nsupdate`, without waiting for the next scheduled rpz-zone-factory run. Changes are also persisted to the allowlist text file so they survive regeneration.

### Quick usage

```sh
# Allow a domain (adds domain + *.domain by default)
./allow.sh example.com

# Allow domain only (no wildcard)
./allow.sh -n example.com

# Remove a domain from the allowlist
./allow.sh -r example.com

# View the audit log (last 20 entries)
./allow.sh --audit

# View the last 50 entries
./allow.sh --audit 50
```

### Requirements

- TSIG key configured for the allowlist zone (see `./allow.sh --setup` for full walkthrough)
- `nsupdate` and `rndc` available in PATH
- The allowlist zone (and every zone in `CONF_INCREMENTAL_ZONES`) configured with `allow-update { key "rpz-update"; };`

### Configuration

`allow.sh` reads defaults from `.run-rpz.conf` (shared with `run-rpz.sh`). The `--setup` wizard in `run-rpz.sh` configures these automatically:

| Setting | Description |
|---------|-------------|
| `CONF_TSIG_KEY_FILE` | Path to TSIG key file |
| `CONF_ALLOW_SERVER` | Server for nsupdate (default: `localhost`) |
| `CONF_ALLOW_ZONE` | Allowlist zone name (default: `allowlist.rpz`) |
| `CONF_ALLOWLIST_FILE` | Allowlist text file (shared with rpz-zone-factory) |
| `CONF_AUDIT_LOG` | Path to audit log file (default: `allow-audit.log` next to allowlist file) |

All settings can be overridden with flags. Run `./allow.sh -h` for the full flag list.

### How it works

1. Validates the domain name
2. Appends/removes the domain in the allowlist text file (race condition safe — file is updated before the dynamic update)
3. Sends `nsupdate` with TSIG key to add/remove RPZ passthru records
4. Runs `rndc sync <zone>` to flush in-memory state to the `.db` file. **The journal (`.jnl`) is preserved** so secondaries can pull the change via IXFR instead of re-AXFR'ing the whole zone.
5. Writes an entry to the audit log (success or failure)

### Audit log

Every add/remove operation is logged to an append-only audit log. The log records:

- Timestamp (local time with UTC offset)
- Action (`add` or `remove`)
- Domain
- Operator (`whoami` — who ran the command)
- Result (`OK` or `FAIL:reason`)

Failures are logged too — if `nsupdate` fails, the log records the exit code.

Example:

```
2026-04-03T12:22:04-0500 | add    | audit-test.example | alice | OK
2026-04-03T12:22:22-0500 | remove | audit-test.example | alice | OK
2026-04-03T12:30:01-0500 | add    | suspect.example    | root  | FAIL:nsupdate-rc1
```

The log file defaults to `allow-audit.log` in the same directory as the allowlist file. Override with `--audit-file` or `CONF_AUDIT_LOG` in `.run-rpz.conf`.

View the log with `--audit`:

```sh
./allow.sh --audit        # last 20 entries
./allow.sh --audit 50     # last 50 entries
```

`--audit` doesn't require a TSIG key, domain, or any preflight — it just reads the log file.

### TSIG setup

Run `./allow.sh --setup` for step-by-step instructions covering key generation, directory permissions, `named.conf` changes, and testing.

The `run-rpz.sh --setup` wizard also walks through TSIG configuration when per-source mode with an allowlist is enabled.

## Pipeline Behavior

### Source caching

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

### False positive filtering

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

## BIND Reload Permissions

The user running `run-rpz.sh` (and `allow.sh`) needs `rndc` access. Pick one approach:

### 1. rndc.key file (recommended)

BIND generates an rndc key at install. Grant the cron user read access:

```sh
# FreeBSD
chgrp named /usr/local/etc/namedb/rndc.key
chmod 640 /usr/local/etc/namedb/rndc.key
pw groupmod named -m rpzuser

# Debian/Ubuntu
chgrp bind /etc/bind/rndc.key
chmod 640 /etc/bind/rndc.key
usermod -aG bind rpzuser
```

### 2. rndc.conf with explicit key

Create `/etc/bind/rndc.conf` (or `/usr/local/etc/namedb/rndc.conf`):

```
key "rndc-key" {
    algorithm hmac-sha256;
    secret "your-base64-key-here";
};

options {
    default-key "rndc-key";
    default-server 127.0.0.1;
    default-port 953;
};
```

rndc reads this automatically. Ensure the cron user can read the file.

### 3. Run cron as the named/bind user

```
15 */4 * * * sudo -u named RPZ_DIR=/opt/rpz-zone-factory /opt/rpz-zone-factory/run-rpz.sh
```

The user also needs write access to the output file directory.

### 4. Passwordless sudo for rndc only (least recommended)

In `/etc/sudoers.d/rpz-rndc`:

```
rpzuser ALL=(ALL) NOPASSWD: /usr/sbin/rndc *
```

Then: `RNDC_BIN="sudo rndc" ./run-rpz.sh ...`

## Running as a Non-Root User

Don't run rpz-zone-factory as root. The pipeline needs write access to a few specific paths and read access to BIND credentials — all achievable with group permissions. Here's the complete list.

### 1. Create a dedicated user (optional but recommended)

You can run as any non-root user. If you want a dedicated service account:

```sh
# FreeBSD
pw useradd rpzuser -m -G named -s /usr/sbin/nologin

# Debian/Ubuntu
useradd -r -m -G bind -s /usr/sbin/nologin rpzuser
```

Adding the user to the `named`/`bind` group gives it read access to BIND key files.

### 2. Project directory

The user needs write access to the project directory for the venv, cache, and config:

```sh
chown -R rpzuser:rpzuser /opt/rpz-zone-factory
```

This covers:

- `.venv/` — Python virtual environment
- `.cache/` — source cache and HTTP metadata
- `.run-rpz.conf` — saved configuration

### 3. Zone file output directory

The user needs write access to wherever zone files are written:

```sh
# FreeBSD
chown named:named /usr/local/etc/namedb/master/rpz
chmod 775 /usr/local/etc/namedb/master/rpz
pw groupmod named -m rpzuser

# Debian/Ubuntu
chown bind:bind /etc/bind/zones/rpz
chmod 775 /etc/bind/zones/rpz
usermod -aG bind rpzuser
```

This also covers `allowlist.txt` and `allow-audit.log`, which live in the same directory.

### 4. rndc access

See [BIND Reload Permissions](#bind-reload-permissions) above. The recommended approach is granting the user read access to the rndc key file via group membership.

### 5. TSIG key access (for allow.sh and incremental updates)

The user needs read access to the TSIG key file:

```sh
# FreeBSD
chmod 640 /usr/local/etc/namedb/tsig/rpz-update.key
chown named:named /usr/local/etc/namedb/tsig/rpz-update.key

# Debian/Ubuntu
chmod 640 /etc/bind/tsig/rpz-update.key
chown bind:bind /etc/bind/tsig/rpz-update.key
```

The user's membership in the `named`/`bind` group (from step 1) covers this.

### 6. named-checkzone

`named-checkzone` is typically installed as part of the BIND utilities package and is world-executable. No special permissions needed. Verify with:

```sh
which named-checkzone && ls -la $(which named-checkzone)
```

### Summary

| Resource | Permission needed | How |
|----------|------------------|-----|
| Project directory | read/write | `chown` to the user |
| Zone file output directory | write | Group membership (`named`/`bind`) |
| `allowlist.txt`, `allow-audit.log` | write | Same as zone directory |
| `rndc.key` | read | Group membership |
| TSIG key file | read | Group membership |
| `named-checkzone` | execute | Already world-executable |
| `.venv/`, `.cache/` | read/write | Inside project directory |

## Pi-hole Configuration

To use the generated blocklist with Pi-hole:

1. Generate the blocklist file:

   ```sh
   ./run-rpz.sh -- --output pihole --output-file /tmp/rpz-blocklist.txt
   ```

   (Or configure Pi-hole output via `./run-rpz.sh --setup` so cron runs pick it up automatically.)

2. In the Pi-hole admin panel:
   - Go to **Group Management** > **Adlists**
   - If hosting the file on a web server, add the URL
   - Or place the file directly and add as a local list:

     ```sh
     cp /tmp/rpz-blocklist.txt /etc/pihole/custom.list
     pihole restartdns
     ```

3. Alternatively, use Pi-hole's gravity update:

   ```sh
   pihole -g  # update gravity after adding the list
   ```

> **Note:** Pi-hole only supports domain-based blocking. IP/CIDR entries from Spamhaus DROP and Emerging Threats are excluded from Pi-hole output.

## Platform Notes

### FreeBSD

- Python venv and pip may be separate packages:

  ```sh
  pkg install python311 py311-pip   # adjust version
  ```

- BIND config lives under `/usr/local/etc/namedb/`
- rndc is at `/usr/local/sbin/rndc`

### Debian / Ubuntu

- Python venv may need a separate package:

  ```sh
  apt install python3-venv python3-pip
  ```

- BIND config lives under `/etc/bind/`
- rndc is at `/usr/sbin/rndc`

## Project Structure

```
rpz-zone-factory/
├── run-rpz.sh          # Main orchestrator (cron/interactive wrapper)
├── allow.sh            # Dynamic allowlist management (TSIG + nsupdate)
├── run.py              # Python CLI entrypoint
├── Makefile            # `make deploy` → rsync to remote BIND host
├── README.md           # This file
├── PYTHON.md           # Direct-invocation reference for the Python CLI
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
│   │   ├── abusech.py         # Abuse.ch URLhaus RPZ feed parser
│   │   ├── cisa.py            # CISA KEV JSON parser
│   │   ├── cryptoscamdb.py    # CryptoScamDB YAML blacklist parser
│   │   ├── emergingthreats.py # Emerging Threats compromised-IPs parser
│   │   ├── scamsniffer.py     # Scam Sniffer JSON blacklist parser
│   │   └── spamhaus.py        # Spamhaus DROP parser
│   └── renderers/
│       ├── __init__.py
│       ├── rpz.py      # RFC 5782 zone file renderer + monotonic serial
│       └── pihole.py   # Flat domain list renderer
├── scripts/            # Legacy reference scripts (unused, kept for context)
├── .cache/             # Per-source cached entries + HTTP metadata (auto-created)
└── feeds/              # `.list.previous` baseline snapshots for incremental
                        #   diffs (auto-created next to the zone output dir)
```

`allow.sh` creates `allow-audit.log` in the zone output directory (next to `allowlist.txt`), not in the project directory.
