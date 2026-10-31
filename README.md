# rpz-zone-factory

Threat intelligence pipeline for DNS. Fetches from 12 public feeds, builds RFC 5782 RPZ zone files for BIND, and optionally outputs Pi-hole flat blocklists.  Currently used in a FreeBSD production environment, so it works, but may be a bit confusing to set up as the project has evolved over time.  I've tried to add Linux specific options, but those have not been extensively tested.

Per-source zones support **incremental updates via TSIG-authenticated `nsupdate`** so secondaries receive **NOTIFY → IXFR** with only the changed records, instead of re-AXFR'ing the whole zone on every refresh. Steady-state runs (no upstream changes) exit in seconds via a 304-aware fast-path.

## Before You Start

Have these in place before running `--setup`:

- **BIND 9.16 or later**, with RPZ support compiled in. The default `bind9` builds on Debian/Ubuntu and `bind918`/`bind916` on FreeBSD include it.
- **`rndc` working against your BIND instance.** Test with `rndc status`.
- **A non-root user to run as.** Don't run rpz-zone-factory as root. Either pick an existing non-root user, or follow [Running as a Non-Root User](#running-as-a-non-root-user) first.

The `--setup` wizard collects configuration but does NOT modify `named.conf`. The expected flow is:

1. Run `./run-rpz.sh --setup` to pick categories, configure TSIG, and save config.
2. Generate `named.conf` snippets for the categories you picked (see [BIND Configuration](#bind-configuration)) and merge them into your BIND config.
3. Restart BIND (or `rndc reconfig`) so it loads the new zone definitions.
4. Run `./run-rpz.sh -i` for the first test run.

## How It Works

Two shell scripts handle all operations:

- **`run-rpz.sh`**: the main orchestrator. Manages the Python venv, runs the pipeline, validates zones with `named-checkzone`, applies incremental updates via `nsupdate`, falls back to per-zone freeze/replace/thaw on full rebuilds, and (when nothing has changed) skips the entire pipeline via the v0.7.0 fast-path. Run it from cron or interactively. One-time `--setup` wizard configures everything.
- **`allow.sh`**: real-time allowlist management. Adds or removes domains from the RPZ allowlist zone via TSIG-authenticated `nsupdate`, with an append-only audit log. Preserves the journal so secondaries see the change as an IXFR delta.

The Python engine (`rpz_factory/`) does the actual fetching, parsing, filtering, and zone rendering. The shell scripts call it. You don't need to invoke Python directly. See [PYTHON.md](PYTHON.md) for direct-invocation reference and [ARCHITECTURE.md](ARCHITECTURE.md) for the developer deep-dive.

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

The `--setup` wizard walks through output format, threat categories (`CONF_CATEGORIES`), which categories use the incremental IXFR path (`CONF_INCREMENTAL_CATEGORIES`), BIND reload, `named-checkzone` validation, optionally `named-compilezone`, TSIG key configuration, and the feeds directory. All choices are saved to `.run-rpz.conf` so subsequent runs (including cron) need zero arguments.

### Cron examples

After `--setup`, the script reads `.run-rpz.conf` automatically. No CLI args needed:

```cron
# Per-source RPZ zones for BIND, every 4 hours - change directory to where you have it installed
15 */4 * * * /opt/rpz-zone-factory/run-rpz.sh

# With explicit args (overrides saved config)
15 */4 * * * /opt/rpz-zone-factory/run-rpz.sh -- --output rpz --output-file /etc/namedb/master/rpz/ -v

# Pi-hole flat file, daily at 3:05 AM
5 3 * * * /opt/rpz-zone-factory/run-rpz.sh -- --output pihole --output-file /var/www/rpz/block.txt
```

> With the v0.7.0 fast-path, runs that find no upstream changes complete in roughly the time it takes to make one conditional GET per configured source (a few seconds total) instead of running the full pipeline. Hourly cron schedules are reasonable if your upstream feeds publish frequently.

### Dynamic allowlist

```sh
# Allow a domain through RPZ (immediate, TSIG-authenticated)
./allow.sh example.com

# Remove it
./allow.sh -r example.com

# View the audit log
./allow.sh --audit
```

See `./allow.sh --setup` for TSIG key configuration, or the [allow.sh section](#allowsh-dynamic-allowlist) below for full details.

## Sources

Each feed produces one RPZ zone. As of v0.8.0, the zone filename encodes
its category: `<feed>.<category>.rpz`. When BIND synthesizes an NXDOMAIN
response from RPZ, the SOA in the authority section reveals which category
caused the block, so an operator looking at `dig` output can immediately
tell whether the entry is `ads`, `malware`, `ipreputation`, etc.

| Source | Category | Type | Zone | URL |
|--------|----------|------|------|-----|
| Abuse.ch URLhaus | malware | Domains (RPZ feed) | `urlhaus.malware.rpz` | https://urlhaus-api.abuse.ch/v2/files/exports/ (Auth-Key required, see below) |
| CISA KEV | vulnerabilities | Domains from CVE data | `cisa-kev.vulnerabilities.rpz` | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| Spamhaus DROP | ipreputation | IP/CIDR | `spamhaus-drop.ipreputation.rpz` | https://www.spamhaus.org/drop/drop.txt |
| Scam Sniffer | scam | Domains (crypto scams) | `scamsniffer.scam.rpz` | https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json |
| CryptoScamDB | scam | Domains (crypto phishing) | `cryptoscamdb.scam.rpz` | https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/urls.yaml |
| Emerging Threats | ipreputation | IPs (compromised hosts) | `et-compromised.ipreputation.rpz` | https://rules.emergingthreats.net/blockrules/compromised-ips.txt |
| AdGuard DNS | ads | Domains | `adguard-dns.ads.rpz` | https://v.firebog.net/hosts/AdguardDNS.txt |
| anudeepND adservers | ads | Domains (hosts file) | `anudeepnd.ads.rpz` | https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt |
| EasyPrivacy | tracking | Domains | `easyprivacy.tracking.rpz` | https://v.firebog.net/hosts/Easyprivacy.txt |
| AntiMalwareHosts | malware | Domains (hosts file) | `antimalware-hosts.malware.rpz` | https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt |
| Prigent Crypto | cryptojacking | Domains | `prigent-crypto.cryptojacking.rpz` | https://v.firebog.net/hosts/Prigent-Crypto.txt |
| developerdan ads-and-tracking | ads | Domains (hosts file) | `developerdan.ads.rpz` | https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt |

Categories: `malware`, `ads`, `tracking`, `scam`, `cryptojacking`,
`ipreputation`, `vulnerabilities`. Pick categories at `--setup` time, or
edit `CONF_CATEGORIES` in `.run-rpz.conf`. Add or drop individual feeds
with `CONF_SOURCES_EXTRA` / `CONF_SOURCES_EXCLUDE`.

### abuse.ch Auth-Key

abuse.ch retired keyless downloads in October 2026; the old URLhaus RPZ
endpoint now returns HTTP 410. The urlhaus feed therefore needs a free
Auth-Key.

**Registering and getting the key:**

1. Go to the abuse.ch authentication portal at https://auth.abuse.ch/.
   There are no password accounts: sign in with GitHub, Google, LinkedIn,
   or X, or request a one-time sign-in link by email. First sign-in creates
   the account; authenticating means accepting the abuse.ch Terms of Use.
2. Once signed in, create an Auth-Key on your profile page and copy it.
   One key covers every abuse.ch platform (URLhaus,
   ThreatFox, MalwareBazaar, Feodo Tracker, SSL Blacklist), so if you
   already have a key for another abuse.ch service, reuse it.
3. The key is free for non-commercial use under the abuse.ch Fair Use
   Policy (https://abuse.ch/terms-of-use/#principles). abuse.ch generates
   the RPZ export every 5 minutes and asks that you not fetch more often
   than that; this pipeline fetches hourly with conditional requests, well
   inside the limit. abuse.ch rate-limits accounts with unusually high
   query volumes. Commercial / for-profit use may require the paid
   Spamhaus commercial API instead.

**Installing the key:**

1. Put the key in a file by itself, readable only by the operator account:

   ```sh
   printf '%s\n' 'YOUR-KEY' > ~/rpz-zone-factory/abuse.ch.key
   chmod 600 ~/rpz-zone-factory/abuse.ch.key
   ```

2. Point the pipeline at it: run `./run-rpz.sh --setup` and enter the path
   at the Auth-Key file prompt, or set `CONF_ABUSECH_AUTH_KEY_FILE` in
   `.run-rpz.conf` directly.

`run-rpz.sh` reads the file at run time and hands the key to Python through
the `ABUSECH_AUTH_KEY` environment variable, never through argv. The key
is substituted into the download URL at request time only. Logs, error
messages, and the syslog Args line always carry the URL template with the
key masked, and both the key file and `.run-rpz.conf` are gitignored, so
the key never lands in the repo, syslog, or `ps` output. Without a key,
the urlhaus feed logs a fetch error each run and keeps serving its last
cached data; every other built-in feed is unaffected.

If abuse.ch changes the export path, override the whole URL template with
the `URLHAUS_RPZ_URL` environment variable (keep the literal `{auth_key}`
placeholder in it).

### Drift monitoring (drift-check.sh)

`drift-check.sh` watches for the failures that syslog records but nobody
reads: slaved zones drifting from their master or expiring out of service,
RPZ zones not propagating to secondaries, feeds erroring persistently
behind a successful exit code, and the cron pipeline not running at all.
Problems go to syslog for forensics and to a Discord webhook for attention.
Serial mismatches are re-checked after a 90-second settle so an in-flight
refresh does not page, and an unchanged alert is suppressed for 24 hours.

Setup: create a webhook (Discord channel settings, Integrations,
Webhooks), put its URL in `discord.webhook` next to the script (mode 600;
gitignored), verify with `./drift-check.sh --test`, then add a cron entry
offset from the pipeline run:

```
47 * * * * /path/to/rpz-zone-factory/drift-check.sh
```

Configuration lives in `.run-rpz.conf`. `CONF_MONITOR_REF_MASTER` (the
master to compare slaved zones against) and `CONF_MONITOR_SECONDARIES`
(the RPZ secondaries) have no in-script defaults, so site addressing
stays out of the repo; while either is unset the corresponding check is
off and the script alerts about that instead of skipping quietly.
`CONF_MONITOR_WEBHOOK_FILE`, `CONF_MONITOR_EXCLUDE_ZONES`, and
`CONF_MONITOR_RESEND_HOURS` are optional.

### Feed attribution and licensing

All threat and blocklist data comes from the providers above; this project
is grateful for their work and redistributes none of it. The pipeline
fetches each feed directly from its source at run time, and the zone files
it generates are derived from that data, so your use of them is governed by
each provider's terms, not this project's MIT license. Some providers
(Spamhaus DROP, for example) restrict commercial use. If you run this
anywhere other than a personal network, check the license or terms of use
for each feed you enable before deploying.

## Adding Your Own Feeds

The feeds above are built in. To add a feed from any other URL without
touching the code, drop it into `user-feeds.yaml` at the repo root (override
the path with the `RPZ_USER_FEEDS` environment variable). If the file is
absent, nothing changes.

```yaml
feeds:
  - key: my-corp-blocklist        # CLI token, cache name, zone-name stem
    category: malware             # must be one of the categories above
    url: https://example.com/blocklist.txt
    kind: domain                  # domain (default) or ip
    label: "Corp blocklist"       # optional, used only in log lines

  - key: my-bad-ips
    category: ipreputation
    url: https://example.com/bad-ips.txt
    kind: ip
```

- `kind: domain` accepts plain-domain and hosts-file lists (the same formats
  the built-in community feeds use).
- `kind: ip` accepts plain IPv4 address and CIDR lists. **IPv4 only** for now:
  the `rpz-ip` encoding this tool emits is IPv4, so IPv6 lines are dropped (and
  counted). A feed that turns out to be mostly IPv6 logs a WARNING so it cannot
  silently render an almost-empty zone.
- A feed reuses one of the existing categories, so it inherits that category's
  zone-name scheme (`<key>.<category>.rpz`) and update mode (IXFR vs full
  rebuild). Custom categories are out of scope.

After editing the file, validate it:

```sh
python -m rpz_factory.categories validate-feeds
```

This exits non-zero and prints every problem (bad key, unknown category, bad
URL, a key or derived zone that collides with a built-in, etc.). A bad feed is
**skipped, not fatal**: the built-in feeds always run, and each run prints a
`WARNING: user-feeds: loaded N, SKIPPED M ...` line naming what was dropped, so
a typo never silently removes coverage.

### Activating a new feed in BIND

A feed in the registry is a feed that gets *rendered*. It is not yet a feed BIND
*serves*. Adding the feed to `user-feeds.yaml` does not, by itself, create the
zone in `named.conf`. The order to follow is **render first, then provision**:

1. Add the feed to `user-feeds.yaml`; run `validate-feeds`.
2. Run `run-rpz.sh` once. Python renders `<key>.<category>.rpz.db` into the zone
   directory. Because the zone is not in `named.conf` yet, the run stages the
   file but cannot activate it, and prints:
   `user-feeds: rendered but NOT served by BIND (no named.conf zone): ...`
3. Regenerate the `named.conf` zone block and response-policy entry. The
   generator already includes the new zone:
   `python -m rpz_factory.categories bind-config ...` (or re-run
   `run-rpz.sh --setup`). Install it and run `rndc reconfig`. BIND loads the
   `.db` staged in step 2 and the feed is live.
4. From then on, `run-rpz.sh` manages the zone automatically.

### Removing a feed

Deleting a feed from `user-feeds.yaml` stops it being rendered, but the live
`<zone>.db`, its `named.conf` block, any `.db.jnl` journal, and the
`<feeds>/<zone>.list.*` snapshots remain on disk, and the zone keeps serving its
last render. Teardown is manual (the tool never deletes live zone files):

1. Remove the feed from `user-feeds.yaml`.
2. `python -m rpz_factory.categories list-orphans --zone-dir <zone-dir> [--feeds-dir <feeds-dir>]`
   reports every live file no longer backed by the registry. `run-rpz.sh` also
   prints this list on every run until the zone is torn down.
3. Remove the zone's `named.conf` block and response-policy entry; `rndc reconfig`.
4. Delete the orphaned `<zone>.db`, `<zone>.db.jnl`, and `<zone>.list.*` files.

## Requirements

- BIND 9.16+ with RPZ support (see [Before You Start](#before-you-start) for distribution notes)
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

**Output:**

| Setting | Description |
|---------|-------------|
| `CONF_OUTPUT` | `rpz` or `pihole` |
| `CONF_OUTPUT_FILE` | Output directory (RPZ) or file path (Pi-hole) |
| `CONF_VERBOSITY` | `0` (quiet), `1` (`-v`), `2` (`-vv`) |

**Source/category selection (v0.7.0+):**

| Setting | Description |
|---------|-------------|
| `CONF_CATEGORIES` | Space-separated categories to fetch (e.g. `malware ads tracking`). When set, replaces the legacy `CONF_SOURCES` selection. |
| `CONF_SOURCES_EXTRA` | Individual feed keys to add on top of the resolved category selection |
| `CONF_SOURCES_EXCLUDE` | Individual feed keys to drop from the resolved selection |
| `CONF_SOURCES` | (Legacy, pre-v0.7.0.) Space-separated source list, or `all`. Honored only when `CONF_CATEGORIES` is empty. |
| `CONF_ABUSECH_AUTH_KEY_FILE` | Path to a file holding the abuse.ch Auth-Key (required by the urlhaus feed; see "abuse.ch Auth-Key" above). Read at run time and exported to Python as `ABUSECH_AUTH_KEY`. |

**BIND reload + validation:**

| Setting | Description |
|---------|-------------|
| `CONF_RELOAD` | `yes` or `no` (handle BIND reloads/freeze/thaw after updates) |
| `CONF_CHECKZONE` | `yes` or `no` (validate with `named-checkzone`) |
| `CONF_COMPILE_ZONE` | `yes` or `no` (compile to binary, raw format) |

**Allowlist / dynamic updates:**

| Setting | Description |
|---------|-------------|
| `CONF_ALLOWLIST_FILE` | Path to allowlist text file |
| `CONF_TSIG_KEY_FILE` | Path to TSIG key file (shared by `allow.sh` and the v0.6.0 incremental update path) |
| `CONF_TRANSFER_TSIG_KEY_FILE` | (v0.8.0+) Path to a separate TSIG key for zone transfers when running split-key mode. Empty = use `CONF_TSIG_KEY_FILE` for both update and transfer. |
| `CONF_ALLOW_SERVER` | Server for nsupdate (default: `localhost`) |
| `CONF_ALLOW_ZONE` | Allowlist zone name (default: `allowlist.rpz`) |
| `CONF_AUDIT_LOG` | Path to audit log file (default: `allow-audit.log` next to allowlist) |

**Incremental (IXFR) updates (v0.6.0+):**

| Setting | Description |
|---------|-------------|
| `CONF_FEEDS_DIR` | Directory holding `.list.previous` baseline snapshots for the incremental update path. Default: `<output>/feeds`. The allowlist `.txt` source file lives here too. |
| `CONF_INCREMENTAL_CATEGORIES` | (v0.7.0+, preferred) Space-separated categories whose feeds should use the IXFR update path. Resolved against `CONF_CATEGORIES` at runtime. |
| `CONF_INCREMENTAL_ZONES` | (Legacy, pre-v0.7.0.) Space-separated zone filenames that should use the IXFR update path. Still honored when `CONF_INCREMENTAL_CATEGORIES` is empty. |
| `CONF_INCREMENTAL_TTL` | TTL for records emitted via `nsupdate` (default: `300`) |
| `CONF_NSUPDATE_MAX_BATCH_BYTES` | (v0.9.1+) Maximum bytes for a single `nsupdate` batch (text, not wire). Oversized batches are split into multiple chunked transactions so they fit BIND's 65535-byte DNS message limit. Default: `600000`. See [Serial-bump budget](#serial-bump-budget-v091) for tuning notes. |
| `CONF_NSUPDATE_MAX_CHUNKS_PER_RUN` | (v0.9.1+) If a zone's projected diff would require more than this many chunks in a single run, fall back to full rebuild instead of chunking. Default: `4`. Bounds per-run SOA-serial bumps and keeps chunking from out-competing a full rebuild on round-trip cost. |
| `CONF_FEED_LOG_DIR` | Optional directory for per-feed delta logs (when `CONF_LOG_REBUILDS` enables logging) |
| `CONF_LOG_REBUILDS` | `yes` or `no`: whether to write a snapshot of each zone's domain list during full rebuilds (default: `no`) |

A zone uses incremental updates when its feed's category is in `CONF_INCREMENTAL_CATEGORIES`, OR its zone filename is in the legacy `CONF_INCREMENTAL_ZONES`. With both empty, every zone goes through the full rebuild path.

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
- **Reused** on subsequent runs (no reinstall overhead)
- **Auto-healed**: if the venv is broken (missing python, missing deps), the script recreates it
- **No activation/deactivation**: the script calls the venv's python binary directly. No `source activate` fragility.

## Incremental Updates (IXFR, v0.6.0+)

Per-source zones listed in `CONF_INCREMENTAL_ZONES` are updated by **diffing the previously-fetched feed against the freshly generated zone** and sending only the additions/deletions via TSIG-authenticated `nsupdate`. BIND writes the delta to the zone's journal, bumps the SOA serial, and secondaries receive **NOTIFY → IXFR** instead of re-AXFR'ing the whole zone. This turns megabyte transfers into hundred-byte deltas.

On a typical day, upstream feeds add or remove a handful of domains. A single domain add transfers as 6 records (~230 bytes), versus the full zone (~5000+ records, ~150KB for `urlhaus.malware.rpz`).

### How a zone goes from cold to incremental

1. **First run for a zone:** no `.list.previous` baseline exists yet, so the zone takes the full rebuild path (per-zone freeze → file replace → thaw). After the rebuild, run-rpz.sh extracts the domain list from the freshly rendered `.db` and writes it to `<feeds>/<zone>.list.previous`. This is the **seed**.
2. **Subsequent runs:** the script diffs the new feed against `.list.previous`. If `adds=0 dels=0`, nothing happens (no nsupdate, no journal entry, no secondary traffic). If there are real diffs, a TSIG-authenticated `nsupdate` transaction adds and removes only the changed records, BIND auto-bumps the serial and writes a journal entry, and secondaries pick up the delta via IXFR. (As of v0.9.1, batches larger than `CONF_NSUPDATE_MAX_BATCH_BYTES` are split across multiple back-to-back nsupdate transactions; see [Serial-bump budget](#serial-bump-budget-v091).)
3. **`.list.previous` is refreshed** after each successful incremental run so the next diff is computed against the current state.

### Falling back to full rebuild

A zone configured for incremental updates will silently drop back to the full rebuild path if any of the following are true:

- The zone has no `.list.previous` snapshot (first-ever run, or `--full-rebuild` was used)
- TSIG is not configured (`CONF_TSIG_KEY_FILE` missing or unreadable)
- `nsupdate` itself fails for any reason
- The projected nsupdate batch would require more than `CONF_NSUPDATE_MAX_CHUNKS_PER_RUN` chunks (v0.9.1+; see [Serial-bump budget](#serial-bump-budget-v091))
- You explicitly pass `--full-rebuild`

A full rebuild always re-seeds `.list.previous` afterward, so a zone can flip back to incremental on the next run.

### BIND configuration requirements

**Every zone selected for IXFR (via `CONF_INCREMENTAL_CATEGORIES` or the legacy `CONF_INCREMENTAL_ZONES`) must have `allow-update { key "rpz-update"; };` in its `named.conf` definition**, including the per-source threat zones, not just the allowlist. Without this, `nsupdate` will be REFUSED and the zone falls back to full rebuild on every run. See the [BIND Configuration](#bind-configuration) section below for complete zone examples.

### Per-zone freeze/thaw (full rebuild path)

When a zone IS in the full rebuild bucket (seed run, fallback, or `--full-rebuild`), run-rpz.sh handles it via **per-zone** `rndc freeze <zone>` → atomic file replace → `rndc thaw <zone>`, not a global freeze/thaw. This is required for dynamic zones (zones with `allow-update`) because:

- `rndc reload <zone>` flatly fails on dynamic zones with `'reload' failed: dynamic zone`
- A global `rndc thaw` is asynchronous and races against the freshly-replaced file, producing `zone serial has gone backwards` warnings
- Per-zone `rndc thaw <zone>` re-reads the file synchronously, eliminating the race

Static (non-dynamic) zones in the full bucket use plain `rndc reload <zone>` instead.

### Verifying IXFR is working

On a secondary, look for transfer log entries with a small record count:

```
zone urlhaus.malware.rpz/IN: Transfer started.
transfer of 'urlhaus.malware.rpz/IN' from <primary>#53: Transfer completed: 1 messages, 6 records, 229 bytes (serial 2026040827)
```

`6 records` is the IXFR delta for a single domain add (old SOA, new SOA, two CNAMEs for `domain` and `*.domain`). If you instead see hundreds or thousands of records for what should have been a small change, the secondary is doing AXFR. Check that the primary has `allow-update` on the zone and that `nsupdate` is succeeding.

When v0.9.1 chunking kicks in for an oversized diff, the secondary log will show N back-to-back transfer entries in quick succession (one per chunk), each with its own small record count. That is expected; the total across them is what an un-chunked transfer would have moved.

### Serial-bump budget (v0.9.1+)

run-rpz.sh's RPZ renderer uses an SOA serial in the format `YYYYMMDDNN` where `NN` is a per-day counter, giving 100 increments per zone per day before the format overflows into the next day's stem. Every operation that updates a zone bumps the serial by 1:

- Each scheduled run that produces a non-empty diff for a zone (1 bump per zone per run).
- Each chunk emitted by `apply_nsupdate_chunked` when a zone's diff exceeds `CONF_NSUPDATE_MAX_BATCH_BYTES` (up to `CONF_NSUPDATE_MAX_CHUNKS_PER_RUN` per zone per run).
- Each `allow.sh` `add` or `remove` operation against the allowlist zone.
- Each full rebuild (1 bump per rebuilt zone).

For most zones, hourly cron and modest activity stay well under 100/day. The risk is concentrated on **active feeds running under aggressive cron schedules**: e.g. a frequently-updated adlist with a 5-minute cron interval, where a single afternoon of accumulated changes triggers multi-chunk runs back-to-back. If a zone's daily bump count crosses 99, the serial format silently rolls into the next day's stem and the following day's first rebuild can compute a serial less than or equal to the running serial, producing `zone serial unchanged` or `zone serial has gone backwards` warnings on secondaries.

This is operator responsibility, not script enforcement. The chunker hard-caps per-run bumps at `CONF_NSUPDATE_MAX_CHUNKS_PER_RUN` (default 4): above the cap it falls back to full rebuild, which costs 1 bump + 1 AXFR per secondary instead of N bumps + N IXFR streams per secondary. The cumulative-across-runs picture is left to you. Guidance:

- **Pick a cron interval matched to your feed cadence.** Hourly is sane for most threat feeds and stays well under any plausible serial budget. 5-minute intervals on a high-churn adlist are where you start eating budget. The [Quick Start cron examples](#cron-examples) above use 4-hourly, which is a reasonable middle ground for most setups.
- **Tune `CONF_NSUPDATE_MAX_BATCH_BYTES`** if you observe many runs being split into multiple chunks. The default `600000` is conservative (observed BIND overflow at ~910 KB on a typical feed); BIND on capable hardware may tolerate higher. Watch the `nsupdate batch N bytes` INFO log lines to see your actual batch sizes.
- **Lower `CONF_NSUPDATE_MAX_CHUNKS_PER_RUN`** to push more big-diff cases into full rebuild. Setting it to `1` disables chunking entirely (any oversized batch falls back to full rebuild).
- **Watch for `gone backwards` warnings** in BIND logs on secondaries; that's the canary that the serial budget was exceeded.

## Fast-path: skip when nothing changed (v0.7.0+)

Every HTTP feed uses `If-Modified-Since` / `ETag` headers. When every requested source returns `304 Not Modified`, run-rpz.sh exits in roughly the time it takes to make the conditional HTTP requests (a few seconds for the full set) instead of running the full pipeline (~30s in steady state).

- **RPZ output (per-zone fast-path):** any zone whose source returned 304 with no error and whose live `.db` exists is skipped entirely (no parse, no filter, no render, no diff, no IXFR, no seed, no reload). Zones with new content render normally on the same run.
- **Pi-hole output (whole-file fast-path):** if every source returned 304 and the live blocklist file exists, the Python engine exits with code 3 and run-rpz.sh skips its post-processing.
- **Allowlist:** the allowlist source is a local text file, not HTTP, so the fast-path uses an mtime check instead. If `allowlist.txt` hasn't been modified since the live `allowlist.rpz.db` was last written, the allowlist render is skipped.
- **`--force`** bypasses all of this and forces a full pipeline run. Use after manual zone edits or for debugging.

The fast-path is safe: 304 means upstream content is unchanged, the cached `.previous` snapshot still matches, and BIND's in-memory state is already correct. There's nothing to do. HTTP metadata is stored in `.cache/*.meta.json`.

## allow.sh: Dynamic Allowlist

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
2. Appends/removes the domain in the allowlist text file (race condition safe: file is updated before the dynamic update)
3. Sends `nsupdate` with TSIG key to add/remove RPZ passthru records
4. Runs `rndc sync <zone>` to flush in-memory state to the `.db` file. **The journal (`.jnl`) is preserved** so secondaries can pull the change via IXFR instead of re-AXFR'ing the whole zone.
5. Writes an entry to the audit log (success or failure)

### Audit log

Every add/remove operation is logged to an append-only audit log. The log records:

- Timestamp (local time with UTC offset)
- Action (`add` or `remove`)
- Domain
- Operator (`whoami`, who ran the command)
- Result (`OK` or `FAIL:reason`)

Failures are logged too. If `nsupdate` fails, the log records the exit code.

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

`--audit` doesn't require a TSIG key, domain, or any preflight. It just reads the log file.

### TSIG setup

Run `./allow.sh --setup` for step-by-step instructions covering key generation, directory permissions, `named.conf` changes, and testing.

The `run-rpz.sh --setup` wizard also walks through TSIG configuration when RPZ output with an allowlist is enabled.

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

You need three things in `named.conf` per selected zone:

1. A `zone { ... };` block declaring the primary, file path, ACLs, and `allow-update` (for zones that use the incremental IXFR path).
2. An entry in a `response-policy { ... };` stanza inside `options { }`, in the right order (allowlist first with `policy passthru`).
3. The TSIG key referenced by `allow-update`, typically pulled in via `include "/etc/bind/tsig/rpz-update.key";` at the top level. See `./allow.sh --setup` for the key generation walkthrough.

The exact set of zones you need depends on which categories you picked at `--setup`. The selection table you saw in [Sources](#sources) above tells you what zone filename each feed produces.

#### Generate the snippets

Rather than hand-writing the `zone {}` blocks for every category combination, let the registry generate them. The same selection flags accepted by the wizard work here:

```sh
# Default: all categories, zones into /etc/namedb/master/rpz, TSIG key "rpz-update"
python -m rpz_factory.categories bind-config

# Match what you set up: just malware and ads, custom paths
python -m rpz_factory.categories bind-config \
    --categories malware ads \
    --zone-dir /usr/local/etc/namedb/master/rpz \
    --tsig-key rpz-update \
    --transfer-acl my-secondaries

# Just the response-policy block (e.g. to merge into an existing options { })
python -m rpz_factory.categories bind-config \
    --categories malware ads \
    --section policy

# Skip the allowlist zone (if you don't want one)
python -m rpz_factory.categories bind-config --no-allowlist

# Use split-TSIG mode (separate transfer key)
python -m rpz_factory.categories bind-config \
    --transfer-tsig-key rpz-transfer
```

Run `python -m rpz_factory.categories bind-config --help` for the full flag list. Pipe the output to a file (`> /etc/bind/rpz.conf`) and `include` it from `named.conf`, or paste the contents directly.

The command emits `allow-update` on every zone by default. That's harmless for static (non-incremental) zones and avoids `REFUSED` errors when you later add a zone to `CONF_INCREMENTAL_CATEGORIES`. Pass `--tsig-key ""` to suppress it entirely.

#### Example output

For `--categories malware`, the command produces:

```bind
// Allowlist zone: evaluated first, passthru overrides blocks
zone "allowlist.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/allowlist.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};

// Threat source zones

zone "urlhaus.malware.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/urlhaus.malware.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};

zone "antimalware-hosts.malware.rpz" {
    type primary;
    file "/etc/namedb/master/rpz/antimalware-hosts.malware.rpz.db";
    allow-update { key "rpz-update"; };
    allow-query { localhost; secondaries; };
    allow-transfer { secondaries; };
    also-notify { /* secondary IPs */ };
};


options {
    // ... your existing options ...

    response-policy {
        zone "allowlist.rpz" policy passthru;
        zone "urlhaus.malware.rpz";
        zone "antimalware-hosts.malware.rpz";
    };
};
```

RPZ zones are evaluated in order. The allowlist goes first with `policy passthru` so it can override blocks from subsequent zones. **Every zone needs `allow-update`** for the incremental path to work. Without it, `nsupdate` will be REFUSED and the zone silently falls back to full rebuild on every run, forcing secondaries to AXFR.

Replace the placeholder ACL `secondaries` (and `also-notify`) with your real values via `--allow-query-acl`, `--transfer-acl`, or by hand-editing after generation.

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

Don't run rpz-zone-factory as root. The pipeline needs write access to a few specific paths and read access to BIND credentials, all achievable with group permissions. Here's the complete list.

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

- `.venv/`: Python virtual environment
- `.cache/`: source cache and HTTP metadata
- `.run-rpz.conf`: saved configuration

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
├── README.md           # This file
├── PYTHON.md           # Direct-invocation reference for the Python CLI
├── ARCHITECTURE.md     # Developer reference (per-zone state machine, IXFR design)
├── LICENSE             # MIT
├── requirements.txt
├── .run-rpz.conf       # Generated by --setup (not in repo)
├── rpz_factory/
│   ├── __init__.py        # __version__
│   ├── categories.py      # Feed/zone/category registry + bind-config generator
│   ├── cli.py             # argparse CLI, conditional HTTP, fast-path, summary output
│   ├── cache.py           # Per-source cache + HTTP metadata persistence
│   ├── fetcher.py         # HTTP fetch with retry/timeout, If-Modified-Since/ETag
│   ├── filters.py         # False positive filtering logic
│   ├── models.py          # Dataclasses: ThreatEntry, FetchResult, HttpMeta, etc.
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── abusech.py          # Abuse.ch URLhaus RPZ feed parser
│   │   ├── cisa.py             # CISA KEV JSON parser
│   │   ├── cryptoscamdb.py     # CryptoScamDB YAML blacklist parser
│   │   ├── emergingthreats.py  # Emerging Threats compromised-IPs parser
│   │   ├── plaintext.py        # Generic parser for hosts-file / plain-domain feeds
│   │   ├── scamsniffer.py      # Scam Sniffer JSON blacklist parser
│   │   └── spamhaus.py         # Spamhaus DROP parser
│   └── renderers/
│       ├── __init__.py
│       ├── rpz.py         # RFC 5782 zone file renderer + monotonic serial
│       └── pihole.py      # Flat domain list renderer
├── .cache/             # Per-source cached entries + HTTP metadata (auto-created)
└── feeds/              # `.list.previous` baseline snapshots for incremental
                        #   diffs (auto-created next to the zone output dir)
```

`allow.sh` creates `allow-audit.log` in the zone output directory (next to `allowlist.txt`), not in the project directory.

## License

MIT. See [LICENSE](LICENSE).
