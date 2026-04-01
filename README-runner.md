# run-rpz.sh — Cron/Interactive Wrapper for rpz-zone-factory

Portable POSIX shell wrapper for running [rpz-zone-factory](https://github.com/richgoodson/rpz-zone-factory) on a schedule via cron, or interactively from the command line. Works on **Debian**, **Ubuntu**, and **FreeBSD 13+**.

## Quick Start

```sh
# 1. Clone rpz-zone-factory
git clone https://github.com/richgoodson/rpz-zone-factory.git /opt/rpz-zone-factory
cd /opt/rpz-zone-factory

# 2. Run the setup wizard (creates venv, installs deps, configures everything)
./run-rpz.sh --setup

# 3. Test interactively
./run-rpz.sh -i

# 4. Add to cron (the wizard generates the cron entry for you)
crontab -e
```

The `--setup` wizard walks through output format, per-source mode, zone names, BIND reload, `named-checkzone` validation, and optionally `named-compilezone`. All choices are saved to `.run-rpz.conf` so subsequent runs (including cron) need zero arguments.

## Cron Examples

After running `--setup`, the script reads `.run-rpz.conf` automatically — no CLI args needed:

### Per-source RPZ zones for BIND (every 4 hours)
```
15 */4 * * * /opt/rpz-zone-factory/run-rpz.sh
```

### With explicit args (overrides saved config)
```
15 */4 * * * /opt/rpz-zone-factory/run-rpz.sh -- --output rpz --per-source --output-file /etc/namedb/master/rpz/ -v
```

### Pi-hole flat file (daily at 3:05 AM)
```
5 3 * * * /opt/rpz-zone-factory/run-rpz.sh -- --output pihole --output-file /usr/local/www/rpz-zone-factory/block.txt
```

## Modes

| Mode | Flag | Behavior |
|------|------|----------|
| Interactive | `-i` or `--interactive` | Output to stdout/stderr. Auto-detected when run from a terminal. |
| Cron | `-c` or `--cron` | Logs via `logger` (syslog). Auto-detected when stdin is not a terminal. |

## Options

| Option | Description |
|--------|-------------|
| `-v`, `--version` | Print version and exit |
| `-h`, `--help` | Show usage and exit |
| `-i`, `--interactive` | Force interactive mode |
| `-c`, `--cron` | Force cron mode |
| `--setup` | Interactive setup wizard: configure output, sources, BIND reload, zone validation/compilation, and generate cron entries |
| `--reload-bind ZONE` | After successful run, call `rndc reload ZONE` |
| `--rpz-dir DIR` | Override RPZ_DIR (can also set via environment) |
| `--python BIN` | Override Python binary (default: `python3.11`) |
| `-- ARGS...` | Everything after `--` is passed to rpz-zone-factory |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RPZ_DIR` | Script's own directory | Path to rpz-zone-factory project |
| `PYTHON_BIN` | `python3.11` | Python interpreter (setup wizard scans for 3.9–3.14) |
| `VENV_NAME` | `.venv` | Venv directory name within RPZ_DIR |
| `RNDC_BIN` | `rndc` | Path to rndc binary |

## Configuration File

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

Edit `.run-rpz.conf` directly or re-run `--setup` to reconfigure.

## BIND Reload Permissions

The `--reload-bind` option runs `rndc reload <ZONE>`. The user executing the script needs rndc access. Pick one approach:

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
15 */4 * * * sudo -u named RPZ_DIR=/opt/rpz-zone-factory /usr/local/sbin/run-rpz.sh --reload-bind block.rpz -- --output rpz --zone-name block.rpz --output-file /var/named/rpz/block.rpz.db
```

The user also needs write access to the output file directory.

### 4. Passwordless sudo for rndc only (least recommended)

In `/etc/sudoers.d/rpz-rndc`:
```
rpzuser ALL=(ALL) NOPASSWD: /usr/sbin/rndc reload *
```

Then: `RNDC_BIN="sudo rndc" /usr/local/sbin/run-rpz.sh --reload-bind block.rpz -- ...`

## Platform Notes

### FreeBSD
- Python venv and pip may be separate packages:
  ```sh
  pkg install python39 py39-pip py39-venv   # adjust version
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

## Logging

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

## Venv Lifecycle

- **Created** on first run (or via `--setup`)
- **Reused** on subsequent runs — no reinstall overhead
- **Auto-healed**: if the venv is broken (missing python, missing deps), the script recreates it
- **No activation/deactivation**: the script calls the venv's python binary directly — no `source activate` fragility
