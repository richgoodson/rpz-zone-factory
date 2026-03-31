# run-rpz.sh — Cron/Interactive Wrapper for rpz-zone-factory

Portable POSIX shell wrapper for running [rpz-zone-factory](https://github.com/your-org/rpz-zone-factory) on a schedule via cron, or interactively from the command line. Works on **Debian**, **Ubuntu**, and **FreeBSD 13+**.

## Quick Start

```sh
# 1. Clone rpz-zone-factory somewhere
git clone https://github.com/your-org/rpz-zone-factory.git /opt/rpz-zone-factory

# 2. Copy this script somewhere in PATH
cp run-rpz.sh /usr/local/sbin/run-rpz.sh
chmod +x /usr/local/sbin/run-rpz.sh

# 3. Run first-time setup (creates venv, installs deps)
RPZ_DIR=/opt/rpz-zone-factory /usr/local/sbin/run-rpz.sh --setup

# 4. Test interactively
RPZ_DIR=/opt/rpz-zone-factory /usr/local/sbin/run-rpz.sh -i -- --output rpz --zone-name block.rpz -v

# 5. Add to cron
crontab -e
```

## Cron Examples

### RPZ zone file for BIND (every 4 hours, reload zone after)
```
15 */4 * * * RPZ_DIR=/opt/rpz-zone-factory /usr/local/sbin/run-rpz.sh --reload-bind block.rpz -- --output rpz --zone-name block.rpz --output-file /etc/namedb/rpz/block.rpz.db
```

### Pi-hole flat file (daily at 3:30 AM)
```
30 3 * * * RPZ_DIR=/opt/rpz-zone-factory /usr/local/sbin/run-rpz.sh -- --output pihole --output-file /etc/pihole/custom-rpz.list
```

### Specific sources only
```
0 6 * * * RPZ_DIR=/opt/rpz-zone-factory /usr/local/sbin/run-rpz.sh -- --output rpz --zone-name threat.rpz --sources urlhaus cisa scamsniffer cryptoscamdb --output-file /var/named/rpz/threat.rpz.db
```

## Modes

| Mode | Flag | Behavior |
|------|------|----------|
| Interactive | `-i` or `--interactive` | Output to stdout/stderr. Auto-detected when run from a terminal. |
| Cron | `-c` or `--cron` | Logs via `logger` (syslog). Auto-detected when stdin is not a terminal. |

## Options

| Option | Description |
|--------|-------------|
| `-h`, `--help` | Show usage and exit |
| `-i`, `--interactive` | Force interactive mode |
| `-c`, `--cron` | Force cron mode |
| `--setup` | First-run setup: create venv, install deps, verify |
| `--reload-bind ZONE` | After successful run, call `rndc reload ZONE` |
| `--rpz-dir DIR` | Override RPZ_DIR (can also set via environment) |
| `--python BIN` | Override Python binary (default: `python3`) |
| `-- ARGS...` | Everything after `--` is passed to rpz-zone-factory |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RPZ_DIR` | `/opt/rpz-zone-factory` | Path to rpz-zone-factory project |
| `PYTHON_BIN` | `python3` | Python interpreter |
| `VENV_NAME` | `.venv` | Venv directory name within RPZ_DIR |
| `RNDC_BIN` | `rndc` | Path to rndc binary |

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

# FreeBSD
grep rpz-zone-factory /var/log/messages
```

## Venv Lifecycle

- **Created** on first run (or via `--setup`)
- **Reused** on subsequent runs — no reinstall overhead
- **Auto-healed**: if the venv is broken (missing python, missing deps), the script recreates it
- **No activation/deactivation**: the script calls the venv's python binary directly — no `source activate` fragility
