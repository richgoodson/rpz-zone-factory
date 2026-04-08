#!/bin/sh
# allow.sh — Dynamic RPZ allowlist management via TSIG-authenticated nsupdate
# Version: 0.5.0
# Portable: Debian, Ubuntu, FreeBSD 13+
# POSIX sh — no bashisms.
#
# Adds or removes domains from the RPZ allowlist zone using nsupdate
# with TSIG authentication, and persists changes to the allowlist text
# file so they survive rpz-zone-factory regeneration runs.
#
# v0.5.0: Allowlist text file now lives in CONF_FEEDS_DIR (alongside the
#         other feed snapshots). Changes to the text file are reverted on
#         nsupdate failure to keep the feed and live zone in sync.
#
# See usage() below or run with -h/--help.

# ─── Defaults ─────────────────────────────────────────────────────────────────
# Override these via .run-rpz.conf, environment, or flags.
# Flags take precedence over .run-rpz.conf, which takes precedence over these.

# TSIG key file path — REQUIRED, no fallback to ACL
# Detected per-platform below if not set via config.
TSIG_KEY_FILE=""

# DNS server to send nsupdate to
ALLOW_SERVER="${ALLOW_SERVER:-}"

# RPZ allowlist zone name
ALLOW_ZONE="${ALLOW_ZONE:-}"

# Allowlist text file (persisted across rpz-zone-factory runs)
ALLOWLIST_FILE=""

# Audit log file (append-only operation log)
AUDIT_LOG=""

# rndc binary (for sync -clean)
RNDC_BIN="${RNDC_BIN:-rndc}"

# TTL for nsupdate records. BIND ignores TTL for RPZ policy actions,
# but nsupdate requires it syntactically. Use 300 to match the zone's
# $TTL default so BIND doesn't emit explicit TTL directives in the zone file.
ALLOW_TTL="300"

# ─── Platform detection ───────────────────────────────────────────────────────

_os=$(uname -s)
case "$_os" in
    FreeBSD)
        _default_tsig_dir="/usr/local/etc/namedb/tsig"
        _default_tsig_key="${_default_tsig_dir}/rpz-update.key"
        ;;
    *)
        _default_tsig_dir="/etc/bind/tsig"
        _default_tsig_key="${_default_tsig_dir}/rpz-update.key"
        ;;
esac

# ─── Load config ──────────────────────────────────────────────────────────────
# Source .run-rpz.conf for shared settings (allowlist file, rndc, TSIG path)

_script_real="$(cd "$(dirname "$0")" && pwd)"
_conf_file="${_script_real}/.run-rpz.conf"
if [ -f "$_conf_file" ]; then
    # shellcheck source=/dev/null
    . "$_conf_file"
fi

# Map config variables to allow.sh variables (config takes precedence over defaults)
if [ -n "$CONF_TSIG_KEY_FILE" ] && [ -z "$TSIG_KEY_FILE" ]; then
    TSIG_KEY_FILE="$CONF_TSIG_KEY_FILE"
fi
if [ -z "$ALLOW_SERVER" ] && [ -n "$CONF_ALLOW_SERVER" ]; then
    ALLOW_SERVER="$CONF_ALLOW_SERVER"
fi
if [ -z "$ALLOW_ZONE" ] && [ -n "$CONF_ALLOW_ZONE" ]; then
    ALLOW_ZONE="$CONF_ALLOW_ZONE"
fi
if [ -n "$CONF_ALLOWLIST_FILE" ] && [ -z "$ALLOWLIST_FILE" ]; then
    ALLOWLIST_FILE="$CONF_ALLOWLIST_FILE"
fi
if [ -n "$CONF_AUDIT_LOG" ] && [ -z "$AUDIT_LOG" ]; then
    AUDIT_LOG="$CONF_AUDIT_LOG"
fi

# Apply defaults if still unset after config
if [ -z "$TSIG_KEY_FILE" ]; then
    TSIG_KEY_FILE="$_default_tsig_key"
fi
if [ -z "$ALLOW_SERVER" ]; then
    ALLOW_SERVER="localhost"
fi
if [ -z "$ALLOW_ZONE" ]; then
    ALLOW_ZONE="allowlist.rpz"
fi
# Fall back to feeds dir for allowlist file if still unset.
# v0.5.0+: allowlist.txt lives alongside the per-zone feed snapshots.
if [ -z "$ALLOWLIST_FILE" ] && [ -n "$CONF_FEEDS_DIR" ]; then
    ALLOWLIST_FILE="${CONF_FEEDS_DIR}/allowlist.txt"
fi
# Audit log default: same directory as allowlist file, or script directory
if [ -z "$AUDIT_LOG" ]; then
    if [ -n "$ALLOWLIST_FILE" ]; then
        AUDIT_LOG="$(dirname "$ALLOWLIST_FILE")/allow-audit.log"
    else
        AUDIT_LOG="${_script_real}/allow-audit.log"
    fi
fi

# ─── Version ──────────────────────────────────────────────────────────────────

VERSION="0.5.0"

# ─── Globals ──────────────────────────────────────────────────────────────────

ACTION="add"          # "add" or "remove" or "audit"
SKIP_WILDCARD=0       # 0 = add wildcard, 1 = skip
DOMAIN=""
AUDIT_LINES=20        # default lines for --audit

# ─── Usage ────────────────────────────────────────────────────────────────────

usage() {
    cat <<USAGE
allow.sh — Dynamic RPZ allowlist management v${VERSION}

Add or remove domains from the RPZ allowlist zone using TSIG-authenticated
nsupdate. Changes are persisted to the allowlist text file so they survive
rpz-zone-factory regeneration runs.

USAGE:
  ./allow.sh [OPTIONS] <domain>           Add domain + wildcard to allowlist
  ./allow.sh [OPTIONS] -n <domain>        Add domain only (no wildcard)
  ./allow.sh [OPTIONS] -r <domain>        Remove domain + wildcard from allowlist
  ./allow.sh --audit [N]                  Show last N audit log entries (default 20)

OPTIONS:
  -r, --remove          Remove domain instead of adding
  -n, --no-wildcard     Skip wildcard entry (*.domain)
                        Default: add both domain and *.domain
  -k, --key FILE        Path to TSIG key file
                        Default: ${_default_tsig_key}
  -s, --server HOST     Server to send nsupdate to
                        Default: localhost
  -z, --zone ZONE       RPZ allowlist zone name
                        Default: allowlist.rpz
  -a, --allowlist FILE  Path to allowlist text file (for persistence)
                        Default: from .run-rpz.conf CONF_ALLOWLIST_FILE
  -h, --help            Show this help and exit
  -v, --version         Print version and exit
  --audit [N]           Show last N audit log entries (default: 20)
  --audit-file FILE     Path to audit log file
                        Default: allow-audit.log next to allowlist file
  --setup               Show full TSIG key setup instructions

EXAMPLES:
  # Allow a domain (adds domain + *.domain by default)
  ./allow.sh example.com

  # Allow a domain without wildcard
  ./allow.sh -n example.com

  # Remove a domain from the allowlist
  ./allow.sh -r example.com

  # Show the last 20 audit log entries
  ./allow.sh --audit

  # Show the last 50 audit log entries
  ./allow.sh --audit 50

  # Use a specific TSIG key and server
  ./allow.sh -k /etc/bind/tsig/rpz-update.key -s 10.0.0.1 example.com

HOW IT WORKS:
  1. Validates the domain name
  2. Appends/removes the domain in the allowlist text file (persistent store)
  3. Sends nsupdate with TSIG key to add/remove RPZ passthru records
  4. Runs 'rndc sync <zone>' to flush in-memory state to the .db file,
     PRESERVING the journal so slaves can pull the change via IXFR

  The allowlist text file is modified BEFORE the dynamic update to avoid a
  race condition where a scheduled rpz-zone-factory run could overwrite the
  dynamic update before the text file is updated.

  RPZ passthru records use: CNAME rpz-passthru.
  This tells BIND to allow the query through despite other RPZ blocks.

  For TSIG key setup instructions, run: ./allow.sh --setup

USAGE
    exit "${1:-0}"
}

usage_setup() {
    cat <<SETUP
allow.sh — TSIG Key Setup for Dynamic RPZ Allowlist Updates

This guide walks through creating a TSIG key, configuring BIND to accept
signed dynamic updates on the allowlist zone, and verifying the setup.

─── 1. Generate a TSIG Key ─────────────────────────────────────────────

  tsig-keygen rpz-update > rpz-update.key

  This creates a file containing a key{} block with a random HMAC-SHA256
  secret. The key name ("rpz-update") can be anything — just keep it
  consistent across all config references.

─── 2. Create the Key Directory ────────────────────────────────────────

  The directory should be owned by the BIND user with group access for
  users who need to run allow.sh.

  FreeBSD:
    mkdir -p /usr/local/etc/namedb/tsig
    chown bind:bind /usr/local/etc/namedb/tsig
    chmod 770 /usr/local/etc/namedb/tsig
    mv rpz-update.key /usr/local/etc/namedb/tsig/
    chown bind:bind /usr/local/etc/namedb/tsig/rpz-update.key
    chmod 640 /usr/local/etc/namedb/tsig/rpz-update.key

  Linux (Debian/Ubuntu):
    mkdir -p /etc/bind/tsig
    chown bind:bind /etc/bind/tsig
    chmod 770 /etc/bind/tsig
    mv rpz-update.key /etc/bind/tsig/
    chown bind:bind /etc/bind/tsig/rpz-update.key
    chmod 640 /etc/bind/tsig/rpz-update.key

  Permissions:
    Directory: 770 (rwxrwx---) — BIND user + group members can access
    Key file:  640 (rw-r-----) — BIND reads, group members read

─── 3. Add Your User to the BIND Group ────────────────────────────────

  FreeBSD:  pw groupmod bind -m \$(whoami)
  Linux:    usermod -aG bind \$(whoami)

  Log out and back in for group membership to take effect.

─── 4. Include the Key in named.conf ──────────────────────────────────

  FreeBSD:
    include "/usr/local/etc/namedb/tsig/rpz-update.key";

  Linux:
    include "/etc/bind/tsig/rpz-update.key";

  Place this at the top level of named.conf (not inside a zone or
  options block).

─── 5. Configure the Allowlist Zone ────────────────────────────────────

  Add allow-update to the allowlist zone definition:

  zone "allowlist.rpz" {
      type primary;
      file "master/rpz/allowlist.rpz.db";
      allow-update { key "rpz-update"; };
      allow-query { localhost; };
      allow-transfer { none; };
  };

  NOTE: As of v0.6.0, every zone listed in CONF_INCREMENTAL_ZONES also
  needs 'allow-update { key "rpz-update"; };' so that run-rpz.sh can
  apply incremental diffs via TSIG-authenticated nsupdate. Add the same
  allow-update line to each per-source threat zone you want to update
  incrementally (urlhaus.rpz, cisa-kev.rpz, spamhaus-drop.rpz,
  scamsniffer.rpz, cryptoscamdb.rpz). Without this, the incremental
  path silently falls back to a full rebuild for that zone and slaves
  pull a full AXFR instead of an IXFR delta.

─── 6. Reload BIND ────────────────────────────────────────────────────

  rndc reconfig

─── 7. Test ────────────────────────────────────────────────────────────

  # Add a test entry
  ./allow.sh test-entry.example

  # Verify it's in the zone
  dig @localhost test-entry.example.allowlist.rpz CNAME +short
  # Should return: rpz-passthru.

  # Remove the test entry
  ./allow.sh -r test-entry.example

─── Troubleshooting ───────────────────────────────────────────────────

  "REFUSED" from nsupdate:
    - Key name in allow-update must match the key name in the key file
    - Key file must be included at the top level of named.conf
    - Run 'rndc reconfig' after any named.conf changes

  "could not read key from <file>":
    - Check file permissions (640) and group membership
    - Verify the key file is a valid tsig-keygen output

  Changes lost after rpz-zone-factory runs:
    - Make sure CONF_ALLOWLIST_FILE in .run-rpz.conf points to
      the same allowlist text file that allow.sh is updating
      (default: \${CONF_FEEDS_DIR}/allowlist.txt)
    - allow.sh persists entries to this file so they survive regeneration
    - If nsupdate fails, allow.sh reverts the text file edit automatically
      so the feed and live zone stay in sync (v0.5.0+)

SETUP
    exit "${1:-0}"
}

# ─── Argument parsing ─────────────────────────────────────────────────────────

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -v|--version)
                echo "$VERSION"
                exit 0
                ;;
            -h|--help)
                usage 0
                ;;
            --setup)
                usage_setup 0
                ;;
            --audit)
                ACTION="audit"
                # Check if next arg is a number (line count)
                if [ -n "$2" ] && printf '%s' "$2" | grep -Eq '^[0-9]+$'; then
                    AUDIT_LINES="$2"
                    shift
                fi
                shift
                ;;
            --audit-file)
                if [ -z "$2" ]; then
                    printf "ERROR: --audit-file requires a file path argument\n" >&2
                    usage 1
                fi
                AUDIT_LOG="$2"
                shift 2
                ;;
            -r|--remove)
                ACTION="remove"
                shift
                ;;
            -n|--no-wildcard)
                SKIP_WILDCARD=1
                shift
                ;;
            -k|--key)
                if [ -z "$2" ]; then
                    printf "ERROR: --key requires a file path argument\n" >&2
                    usage 1
                fi
                TSIG_KEY_FILE="$2"
                shift 2
                ;;
            -s|--server)
                if [ -z "$2" ]; then
                    printf "ERROR: --server requires a host argument\n" >&2
                    usage 1
                fi
                ALLOW_SERVER="$2"
                shift 2
                ;;
            -z|--zone)
                if [ -z "$2" ]; then
                    printf "ERROR: --zone requires a zone name argument\n" >&2
                    usage 1
                fi
                ALLOW_ZONE="$2"
                shift 2
                ;;
            -a|--allowlist)
                if [ -z "$2" ]; then
                    printf "ERROR: --allowlist requires a file path argument\n" >&2
                    usage 1
                fi
                ALLOWLIST_FILE="$2"
                shift 2
                ;;
            -*)
                printf "ERROR: Unknown option: %s\n\n" "$1" >&2
                usage 1
                ;;
            *)
                if [ -n "$DOMAIN" ]; then
                    printf "ERROR: Multiple domains specified. Only one domain per invocation.\n" >&2
                    usage 1
                fi
                DOMAIN="$1"
                shift
                ;;
        esac
    done

    if [ "$ACTION" != "audit" ] && [ -z "$DOMAIN" ]; then
        printf "ERROR: No domain specified.\n\n" >&2
        usage 1
    fi
}

# ─── Validation ───────────────────────────────────────────────────────────────

# Basic DNS label validation. Rejects obviously invalid input.
validate_domain() {
    _domain="$1"

    # Strip trailing dot if present
    _domain=$(echo "$_domain" | sed 's/\.$//')

    # Reject empty
    if [ -z "$_domain" ]; then
        printf "ERROR: Domain name is empty.\n" >&2
        return 1
    fi

    # Reject domains with slashes (URLs, paths)
    case "$_domain" in
        */*|*\\*)
            printf "ERROR: Domain contains path characters: %s\n" "$_domain" >&2
            printf "  Provide a bare domain name, not a URL.\n" >&2
            return 1
            ;;
    esac

    # Reject domains with spaces or control characters
    case "$_domain" in
        *" "*|*"	"*)
            printf "ERROR: Domain contains whitespace: %s\n" "$_domain" >&2
            return 1
            ;;
    esac

    # Total FQDN length check (253 chars max)
    _len=$(printf '%s' "$_domain" | wc -c | tr -d ' ')
    if [ "$_len" -gt 253 ]; then
        printf "ERROR: Domain exceeds 253 characters: %s\n" "$_domain" >&2
        return 1
    fi

    # Per-label check (max 63 chars)
    _remaining="$_domain"
    while [ -n "$_remaining" ]; do
        case "$_remaining" in
            *.*)
                _label="${_remaining%%.*}"
                _remaining="${_remaining#*.}"
                ;;
            *)
                _label="$_remaining"
                _remaining=""
                ;;
        esac

        if [ -z "$_label" ]; then
            printf "ERROR: Domain has empty label (consecutive dots): %s\n" "$_domain" >&2
            return 1
        fi

        _label_len=$(printf '%s' "$_label" | wc -c | tr -d ' ')
        if [ "$_label_len" -gt 63 ]; then
            printf "ERROR: Label exceeds 63 characters: %s\n" "$_label" >&2
            return 1
        fi
    done

    # Update global with normalized domain (trailing dot stripped)
    DOMAIN="$_domain"
    return 0
}

# ─── Preflight checks ────────────────────────────────────────────────────────

preflight() {
    _errors=0

    # nsupdate must exist
    if ! command -v nsupdate >/dev/null 2>&1; then
        printf "ERROR: nsupdate not found in PATH.\n" >&2
        printf "  Install BIND utilities (bind-utils, bind9-dnsutils, or dns/bind-tools).\n" >&2
        _errors=$(( _errors + 1 ))
    fi

    # TSIG key must exist and be readable
    if [ ! -f "$TSIG_KEY_FILE" ]; then
        printf "ERROR: TSIG key file not found: %s\n" "$TSIG_KEY_FILE" >&2
        printf "  Generate one with: tsig-keygen rpz-update > rpz-update.key\n" >&2
        printf "  See: ./allow.sh --setup for full TSIG setup instructions.\n" >&2
        _errors=$(( _errors + 1 ))
    elif [ ! -r "$TSIG_KEY_FILE" ]; then
        printf "ERROR: TSIG key file not readable: %s\n" "$TSIG_KEY_FILE" >&2
        printf "  Fix permissions or add your user to the BIND group.\n" >&2
        _errors=$(( _errors + 1 ))
    fi

    # rndc must exist (needed for sync -clean)
    _rndc_found=0
    if command -v "$RNDC_BIN" >/dev/null 2>&1; then
        _rndc_found=1
    else
        for _try in /usr/sbin/rndc /usr/local/sbin/rndc /usr/bin/rndc; do
            if [ -x "$_try" ]; then
                RNDC_BIN="$_try"
                _rndc_found=1
                break
            fi
        done
    fi
    if [ $_rndc_found -eq 0 ]; then
        printf "ERROR: rndc not found. Required for 'rndc sync'.\n" >&2
        printf "  Install BIND utilities or set RNDC_BIN.\n" >&2
        _errors=$(( _errors + 1 ))
    fi

    # Allowlist file path must be set
    if [ -z "$ALLOWLIST_FILE" ]; then
        printf "ERROR: Allowlist text file path not set.\n" >&2
        printf "  Set CONF_ALLOWLIST_FILE in .run-rpz.conf, or use -a/--allowlist flag.\n" >&2
        _errors=$(( _errors + 1 ))
    fi

    if [ $_errors -gt 0 ]; then
        return 1
    fi

    return 0
}

# ─── Allowlist text file operations ───────────────────────────────────────────

# Add domain to the allowlist text file (one domain per line).
# Skips if the domain is already present.
allowlist_add() {
    _domain="$1"
    _file="$2"

    # Create the file if it doesn't exist
    if [ ! -f "$_file" ]; then
        touch "$_file" || {
            printf "ERROR: Cannot create allowlist file: %s\n" "$_file" >&2
            return 1
        }
    fi

    # Check if domain already exists (exact line match)
    if grep -Fxq "$_domain" "$_file" 2>/dev/null; then
        printf "  Domain already in allowlist file: %s\n" "$_domain"
        return 0
    fi

    # Append
    printf '%s\n' "$_domain" >> "$_file" || {
        printf "ERROR: Failed to write to allowlist file: %s\n" "$_file" >&2
        return 1
    }

    printf "  Added to allowlist file: %s\n" "$_domain"
    return 0
}

# Remove domain from the allowlist text file.
# Uses a temp file for atomic replacement (portable, no sed -i).
allowlist_remove() {
    _domain="$1"
    _file="$2"

    if [ ! -f "$_file" ]; then
        printf "  Allowlist file does not exist: %s (nothing to remove)\n" "$_file"
        return 0
    fi

    # Check if domain exists
    if ! grep -Fxq "$_domain" "$_file" 2>/dev/null; then
        printf "  Domain not found in allowlist file: %s\n" "$_domain"
        return 0
    fi

    # Remove exact line matches via temp file
    _tmp="${_file}.tmp.$$"
    grep -Fxv "$_domain" "$_file" > "$_tmp" || true
    mv "$_tmp" "$_file" || {
        printf "ERROR: Failed to update allowlist file: %s\n" "$_file" >&2
        rm -f "$_tmp"
        return 1
    }

    printf "  Removed from allowlist file: %s\n" "$_domain"
    return 0
}

# ─── nsupdate operations ─────────────────────────────────────────────────────

nsupdate_add() {
    _domain="$1"
    _zone="$2"

    _commands="server ${ALLOW_SERVER}
zone ${_zone}
update add ${_domain}.${_zone}. ${ALLOW_TTL} IN CNAME rpz-passthru."

    if [ $SKIP_WILDCARD -eq 0 ]; then
        _commands="${_commands}
update add *.${_domain}.${_zone}. ${ALLOW_TTL} IN CNAME rpz-passthru."
    fi

    _commands="${_commands}
send"

    printf '%s\n' "$_commands" | nsupdate -k "$TSIG_KEY_FILE" 2>&1
    return $?
}

nsupdate_remove() {
    _domain="$1"
    _zone="$2"

    _commands="server ${ALLOW_SERVER}
zone ${_zone}
update delete ${_domain}.${_zone}. IN CNAME
update delete *.${_domain}.${_zone}. IN CNAME
send"

    printf '%s\n' "$_commands" | nsupdate -k "$TSIG_KEY_FILE" 2>&1
    return $?
}

# ─── Audit log ────────────────────────────────────────────────────────────────

# Append a line to the audit log.
# Format: YYYY-MM-DDTHH:MM:SS+ZZZZ | action | domain | operator | result
audit_write() {
    _action="$1"
    _domain="$2"
    _result="$3"

    _ts=$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')
    _operator=$(whoami 2>/dev/null || echo "unknown")

    # Create audit log if it doesn't exist
    if [ ! -f "$AUDIT_LOG" ]; then
        touch "$AUDIT_LOG" 2>/dev/null || {
            printf "WARNING: Cannot create audit log: %s\n" "$AUDIT_LOG" >&2
            return 1
        }
    fi

    printf '%s | %-6s | %s | %s | %s\n' \
        "$_ts" "$_action" "$_domain" "$_operator" "$_result" \
        >> "$AUDIT_LOG" 2>/dev/null || {
        printf "WARNING: Failed to write audit log: %s\n" "$AUDIT_LOG" >&2
        return 1
    }

    return 0
}

# Display last N lines from the audit log.
audit_show() {
    _lines="$1"

    if [ ! -f "$AUDIT_LOG" ]; then
        printf "No audit log found at: %s\n" "$AUDIT_LOG"
        return 0
    fi

    _total=$(wc -l < "$AUDIT_LOG" | tr -d ' ')
    printf "Audit log: %s (%s entries)\n" "$AUDIT_LOG" "$_total"
    printf "Showing last %s:\n\n" "$_lines"
    printf '%-25s | %-6s | %-40s | %-12s | %s\n' \
        "TIMESTAMP" "ACTION" "DOMAIN" "OPERATOR" "RESULT"
    printf '%s\n' "────────────────────────────────────────────────────────────────────────────────────────────────────"
    tail -n "$_lines" "$AUDIT_LOG"

    return 0
}

# ─── rndc sync ────────────────────────────────────────────────────────────────

# Flush BIND's in-memory state for the zone to its .db file but PRESERVE the
# journal (.jnl). This is critical for IXFR: slaves use the journal to pull
# only the delta we just nsupdate'd, instead of re-AXFR'ing the whole zone.
#
# Pre-v0.6.0 this function used `rndc sync -clean` (which deletes the .jnl
# after writing), but that was a v0.4.0-era behavior from when run-rpz.sh
# always wrote full zone files. With v0.6.0+ IXFR support, removing the
# journal after every nsupdate would force every slave refresh to AXFR.
rndc_sync() {
    _zone="$1"

    printf "  Syncing zone (preserving journal for IXFR): %s\n" "$_zone"
    # RNDC_BIN may contain "sudo rndc", so don't quote as single token
    _output=$(eval "$RNDC_BIN sync $_zone" 2>&1)
    _rc=$?

    if [ $_rc -ne 0 ]; then
        printf "WARNING: rndc sync failed (exit %d): %s\n" "$_rc" "$_output" >&2
        printf "  The dynamic update was applied but the journal was not flushed to disk.\n" >&2
        printf "  This is not critical — BIND will resolve the journal on next reload.\n" >&2
        return 1
    fi

    printf "  Zone synced; journal preserved for IXFR.\n"
    return 0
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    # --audit doesn't need a domain, TSIG key, or preflight
    if [ "$ACTION" = "audit" ]; then
        audit_show "$AUDIT_LINES"
        exit 0
    fi

    if ! validate_domain "$DOMAIN"; then
        exit 1
    fi

    if ! preflight; then
        exit 1
    fi

    printf "\n"

    if [ "$ACTION" = "add" ]; then
        printf "Adding to RPZ allowlist: %s\n" "$DOMAIN"
        if [ $SKIP_WILDCARD -eq 0 ]; then
            printf "  Entries: %s + *.%s\n" "$DOMAIN" "$DOMAIN"
        else
            printf "  Entry: %s (no wildcard)\n" "$DOMAIN"
        fi
        printf "  Zone: %s | Server: %s\n\n" "$ALLOW_ZONE" "$ALLOW_SERVER"

        # Step 1: Persist to allowlist text file FIRST.
        # If nsupdate fails we revert this edit so the text file stays in
        # sync with the live zone (run-rpz.sh uses the text file to compute
        # incremental diffs on the next scheduled run).
        if ! allowlist_add "$DOMAIN" "$ALLOWLIST_FILE"; then
            printf "\nERROR: Failed to update allowlist file. Aborting.\n" >&2
            exit 1
        fi

        # Step 2: Dynamic update via nsupdate
        printf "  Sending nsupdate...\n"
        _nsupdate_output=$(nsupdate_add "$DOMAIN" "$ALLOW_ZONE")
        _nsupdate_rc=$?

        if [ $_nsupdate_rc -ne 0 ]; then
            printf "ERROR: nsupdate failed (exit %d)\n" "$_nsupdate_rc" >&2
            if [ -n "$_nsupdate_output" ]; then
                printf "  %s\n" "$_nsupdate_output" >&2
            fi
            # Revert the allowlist file edit so it matches the live zone.
            printf "  Reverting allowlist file edit...\n" >&2
            if allowlist_remove "$DOMAIN" "$ALLOWLIST_FILE" >/dev/null 2>&1; then
                printf "  Allowlist file reverted.\n" >&2
            else
                printf "  WARNING: Failed to revert allowlist file — manual cleanup needed.\n" >&2
            fi
            audit_write "add" "$DOMAIN" "FAIL:nsupdate-rc${_nsupdate_rc}"
            exit 1
        fi
        printf "  nsupdate succeeded.\n"

        # Step 3: Flush in-memory state to .db (preserving journal for IXFR)
        rndc_sync "$ALLOW_ZONE"

        # Step 4: Audit log
        audit_write "add" "$DOMAIN" "OK"

        printf "\nDone. %s is now allowed through RPZ.\n" "$DOMAIN"

    elif [ "$ACTION" = "remove" ]; then
        printf "Removing from RPZ allowlist: %s\n" "$DOMAIN"
        printf "  Entries: %s + *.%s\n" "$DOMAIN" "$DOMAIN"
        printf "  Zone: %s | Server: %s\n\n" "$ALLOW_ZONE" "$ALLOW_SERVER"

        # Step 1: Remove from allowlist text file FIRST.
        # If nsupdate fails we re-add it so the text file stays in sync.
        if ! allowlist_remove "$DOMAIN" "$ALLOWLIST_FILE"; then
            printf "\nERROR: Failed to update allowlist file. Aborting.\n" >&2
            exit 1
        fi

        # Step 2: Dynamic delete via nsupdate
        printf "  Sending nsupdate...\n"
        _nsupdate_output=$(nsupdate_remove "$DOMAIN" "$ALLOW_ZONE")
        _nsupdate_rc=$?

        if [ $_nsupdate_rc -ne 0 ]; then
            printf "ERROR: nsupdate failed (exit %d)\n" "$_nsupdate_rc" >&2
            if [ -n "$_nsupdate_output" ]; then
                printf "  %s\n" "$_nsupdate_output" >&2
            fi
            # Revert the allowlist file edit so it matches the live zone.
            printf "  Reverting allowlist file edit...\n" >&2
            if allowlist_add "$DOMAIN" "$ALLOWLIST_FILE" >/dev/null 2>&1; then
                printf "  Allowlist file reverted.\n" >&2
            else
                printf "  WARNING: Failed to revert allowlist file — manual cleanup needed.\n" >&2
            fi
            audit_write "remove" "$DOMAIN" "FAIL:nsupdate-rc${_nsupdate_rc}"
            exit 1
        fi
        printf "  nsupdate succeeded.\n"

        # Step 3: Flush in-memory state to .db (preserving journal for IXFR)
        rndc_sync "$ALLOW_ZONE"

        # Step 4: Audit log
        audit_write "remove" "$DOMAIN" "OK"

        printf "\nDone. %s removed from RPZ allowlist.\n" "$DOMAIN"
    fi

    exit 0
}

main "$@"
