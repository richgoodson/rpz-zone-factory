#!/bin/sh
# drift-check.sh - health monitor for the RPZ primary and its zone estate.
#
# Born out of two silent failures that syslog recorded faithfully and nobody
# saw: a TSIG secret mismatch that broke inbound slave transfers for four
# months (zones aged past SOA expire and stopped loading), and a feed whose
# upstream endpoint died and served stale cache for ten days behind a
# "completed successfully" exit.
#
# Checks:
#   1. pipeline liveness - the cron run has completed within the last 2 hours
#   2. slaved zones      - every type-slave zone is loaded locally and its
#                          serial matches the reference master
#   3. RPZ propagation   - every locally-mastered *.rpz zone is served at the
#                          same serial by every secondary
#   4. feed health       - no feed has been erroring across most runs in the
#                          retained logs
#
# Alerts go to a Discord webhook (URL read from a mode-600 file, never from
# argv or this script). Serial mismatches are re-checked after a settle delay
# before alerting, so a secondary caught mid-refresh does not page. Each problem
# line is suppressed for RESEND_HOURS via per-line fingerprints in the state dir.
# Detail always goes to syslog regardless, for forensics.
#
# Config (via .run-rpz.conf next to this script; the topology values have no
# defaults on purpose, so site specifics never live in this file):
#   CONF_MONITOR_WEBHOOK_FILE    path to file holding the Discord webhook URL
#                                (default: <script dir>/discord.webhook)
#   CONF_MONITOR_REF_MASTER     reference master for slaved-zone comparison
#                                (empty = slave-zone check skipped, warned)
#   CONF_MONITOR_SECONDARIES    space-separated RPZ secondaries
#                                (empty = propagation check skipped, warned)
#   CONF_MONITOR_EXCLUDE_ZONES  space-separated zones to skip entirely
#   CONF_MONITOR_RESEND_HOURS   re-alert interval for an unchanged alert (24)
#
# Usage:
#   ./drift-check.sh          run all checks, alert on problems
#   ./drift-check.sh --test   send a test message to the webhook and exit
#
# Cron (offset from the pipeline run, so refresh lag has settled):
#   47 * * * * /path/to/rpz-zone-factory/drift-check.sh

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
LOG_TAG="rpz-drift-check"

# Defaults; .run-rpz.conf overrides. Topology (reference master, secondary
# list) is deliberately not defaulted here: it comes from the gitignored
# config so this file stays free of any site's addressing.
CONF_MONITOR_WEBHOOK_FILE="${SCRIPT_DIR}/discord.webhook"
CONF_MONITOR_REF_MASTER=""
CONF_MONITOR_SECONDARIES=""
CONF_MONITOR_EXCLUDE_ZONES=""
CONF_MONITOR_RESEND_HOURS="24"

NAMED_CONF="/usr/local/etc/namedb/named.conf"
DAEMON_LOG="/var/log/daemon.log"
STATE_DIR="${SCRIPT_DIR}/.monitor-state"
SETTLE_SECONDS=90
FEED_ERROR_THRESHOLD=12

# shellcheck source=/dev/null
[ -f "${SCRIPT_DIR}/.run-rpz.conf" ] && . "${SCRIPT_DIR}/.run-rpz.conf"

log_syslog() {
    logger -t "$LOG_TAG" -p "daemon.warning" -- "$1"
}

# ── Discord ───────────────────────────────────────────────────────────────────

send_discord() {
    # $1 = message body. Escapes for JSON, truncates to Discord's limit,
    # posts to the webhook. The URL never appears in argv of any process.
    if [ ! -r "$CONF_MONITOR_WEBHOOK_FILE" ]; then
        log_syslog "webhook file not readable: $CONF_MONITOR_WEBHOOK_FILE - alert NOT sent"
        return 1
    fi
    _body=$(printf '%s' "$1" | head -c 1800 | awk '
        BEGIN { out = "" }
        {
            line = $0
            gsub(/\\/, "\\\\", line)
            gsub(/"/, "\\\"", line)
            gsub(/\t/, "\\t", line)
            out = out line "\\n"
        }
        END { printf "%s", out }')
    # The URL rides in on --config via stdin, and the payload in a temp
    # file, so neither the webhook URL nor the message ever appears in any
    # process's argv.
    mkdir -p "$STATE_DIR"
    _pf="${STATE_DIR}/.payload.$$"
    printf '{"content":"%s"}' "$_body" > "$_pf"
    _rc=$(printf 'url = "%s"\n' "$(cat "$CONF_MONITOR_WEBHOOK_FILE")" |
        curl -sS -m 15 -o /dev/null -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -d "@${_pf}" --config - 2>/dev/null)
    rm -f "$_pf"
    case "$_rc" in
        2*) return 0 ;;
        *)  log_syslog "Discord webhook POST failed: HTTP ${_rc:-none} - alert NOT delivered"
            return 1 ;;
    esac
}

# ── Test mode ─────────────────────────────────────────────────────────────────

if [ "${1:-}" = "--test" ]; then
    if send_discord "[OK] drift-check test from $(hostname) at $(date)"; then
        echo "[OK] test message sent"
        exit 0
    fi
    echo "[!]  test message failed (see syslog)"
    exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

soa_serial() {
    # $1 = server, $2 = zone. Prints serial, or nothing on SERVFAIL/timeout.
    dig +short +time=3 +tries=1 "@$1" "$2" SOA 2>/dev/null | awk '{print $3}' | head -1
}

is_excluded() {
    for _x in $CONF_MONITOR_EXCLUDE_ZONES; do
        [ "$_x" = "$1" ] && return 0
    done
    return 1
}

PROBLEMS=""
add_problem() {
    PROBLEMS="${PROBLEMS}${1}
"
}

# ── Check 1: pipeline liveness ────────────────────────────────────────────────

check_pipeline() {
    # The hourly run logs "Per-source run complete" (or an error) via syslog.
    # Nothing in the last 2 hours means cron is broken or the run is wedged.
    _last=$(grep "rpz-zone-factory" "$DAEMON_LOG" 2>/dev/null | tail -1 | awk '{print $1, $2, $3}')
    if [ -z "$_last" ]; then
        add_problem "pipeline: no rpz-zone-factory syslog entries in $DAEMON_LOG at all"
        return
    fi
    _last_epoch=$(date -j -f "%b %d %T" "$_last" +%s 2>/dev/null)
    _now=$(date +%s)
    if [ -n "$_last_epoch" ] && [ $((_now - _last_epoch)) -gt 7200 ]; then
        add_problem "pipeline: last run activity was $_last (over 2h ago) - cron broken or run wedged"
    fi
}

# ── Check 2 + 3: zone serials (with settle re-check) ──────────────────────────

slave_zones() {
    # All type-slave zones from named.conf and any .conf it includes,
    # except the root slave.
    _confs="$NAMED_CONF"
    for _inc in $(awk -F'"' '/^include/ {print $2}' "$NAMED_CONF" 2>/dev/null); do
        case "$_inc" in *.conf) _confs="$_confs $_inc" ;; esac
    done
    # shellcheck disable=SC2086
    awk '/^zone/ {z=$2} /type (slave|secondary);/ {gsub(/"/,"",z); if (z != ".") print z}' $_confs 2>/dev/null
}

rpz_zones() {
    awk '/^zone ".*\.rpz"/ {z=$2} /type (master|primary);/ {if (z != "") {gsub(/"/,"",z); print z; z=""}}' "$NAMED_CONF" 2>/dev/null
}

# First pass: collect suspects as "kind|zone|server" lines.
collect_suspects() {
    if [ -n "$CONF_MONITOR_REF_MASTER" ]; then
        for _z in $(slave_zones); do
            is_excluded "$_z" && continue
            _local=$(soa_serial 127.0.0.1 "$_z")
            _ref=$(soa_serial "$CONF_MONITOR_REF_MASTER" "$_z")
            if [ -z "$_local" ] || { [ -n "$_ref" ] && [ "$_local" != "$_ref" ]; }; then
                printf 'slave|%s|%s\n' "$_z" "$CONF_MONITOR_REF_MASTER"
            fi
        done
    fi
    for _z in $(rpz_zones); do
        is_excluded "$_z" && continue
        _local=$(soa_serial 127.0.0.1 "$_z")
        if [ -z "$_local" ]; then
            printf 'rpz-local|%s|127.0.0.1\n' "$_z"
            continue
        fi
        for _s in $CONF_MONITOR_SECONDARIES; do
            _remote=$(soa_serial "$_s" "$_z")
            [ "$_remote" != "$_local" ] && printf 'rpz|%s|%s\n' "$_z" "$_s"
        done
    done
}

check_config() {
    # A monitor with checks silently switched off is the failure mode this
    # script exists to kill, so an unconfigured check alerts (once per
    # resend window) instead of skipping quietly.
    [ -z "$CONF_MONITOR_REF_MASTER" ] &&
        add_problem "config: CONF_MONITOR_REF_MASTER not set in .run-rpz.conf - slave-zone drift check is OFF"
    [ -z "$CONF_MONITOR_SECONDARIES" ] &&
        add_problem "config: CONF_MONITOR_SECONDARIES not set in .run-rpz.conf - RPZ propagation check is OFF"
}

check_zones() {
    _suspects=$(collect_suspects)
    [ -z "$_suspects" ] && return

    # Give in-flight refreshes time to land, then re-check only the suspects.
    sleep "$SETTLE_SECONDS"

    printf '%s\n' "$_suspects" | while IFS='|' read -r _kind _z _srv; do
        [ -z "$_z" ] && continue
        _local=$(soa_serial 127.0.0.1 "$_z")
        case "$_kind" in
            slave)
                _ref=$(soa_serial "$_srv" "$_z")
                if [ -z "$_local" ]; then
                    echo "slave zone $_z: not served locally (SERVFAIL/not loaded); $_srv has ${_ref:-none}"
                elif [ -n "$_ref" ] && [ "$_local" != "$_ref" ]; then
                    echo "slave zone $_z: local serial $_local != $_srv serial $_ref"
                fi
                ;;
            rpz-local)
                [ -z "$_local" ] && echo "rpz zone $_z: not served locally (SERVFAIL/not loaded)"
                ;;
            rpz)
                _remote=$(soa_serial "$_srv" "$_z")
                if [ -n "$_local" ] && [ "$_remote" != "$_local" ]; then
                    echo "rpz zone $_z: secondary $_srv at ${_remote:-SERVFAIL}, primary at $_local"
                fi
                ;;
        esac
    done > "${STATE_DIR}/.zone-problems.$$"

    while IFS= read -r _line; do
        [ -n "$_line" ] && add_problem "$_line"
    done < "${STATE_DIR}/.zone-problems.$$"
    rm -f "${STATE_DIR}/.zone-problems.$$"
}

# ── Check 4: feed health ──────────────────────────────────────────────────────

check_feeds() {
    # A feed named on "Source errors" detail lines across most retained runs
    # is dead upstream, not hiccuping. Threshold 12 = half a day of hourly
    # runs. Covers the current log plus the newest rotated one.
    { bzcat "${DAEMON_LOG}.0.bz2" 2>/dev/null; cat "$DAEMON_LOG" 2>/dev/null; } |
        grep "rpz-zone-factory" |
        grep -oE '  - [a-z0-9-]+: ' |
        sed 's/^  - //; s/: $//' |
        sort | uniq -c |
        while read -r _n _feed; do
            [ "$_n" -ge "$FEED_ERROR_THRESHOLD" ] &&
                echo "feed $_feed: fetch errors in $_n recent runs - upstream likely dead, serving cached data"
        done > "${STATE_DIR}/.feed-problems.$$"

    while IFS= read -r _line; do
        [ -n "$_line" ] && add_problem "$_line"
    done < "${STATE_DIR}/.feed-problems.$$"
    rm -f "${STATE_DIR}/.feed-problems.$$"
}

# ── Run ───────────────────────────────────────────────────────────────────────

mkdir -p "$STATE_DIR"

check_config
check_pipeline
check_zones
check_feeds

if [ -z "$PROBLEMS" ]; then
    # Healthy: clear any previous alert fingerprint so the next problem,
    # even an identical recurrence, alerts immediately.
    rm -f "${STATE_DIR}/alerted-lines" "${STATE_DIR}/last-alert.md5" "${STATE_DIR}/last-alert.epoch"
    exit 0
fi

# Always record the detail in syslog.
printf '%s' "$PROBLEMS" | while IFS= read -r _line; do
    [ -n "$_line" ] && log_syslog "$_line"
done

# Suppress problem lines already alerted inside the resend window. Fingerprints
# are per line, not per alert: a new problem appearing beside a known one
# alerts for the new one only, and the known one does not re-alert when the
# new one clears.
fp() { printf '%s' "$1" | md5 -q 2>/dev/null || printf '%s' "$1" | md5sum | awk '{print $1}'; }
_alerted="${STATE_DIR}/alerted-lines"   # "<epoch> <md5>" per alerted problem line
_now=$(date +%s)
_resend=$((CONF_MONITOR_RESEND_HOURS * 3600))
: > "${_alerted}.$$"
[ -f "$_alerted" ] && awk -v cutoff=$((_now - _resend)) '$1 > cutoff' "$_alerted" > "${_alerted}.$$"
: > "${_alerted}.new.$$"
_known=0
printf '%s\n' "$PROBLEMS" | while IFS= read -r _line; do
    [ -z "$_line" ] && continue
    _h=$(fp "$_line")
    if grep -q " ${_h}\$" "${_alerted}.$$"; then
        echo "$_h" >> "${_alerted}.known.$$"
    else
        echo "$_line"
        echo "$_now $_h" >> "${_alerted}.new.$$"
    fi
done > "${_alerted}.lines.$$"
[ -f "${_alerted}.known.$$" ] && _known=$(wc -l < "${_alerted}.known.$$" | tr -d ' ')
rm -f "${_alerted}.known.$$"

if [ ! -s "${_alerted}.lines.$$" ]; then
    mv "${_alerted}.$$" "$_alerted"
    rm -f "${_alerted}.new.$$" "${_alerted}.lines.$$"
    exit 1
fi

_still=""
[ "$_known" -gt 0 ] && _still="(+${_known} previously alerted problem(s) still open)
"
send_discord "[!] rpz drift-check on $(hostname) found problems:

$(cat "${_alerted}.lines.$$")
${_still}(details in daemon.log; each problem re-alerts after ${CONF_MONITOR_RESEND_HOURS}h)" &&
    cat "${_alerted}.new.$$" >> "${_alerted}.$$"
mv "${_alerted}.$$" "$_alerted"
rm -f "${_alerted}.new.$$" "${_alerted}.lines.$$"

exit 1
