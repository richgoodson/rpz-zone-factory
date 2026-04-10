#!/bin/sh
# run-rpz.sh — Cron/interactive wrapper for rpz-zone-factory
# Version: 0.6.0
# Portable: Debian, Ubuntu, FreeBSD 13+
# POSIX sh — no bashisms.
#
# v0.6.0: Incremental zone updates via nsupdate/TSIG for IXFR support.
#         Zones listed in CONF_INCREMENTAL_ZONES are updated by diffing
#         the previous feed against the newly generated zone and applying
#         only the additions/deletions via TSIG-authenticated nsupdate.
#         BIND writes the delta to the journal and bumps the SOA serial,
#         which allows secondaries to IXFR only the changes instead of AXFR'ing
#         the entire zone on every scheduled run.
#
# Usage:
#   ./run-rpz.sh --setup             Interactive setup wizard
#   ./run-rpz.sh [OPTIONS] [-- ARGS]  Run rpz-zone-factory
#
# See usage() below or run with -h/--help.

# ─── Configuration ────────────────────────────────────────────────────────────
# Override these via environment, config file, or edit in place.

# Path to the rpz-zone-factory project directory (contains run.py, requirements.txt)
# Default: directory where this script lives (resolved via symlinks)
_script_real="$(cd "$(dirname "$0")" && pwd)"
RPZ_DIR="${RPZ_DIR:-$_script_real}"

# Python binary (must be >= 3.9). Searches PATH if not absolute.
PYTHON_BIN="${PYTHON_BIN:-python3.11}"

# Minimum Python version (major.minor)
PYTHON_MIN_VERSION="3.9"

# Venv directory name (relative to RPZ_DIR)
VENV_NAME="${VENV_NAME:-.venv}"

# Syslog tag for logger
LOG_TAG="rpz-zone-factory"

# Syslog facility
LOG_FACILITY="daemon"

# rndc binary (for --reload-bind)
RNDC_BIN="${RNDC_BIN:-rndc}"

# ─── Saved config (from --setup wizard) ───────────────────────────────────────
# These are set by the wizard and saved to .run-rpz.conf
# They provide defaults for cron runs so no CLI args are needed.

CONF_OUTPUT=""          # rpz or pihole
CONF_ZONE_NAME=""       # RPZ zone name (e.g., block.rpz)
CONF_OUTPUT_FILE=""     # Output file path
CONF_SOURCES=""         # Space-separated source list, or empty for all
CONF_VERBOSITY=""       # 0=quiet, 1=-v, 2=-vv
CONF_RELOAD=""          # yes or no
CONF_RELOAD_ZONE=""     # Zone to reload via rndc
CONF_COMPILE_ZONE=""    # yes or no — use named-compilezone for binary (raw) format
CONF_CHECKZONE=""       # yes or no — validate with named-checkzone before deploying
CONF_PER_SOURCE=""      # yes or no — output one zone file per source
CONF_ALLOWLIST_FILE=""  # path to allowlist file (used with per-source mode)
CONF_TSIG_KEY_FILE=""  # path to TSIG key file for nsupdate (shared by allow.sh and incremental updates)
CONF_ALLOW_SERVER=""   # server for nsupdate (default: localhost)
CONF_ALLOW_ZONE=""     # allowlist zone name (default: allowlist.rpz)
CONF_FEEDS_DIR=""      # directory holding previous/current feed snapshots for incremental diffs
CONF_INCREMENTAL_ZONES=""  # space-separated zones that use the incremental (IXFR) update path
CONF_INCREMENTAL_TTL="300" # TTL for nsupdate records (matches zone default)

# Source config file if it exists (overrides defaults above)
_conf_file="${RPZ_DIR}/.run-rpz.conf"
if [ -f "$_conf_file" ]; then
    # shellcheck source=/dev/null
    . "$_conf_file"
fi

# ─── Version ──────────────────────────────────────────────────────────────────

VERSION="0.6.0"

# ─── Globals ──────────────────────────────────────────────────────────────────

MODE="cron"       # "cron" or "interactive"
DO_SETUP=0
DO_RELOAD=0
DO_FULL_REBUILD=0  # force full rebuild path even for incremental zones
DO_FORCE=0         # bypass v0.7.0 "all sources unchanged" fast-path
RELOAD_ZONE=""
RPZ_ARGS=""
EXIT_CODE=0

# ─── Logging ──────────────────────────────────────────────────────────────────

log_info() {
    if [ "$MODE" = "cron" ]; then
        logger -t "$LOG_TAG" -p "${LOG_FACILITY}.info" -- "$1"
    else
        printf "[INFO]  %s\n" "$1" >&2
    fi
}

log_warn() {
    if [ "$MODE" = "cron" ]; then
        logger -t "$LOG_TAG" -p "${LOG_FACILITY}.warning" -- "$1"
    else
        printf "[WARN]  %s\n" "$1" >&2
    fi
}

log_err() {
    if [ "$MODE" = "cron" ]; then
        logger -t "$LOG_TAG" -p "${LOG_FACILITY}.err" -- "$1"
    else
        printf "[ERROR] %s\n" "$1" >&2
    fi
}

log_notice() {
    if [ "$MODE" = "cron" ]; then
        logger -t "$LOG_TAG" -p "${LOG_FACILITY}.notice" -- "$1"
    else
        printf "[NOTE]  %s\n" "$1" >&2
    fi
}

# ─── Interactive prompts ─────────────────────────────────────────────────────

# prompt_value "Label" "default"
# Prints prompt to stderr, reads input, echoes result to stdout (default if blank)
prompt_value() {
    printf "  %s [%s]: " "$1" "$2" >&2
    read -r _pv_input
    if [ -z "$_pv_input" ]; then
        echo "$2"
    else
        echo "$_pv_input"
    fi
}

# prompt_yn "Question" "y" (or "n")
# Returns 0 for yes, 1 for no
prompt_yn() {
    printf "  %s (y/n) [%s]: " "$1" "$2" >&2
    read -r _yn_input
    _yn_input=$(echo "$_yn_input" | tr '[:upper:]' '[:lower:]')
    if [ -z "$_yn_input" ]; then
        _yn_input="$2"
    fi
    case "$_yn_input" in
        y|yes) return 0 ;;
        *)     return 1 ;;
    esac
}

# prompt_choice "Question" "1" "opt1" "opt2" "opt3" ...
# Prints numbered options, returns the chosen option string
prompt_choice() {
    _pc_question="$1"
    _pc_default="$2"
    shift 2

    printf "\n  %s\n" "$_pc_question" >&2
    _pc_num=1
    for _pc_opt in "$@"; do
        if [ "$_pc_num" = "$_pc_default" ]; then
            printf "    %d) %s (default)\n" "$_pc_num" "$_pc_opt" >&2
        else
            printf "    %d) %s\n" "$_pc_num" "$_pc_opt" >&2
        fi
        _pc_num=$(( _pc_num + 1 ))
    done

    printf "  Choice [%s]: " "$_pc_default" >&2
    read -r _pc_input
    if [ -z "$_pc_input" ]; then
        _pc_input="$_pc_default"
    fi

    # Return the nth argument
    _pc_num=1
    for _pc_opt in "$@"; do
        if [ "$_pc_num" = "$_pc_input" ]; then
            echo "$_pc_opt"
            return 0
        fi
        _pc_num=$(( _pc_num + 1 ))
    done

    # Invalid choice — return default
    _pc_num=1
    for _pc_opt in "$@"; do
        if [ "$_pc_num" = "$_pc_default" ]; then
            echo "$_pc_opt"
            return 0
        fi
        _pc_num=$(( _pc_num + 1 ))
    done
}

# ─── Usage ────────────────────────────────────────────────────────────────────

usage() {
    cat <<USAGE
run-rpz.sh — Cron/interactive wrapper for rpz-zone-factory v${VERSION}

USAGE:
  ./run-rpz.sh --setup                Interactive setup wizard
  ./run-rpz.sh [OPTIONS] [-- ARGS]    Run rpz-zone-factory

OPTIONS:
  -v, --version       Print version and exit
  -h, --help          Show this help and exit
  -i, --interactive   Interactive mode (output to stdout/stderr)
                      Default when stdin is a terminal.
  -c, --cron          Cron mode (log via syslog/logger)
                      Default when stdin is NOT a terminal.
  --setup             Interactive setup wizard: configure all options,
                      verify the environment, test rndc, and optionally
                      generate a cron entry and BIND config example.
  --reload-bind ZONE  After successful run, execute: rndc reload ZONE
                      Requires rndc access (see --setup for help).
  --full-rebuild      Force full rebuild path (freeze/reload/thaw) for all
                      zones, bypassing the incremental IXFR update path.
                      Use for recovery or after BIND/zone config changes.
  --force             Bypass the v0.7.0 fast-path that exits early when
                      every upstream source returns 304 Not Modified.
                      Use after manual zone edits or for debugging.
  --rpz-dir DIR       Override RPZ_DIR
  --python BIN        Override PYTHON_BIN

INCREMENTAL UPDATES (v0.6.0+):
  Zones listed in CONF_INCREMENTAL_ZONES (set via --setup) are updated
  by diffing the previously-fetched feed against the newly generated zone
  and sending only the additions/deletions via TSIG-authenticated nsupdate.
  BIND writes the delta to the zone's journal file, bumps the SOA serial,
  and secondaries receive NOTIFY → IXFR instead of re-AXFR'ing the whole zone.

  Feed snapshots live in CONF_FEEDS_DIR (default:
  /usr/local/etc/namedb/master/rpz/feeds). The allowlist source file also
  lives there and is treated as just another feed.

ARGS:
  Everything after "--" is passed directly to rpz-zone-factory.
  If no args are given, the script looks for .run-rpz.conf in its
  own directory (created by --setup) and uses the saved config.

DYNAMIC ALLOWLIST:
  Use allow.sh to add or remove domains from the RPZ allowlist in
  real time, without waiting for the next scheduled run:

    ./allow.sh example.com           # allow domain + *.domain
    ./allow.sh -n example.com        # allow domain only (no wildcard)
    ./allow.sh -r example.com        # remove from allowlist

  Requires TSIG authentication. Run --setup to configure the TSIG key,
  or see: ./allow.sh --help

EXAMPLES:
  # First-time setup (interactive wizard)
  ./run-rpz.sh --setup

  # Run using saved config from setup (no args needed)
  ./run-rpz.sh

  # Interactive test run with explicit args
  ./run-rpz.sh -i -- --output rpz --zone-name block.rpz -v

  # Explicit args override saved config
  ./run-rpz.sh --reload-bind block.rpz -- --output rpz --zone-name block.rpz \
    --output-file /usr/local/etc/namedb/master/block.rpz.db

USAGE
    exit "${1:-0}"
}

# ─── Argument parsing ────────────────────────────────────────────────────────

parse_args() {
    # Auto-detect mode: interactive if terminal, cron otherwise
    if [ -t 0 ]; then
        MODE="interactive"
    else
        MODE="cron"
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            -v|--version)
                echo "$VERSION"
                exit 0
                ;;
            -h|--help)
                usage 0
                ;;
            -i|--interactive)
                MODE="interactive"
                shift
                ;;
            -c|--cron)
                MODE="cron"
                shift
                ;;
            --setup)
                DO_SETUP=1
                MODE="interactive"
                shift
                ;;
            --reload-bind)
                if [ -z "$2" ] || [ "$(printf '%.1s' "$2")" = "-" ]; then
                    printf "ERROR: --reload-bind requires a zone name argument\n" >&2
                    usage 1
                fi
                DO_RELOAD=1
                RELOAD_ZONE="$2"
                shift 2
                ;;
            --full-rebuild)
                DO_FULL_REBUILD=1
                shift
                ;;
            --force)
                DO_FORCE=1
                shift
                ;;
            --rpz-dir)
                if [ -z "$2" ]; then
                    printf "ERROR: --rpz-dir requires a path argument\n" >&2
                    usage 1
                fi
                RPZ_DIR="$2"
                shift 2
                ;;
            --python)
                if [ -z "$2" ]; then
                    printf "ERROR: --python requires a binary name/path\n" >&2
                    usage 1
                fi
                PYTHON_BIN="$2"
                shift 2
                ;;
            --)
                shift
                RPZ_ARGS="$*"
                break
                ;;
            *)
                printf "ERROR: Unknown option: %s\n\n" "$1" >&2
                usage 1
                ;;
        esac
    done
}

# ─── Python version check ────────────────────────────────────────────────────

check_python_version() {
    _py="$1"

    if ! command -v "$_py" >/dev/null 2>&1; then
        log_err "Python not found: $_py"
        log_err "Install Python >= $PYTHON_MIN_VERSION or set PYTHON_BIN"
        return 1
    fi

    _version=$("$_py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
    if [ -z "$_version" ]; then
        log_err "Could not determine Python version from: $_py"
        return 1
    fi

    _major=$(echo "$_version" | cut -d. -f1)
    _minor=$(echo "$_version" | cut -d. -f2)
    _req_major=$(echo "$PYTHON_MIN_VERSION" | cut -d. -f1)
    _req_minor=$(echo "$PYTHON_MIN_VERSION" | cut -d. -f2)

    if [ "$_major" -lt "$_req_major" ] 2>/dev/null || \
       { [ "$_major" -eq "$_req_major" ] && [ "$_minor" -lt "$_req_minor" ]; } 2>/dev/null; then
        log_err "Python $_version is too old. Minimum required: $PYTHON_MIN_VERSION"
        log_err "Binary: $(command -v "$_py")"
        return 1
    fi

    log_info "Python $_version found: $(command -v "$_py")"
    return 0
}

# ─── Venv management ─────────────────────────────────────────────────────────

VENV_DIR=""

check_venv() {
    VENV_DIR="${RPZ_DIR}/${VENV_NAME}"
    _venv_py="${VENV_DIR}/bin/python"

    if [ ! -d "$VENV_DIR" ]; then
        log_warn "Virtual environment not found at: $VENV_DIR"
        return 1
    fi

    if [ ! -x "$_venv_py" ]; then
        log_warn "Venv exists but python binary missing/not executable: $_venv_py"
        return 1
    fi

    if ! "$_venv_py" -m pip --version >/dev/null 2>&1; then
        log_warn "Venv exists but pip is not available inside it"
        return 1
    fi

    if ! "$_venv_py" -c "import requests" >/dev/null 2>&1; then
        log_warn "Venv exists but dependencies are not installed"
        return 1
    fi

    log_info "Virtual environment OK: $VENV_DIR"
    return 0
}

create_venv() {
    VENV_DIR="${RPZ_DIR}/${VENV_NAME}"
    _req_file="${RPZ_DIR}/requirements.txt"

    log_info "Creating virtual environment at: $VENV_DIR"

    if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
        log_err "Python venv module is not available"
        log_err "Install it:"
        log_err "  Debian/Ubuntu: apt install python3-venv"
        log_err "  FreeBSD:       pkg install py311-venv (adjust version)"
        return 1
    fi

    if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
        log_err "Failed to create virtual environment"
        return 1
    fi

    log_info "Virtual environment created"

    _venv_py="${VENV_DIR}/bin/python"
    if ! "$_venv_py" -m pip --version >/dev/null 2>&1; then
        log_err "pip is not available in the new virtual environment"
        log_err "Fix:"
        log_err "  FreeBSD:       pkg install py311-pip (adjust for your Python version)"
        log_err "  Debian/Ubuntu: apt install python3-pip"
        log_err "Then re-run: $0 --setup"
        rm -rf "$VENV_DIR"
        return 1
    fi

    log_info "Upgrading pip..."
    if [ "$MODE" = "interactive" ]; then
        "$_venv_py" -m pip install --upgrade pip
    else
        "$_venv_py" -m pip install --upgrade pip >/dev/null 2>&1
    fi

    if [ ! -f "$_req_file" ]; then
        log_err "requirements.txt not found at: $_req_file"
        return 1
    fi

    log_info "Installing dependencies from: $_req_file"
    if [ "$MODE" = "interactive" ]; then
        "$_venv_py" -m pip install -r "$_req_file"
    else
        "$_venv_py" -m pip install -r "$_req_file" >/dev/null 2>&1
    fi

    _pip_rc=$?
    if [ $_pip_rc -ne 0 ]; then
        log_err "pip install failed (exit code: $_pip_rc)"
        return 1
    fi

    if ! "$_venv_py" -c "import requests" >/dev/null 2>&1; then
        log_err "Dependencies installed but import check failed"
        return 1
    fi

    log_info "Dependencies installed successfully"
    return 0
}

# ─── Python discovery ─────────────────────────────────────────────────────────

# Scan PATH for python3 and versioned python3.X binaries.
# Prints a human-readable summary and sets PYTHON_BIN to the best candidate.
discover_python() {
    _found=""       # "binary:path:version" entries, newline-separated
    _best_bin=""
    _best_ver=""
    _best_major=0
    _best_minor=0

    # Candidates to search for
    _candidates="python3 python3.9 python3.10 python3.11 python3.12 python3.13 python3.14"

    for _cand in $_candidates; do
        _path=$(command -v "$_cand" 2>/dev/null) || continue

        # Resolve symlinks to avoid counting the same binary twice
        _real=""
        if command -v realpath >/dev/null 2>&1; then
            _real=$(realpath "$_path" 2>/dev/null)
        elif command -v readlink >/dev/null 2>&1; then
            _real=$(readlink -f "$_path" 2>/dev/null)
        fi
        [ -z "$_real" ] && _real="$_path"

        _ver=$("$_path" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null) || continue

        _found="${_found}${_cand}:${_path}:${_ver}:${_real}
"

        # Track best (highest version that meets minimum)
        _cmaj=$(echo "$_ver" | cut -d. -f1)
        _cmin=$(echo "$_ver" | cut -d. -f2)
        _req_major=$(echo "$PYTHON_MIN_VERSION" | cut -d. -f1)
        _req_minor=$(echo "$PYTHON_MIN_VERSION" | cut -d. -f2)

        # Skip if below minimum
        if [ "$_cmaj" -lt "$_req_major" ] 2>/dev/null; then
            continue
        fi
        if [ "$_cmaj" -eq "$_req_major" ] && [ "$_cmin" -lt "$_req_minor" ] 2>/dev/null; then
            continue
        fi

        # Prefer highest version
        if [ "$_cmaj" -gt "$_best_major" ] 2>/dev/null || \
           { [ "$_cmaj" -eq "$_best_major" ] && [ "$_cmin" -gt "$_best_minor" ]; } 2>/dev/null; then
            _best_bin="$_cand"
            _best_ver="$_ver"
            _best_major="$_cmaj"
            _best_minor="$_cmin"
        fi
    done

    if [ -z "$_found" ]; then
        printf "  No Python 3 installations found in PATH.\n" >&2
        printf "  Install Python >= %s and re-run setup.\n" "$PYTHON_MIN_VERSION" >&2
        return 1
    fi

    # Build human-readable summary
    # Group by real path to show aliases
    printf "\n  Python installations found:\n" >&2

    # Deduplicate by real path, show all names that point to the same binary
    _seen_reals=""
    echo "$_found" | while IFS= read -r _entry; do
        [ -z "$_entry" ] && continue
        _cand=$(echo "$_entry" | cut -d: -f1)
        _path=$(echo "$_entry" | cut -d: -f2)
        _ver=$(echo "$_entry" | cut -d: -f3)
        _real=$(echo "$_entry" | cut -d: -f4)
        _dir=$(dirname "$_path")

        printf "    %-14s → %s (Python %s)\n" "$_cand" "$_path" "$_ver" >&2
    done

    # Show what python3 resolves to, if it exists and points to a versioned binary
    _py3_path=$(command -v python3 2>/dev/null)
    if [ -n "$_py3_path" ]; then
        _py3_real=""
        if command -v realpath >/dev/null 2>&1; then
            _py3_real=$(realpath "$_py3_path" 2>/dev/null)
        elif command -v readlink >/dev/null 2>&1; then
            _py3_real=$(readlink -f "$_py3_path" 2>/dev/null)
        fi
        if [ -n "$_py3_real" ] && [ "$_py3_real" != "$_py3_path" ]; then
            printf "\n    python3 → %s\n" "$_py3_real" >&2
        fi
    fi

    printf "\n" >&2

    # Update default if we found something better than current setting
    if [ -n "$_best_bin" ]; then
        PYTHON_BIN="$_best_bin"
    fi
}

# ─── Setup wizard ─────────────────────────────────────────────────────────────

run_setup() {
    printf "\n"
    printf "╔══════════════════════════════════════════════════════════════╗\n"
    printf "║        rpz-zone-factory v%-6s — Interactive Setup        ║\n" "$VERSION"
    printf "╚══════════════════════════════════════════════════════════════╝\n"
    printf "\n"
    printf "This wizard will walk you through configuration, verify your\n"
    printf "environment, and optionally generate a cron entry.\n"
    printf "\n"
    printf "Press Enter to accept defaults shown in [brackets].\n"

    # ── Section 1: Environment ────────────────────────────────────────────

    printf "\n─── Environment ────────────────────────────────────────────\n\n"

    RPZ_DIR=$(prompt_value "Project directory" "$RPZ_DIR")

    # Validate RPZ_DIR immediately
    if [ ! -d "$RPZ_DIR" ]; then
        log_err "Directory does not exist: $RPZ_DIR"
        log_err "Clone the repository first, then re-run --setup."
        return 1
    fi

    if [ ! -f "${RPZ_DIR}/run.py" ]; then
        log_err "run.py not found in: $RPZ_DIR"
        log_err "This doesn't look like the rpz-zone-factory project directory."
        return 1
    fi

    # Discover Python installations
    discover_python

    PYTHON_BIN=$(prompt_value "Python binary" "$PYTHON_BIN")

    if ! check_python_version "$PYTHON_BIN"; then
        return 1
    fi

    VENV_NAME=$(prompt_value "Venv directory name" "$VENV_NAME")

    # ── Venv check/create ─────────────────────────────────────────────────

    printf "\n─── Virtual Environment ────────────────────────────────────\n\n"

    if check_venv; then
        printf "\n  Existing venv is healthy.\n"
        if prompt_yn "Recreate it anyway?" "n"; then
            rm -rf "${RPZ_DIR}/${VENV_NAME}"
            if ! create_venv; then
                log_err "Venv creation failed."
                return 1
            fi
        fi
    else
        printf "\n"
        if ! create_venv; then
            log_err "Venv creation failed."
            return 1
        fi
    fi

    # Quick smoke test
    _venv_py="${RPZ_DIR}/${VENV_NAME}/bin/python"
    if "$_venv_py" "${RPZ_DIR}/run.py" --help >/dev/null 2>&1; then
        printf "\n  ✓ rpz-zone-factory responds to --help\n"
    else
        log_err "rpz-zone-factory failed --help smoke test"
        return 1
    fi

    # ── Section 2: Output Configuration ───────────────────────────────────

    printf "\n─── Output Configuration ───────────────────────────────────\n\n"

    _def_output="${CONF_OUTPUT:-rpz}"
    _choice=$(prompt_choice "Output format:" "1" "rpz  — BIND RPZ zone file (RFC 5782)" "pihole — Pi-hole flat blocklist")
    case "$_choice" in
        rpz*) CONF_OUTPUT="rpz" ;;
        pihole*) CONF_OUTPUT="pihole" ;;
    esac

    if [ "$CONF_OUTPUT" = "rpz" ]; then
        # Per-source mode question
        _def_persource="${CONF_PER_SOURCE:-no}"
        if [ "$_def_persource" = "yes" ]; then _yn_def="y"; else _yn_def="n"; fi

        printf "\n  Per-source mode outputs one zone file per threat source,\n"
        printf "  so BIND logs show which threat list triggered each block.\n\n"

        if prompt_yn "Enable per-source mode?" "$_yn_def"; then
            CONF_PER_SOURCE="yes"
            CONF_ZONE_NAME=""  # ignored in per-source mode

            _def_outdir="${CONF_OUTPUT_FILE:-/usr/local/etc/namedb/master/rpz}"
            CONF_OUTPUT_FILE=$(prompt_value "Output directory path" "$_def_outdir")

            # Feeds directory: holds previous/current feed snapshots for
            # incremental diffs, and the canonical allowlist.txt source file.
            printf "\n  The feeds directory holds snapshots of the domain list for\n"
            printf "  each zone from the previous run. On the next run, the script\n"
            printf "  diffs the new feed against the saved snapshot to compute\n"
            printf "  additions and deletions for incremental (IXFR) updates.\n"
            printf "  It also holds allowlist.txt, the canonical allowlist source.\n\n"
            _def_feeds="${CONF_FEEDS_DIR:-${CONF_OUTPUT_FILE}/feeds}"
            CONF_FEEDS_DIR=$(prompt_value "Feeds directory" "$_def_feeds")

            if [ ! -d "$CONF_FEEDS_DIR" ]; then
                printf "  \u2717 Feeds directory does not exist: %s\n" "$CONF_FEEDS_DIR"
                if prompt_yn "Create it now?" "y"; then
                    if mkdir -p "$CONF_FEEDS_DIR" 2>/dev/null; then
                        printf "  \u2713 Created: %s\n" "$CONF_FEEDS_DIR"
                    else
                        printf "  \u2717 Could not create %s (permission denied?)\n" "$CONF_FEEDS_DIR"
                        printf "    Create it manually and ensure the rpz-zone-factory user can write to it.\n"
                    fi
                fi
            else
                printf "  \u2713 Feeds directory exists: %s\n" "$CONF_FEEDS_DIR"
            fi

            # Allowlist file — now lives inside the feeds directory by default
            printf "\n  An allowlist zone (allowlist.rpz) provides BIND-level override\n"
            printf "  for domains that appear in threat zones but should be allowed.\n\n"
            printf "  The allowlist is a plain text file with one domain per line.\n"
            printf "  Lines starting with # are comments. Example:\n\n"
            printf "    # False positives\n"
            printf "    bing.com\n"
            printf "    www.bing.com\n\n"
            printf "  rpz-zone-factory reads this file and generates the allowlist RPZ zone.\n"
            printf "  allow.sh reads/writes the same file for interactive management.\n\n"
            _def_allowlist="${CONF_ALLOWLIST_FILE:-${CONF_FEEDS_DIR}/allowlist.txt}"
            CONF_ALLOWLIST_FILE=$(prompt_value "Allowlist text file path (blank to skip)" "$_def_allowlist")

            if [ -n "$CONF_ALLOWLIST_FILE" ] && [ ! -f "$CONF_ALLOWLIST_FILE" ]; then
                printf "  \u2717 Allowlist file does not exist: %s\n" "$CONF_ALLOWLIST_FILE"
                if prompt_yn "Create an empty allowlist file?" "y"; then
                    _allowlist_dir=$(dirname "$CONF_ALLOWLIST_FILE")
                    mkdir -p "$_allowlist_dir" 2>/dev/null
                    if : > "$CONF_ALLOWLIST_FILE" 2>/dev/null; then
                        printf "  \u2713 Created empty allowlist: %s\n" "$CONF_ALLOWLIST_FILE"
                    else
                        printf "  \u2717 Could not create %s\n" "$CONF_ALLOWLIST_FILE"
                    fi
                fi
            elif [ -n "$CONF_ALLOWLIST_FILE" ]; then
                _allow_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$CONF_ALLOWLIST_FILE" 2>/dev/null || echo 0)
                printf "  \u2713 Allowlist file exists (%s entries): %s\n" "$_allow_count" "$CONF_ALLOWLIST_FILE"
            fi
        else
            CONF_PER_SOURCE="no"
            _def_zone="${CONF_ZONE_NAME:-block.rpz}"
            CONF_ZONE_NAME=$(prompt_value "RPZ zone name" "$_def_zone")

            _def_outfile="${CONF_OUTPUT_FILE:-/usr/local/etc/namedb/master/block-combined.rpz.db}"
            CONF_OUTPUT_FILE=$(prompt_value "Output file path" "$_def_outfile")
        fi
    else
        CONF_PER_SOURCE="no"
        CONF_ZONE_NAME=""
        _def_outfile="${CONF_OUTPUT_FILE:-/usr/local/etc/pihole/custom.list}"
        CONF_OUTPUT_FILE=$(prompt_value "Output file path" "$_def_outfile")
    fi

    printf "\n  Available threat intel sources:\n"
    printf "    urlhaus      — Abuse.ch URLhaus (malware distribution URLs)\n"
    printf "    cisa         — CISA Known Exploited Vulnerabilities\n"
    printf "    drop         — Spamhaus DROP (hijacked IP blocks)\n"

    printf "    scamsniffer  — Scam Sniffer crypto scam domains\n"
    printf "    cryptoscamdb — CryptoScamDB phishing/scam domains\n"
    printf "    et-compromised — Emerging Threats compromised IPs (single hosts)\n"
    printf "\n"
    _def_sources="${CONF_SOURCES:-all}"
    CONF_SOURCES=$(prompt_value "Sources (space-separated, or 'all')" "$_def_sources")

    _def_verb="${CONF_VERBOSITY:-0}"
    _verb_choice=$(prompt_choice "Verbosity level:" "1" "Quiet (errors only)" "Info (-v)" "Debug (-vv)")
    case "$_verb_choice" in
        Quiet*) CONF_VERBOSITY="0" ;;
        Info*)  CONF_VERBOSITY="1" ;;
        Debug*) CONF_VERBOSITY="2" ;;
    esac

    # ── Section 3: BIND Reload ────────────────────────────────────────────

    printf "\n─── BIND Reload ────────────────────────────────────────────\n\n"

    _def_reload="${CONF_RELOAD:-yes}"
    if [ "$_def_reload" = "yes" ]; then
        _yn_def="y"
    else
        _yn_def="n"
    fi

    if prompt_yn "Reload BIND zone after each update?" "$_yn_def"; then
        CONF_RELOAD="yes"

        _def_rndc="${RNDC_BIN:-rndc}"
        RNDC_BIN=$(prompt_value "rndc binary" "$_def_rndc")

        if [ "$CONF_PER_SOURCE" = "yes" ]; then
            # Per-source mode: zone names are derived from source keys,
            # no need to ask. All zones are reloaded automatically.
            CONF_RELOAD_ZONE=""
            printf "\n  Per-source mode: all source zones will be reloaded\n"
            printf "  automatically after each update (allowlist.rpz,\n"
            printf "  urlhaus.rpz, cisa-kev.rpz, spamhaus-drop.rpz, etc.)\n"
        else
            if [ "$CONF_OUTPUT" = "rpz" ] && [ -n "$CONF_ZONE_NAME" ]; then
                _def_rzone="$CONF_ZONE_NAME"
            else
                _def_rzone="${CONF_RELOAD_ZONE:-block.rpz}"
            fi
            CONF_RELOAD_ZONE=$(prompt_value "Zone to reload" "$_def_rzone")
        fi

        # Test rndc access
        printf "\n  Testing rndc access...\n"

        # First check if rndc binary exists
        _rndc_path=""
        if command -v "$RNDC_BIN" >/dev/null 2>&1; then
            _rndc_path=$(command -v "$RNDC_BIN")
        else
            for _try in /usr/sbin/rndc /usr/local/sbin/rndc /usr/bin/rndc; do
                if [ -x "$_try" ]; then
                    _rndc_path="$_try"
                    RNDC_BIN="$_try"
                    break
                fi
            done
        fi

        if [ -z "$_rndc_path" ]; then
            printf "  ✗ rndc not found in PATH or common locations\n"
            printf "    Install BIND utilities or set RNDC_BIN.\n"
        else
            printf "  ✓ rndc found: %s\n" "$_rndc_path"

            # Test rndc status (non-destructive)
            _rndc_test=$($RNDC_BIN status 2>&1)
            _rndc_rc=$?

            if [ $_rndc_rc -eq 0 ]; then
                printf "  ✓ rndc status succeeded — you have access\n"

                # Test reload with a specific zone (skip in per-source mode
                # since the zones may not exist yet)
                if [ "$CONF_PER_SOURCE" != "yes" ] && [ -n "$CONF_RELOAD_ZONE" ]; then
                    _rndc_reload=$($RNDC_BIN reload "$CONF_RELOAD_ZONE" 2>&1)
                    _rndc_rrc=$?
                    if [ $_rndc_rrc -eq 0 ]; then
                        printf "  ✓ rndc reload %s succeeded\n" "$CONF_RELOAD_ZONE"
                    else
                        printf "  ✗ rndc reload %s failed: %s\n" "$CONF_RELOAD_ZONE" "$_rndc_reload"
                        printf "    The zone may not exist yet. This is OK if you haven't\n"
                        printf "    added the zone to named.conf yet (see BIND config below).\n"
                    fi
                fi
            else
                printf "  ✗ rndc status failed (exit code %d)\n" "$_rndc_rc"
                printf "    Output: %s\n" "$_rndc_test"
                printf "\n"
                printf "  Common fixes:\n"
                printf "    1. Ensure rndc.key is readable by this user:\n"
                printf "       chgrp named /usr/local/etc/namedb/rndc.key\n"
                printf "       chmod 640 /usr/local/etc/namedb/rndc.key\n"
                printf "       pw groupmod named -m $(whoami)  # FreeBSD\n"
                printf "       usermod -aG named $(whoami)     # Linux\n"
                printf "\n"
                printf "    2. Or run the cron job as the named user:\n"
                printf "       sudo -u named ./run-rpz.sh\n"
                printf "\n"
                printf "    3. Or use sudo (least recommended):\n"
                printf "       Set RNDC_BIN=\"sudo rndc\" in environment\n"
            fi
        fi
    else
        CONF_RELOAD="no"
        CONF_RELOAD_ZONE=""
    fi

    # ── Section 3b: Zone Validation & Compilation ─────────────────────────

    if [ "$CONF_OUTPUT" = "rpz" ]; then
        printf "\n─── Zone Validation & Compilation ──────────────────────────\n\n"

        # named-checkzone
        _def_checkzone="${CONF_CHECKZONE:-yes}"
        if [ "$_def_checkzone" = "yes" ]; then _yn_def="y"; else _yn_def="n"; fi

        if prompt_yn "Validate zone with named-checkzone before deploying?" "$_yn_def"; then
            CONF_CHECKZONE="yes"
            _cz_path=$(find_named_tool "named-checkzone")
            if [ -n "$_cz_path" ]; then
                printf "  ✓ named-checkzone found: %s\n" "$_cz_path"
            else
                printf "  ✗ named-checkzone not found in PATH or common locations\n"
                printf "    Install BIND utilities for zone validation.\n"
                printf "    Validation will be skipped at runtime if not found.\n"
            fi
        else
            CONF_CHECKZONE="no"
        fi

        # named-compilezone (raw binary format)
        printf "\n"
        _def_compile="${CONF_COMPILE_ZONE:-no}"
        if [ "$_def_compile" = "yes" ]; then _yn_def="y"; else _yn_def="n"; fi

        printf "  Compiled (raw) zone format loads significantly faster than\n"
        printf "  plain text. BIND skips the text parser and memory-maps the\n"
        printf "  pre-parsed data. Recommended for large zones (>10K entries).\n"
        printf "\n"
        printf "  ⚠  Requires 'masterfile-format raw;' in named.conf zone statement.\n"
        printf "     The BIND config example below will reflect your choice.\n"
        printf "\n"

        if prompt_yn "Compile zone to binary (raw) format with named-compilezone?" "$_yn_def"; then
            CONF_COMPILE_ZONE="yes"
            _compile_path=$(find_named_tool "named-compilezone")
            if [ -n "$_compile_path" ]; then
                printf "  ✓ named-compilezone found: %s\n" "$_compile_path"
            else
                printf "  ✗ named-compilezone not found in PATH or common locations\n"
                printf "    Install BIND utilities for zone compilation.\n"
                printf "    Will fall back to text format at runtime if not found.\n"
            fi
        else
            CONF_COMPILE_ZONE="no"
        fi
    else
        CONF_CHECKZONE="no"
        CONF_COMPILE_ZONE="no"
    fi


    # ── Section 3c: TSIG (shared by allow.sh and incremental updates) ────

    if [ "$CONF_PER_SOURCE" = "yes" ]; then
        printf "\n─── TSIG Key (Dynamic Updates) ──────────────────────────────\n\n"

        printf "  A single TSIG key is used for two dynamic-update paths:\n\n"
        printf "    1. allow.sh — interactive allowlist management\n"
        printf "    2. Incremental zone updates (IXFR) via run-rpz.sh\n\n"
        printf "  Both use nsupdate with the same TSIG key. BIND must be configured\n"
        printf "  with allow-update { key \"<keyname>\"; } on every zone that\n"
        printf "  accepts dynamic updates (all zones in per-source incremental mode).\n\n"

        if prompt_yn "Configure TSIG key for dynamic updates?" "y"; then

            # Detect platform defaults
            _tsig_os=$(uname -s)
            case "$_tsig_os" in
                FreeBSD)
                    _def_tsig_dir="/usr/local/etc/namedb/tsig"
                    ;;
                *)
                    _def_tsig_dir="/etc/bind/tsig"
                    ;;
            esac
            _def_tsig_key="${_def_tsig_dir}/rpz-update.key"

            _tsig_key="${CONF_TSIG_KEY_FILE:-$_def_tsig_key}"
            CONF_TSIG_KEY_FILE=$(prompt_value "TSIG key file path" "$_tsig_key")

            _allow_server="${CONF_ALLOW_SERVER:-localhost}"
            CONF_ALLOW_SERVER=$(prompt_value "nsupdate server" "$_allow_server")

            _allow_zone="${CONF_ALLOW_ZONE:-allowlist.rpz}"
            CONF_ALLOW_ZONE=$(prompt_value "Allowlist zone name" "$_allow_zone")

            # Check if TSIG key file exists
            if [ -f "$CONF_TSIG_KEY_FILE" ]; then
                printf "\n  ✓ TSIG key file found: %s\n" "$CONF_TSIG_KEY_FILE"
            else
                printf "\n  ✗ TSIG key file not found: %s\n" "$CONF_TSIG_KEY_FILE"
                printf "\n  Run './allow.sh --setup' for full TSIG setup instructions.\n"
            fi

            printf "\n  allow.sh usage:\n\n"
            printf "    ./allow.sh example.com           # allow domain + *.domain\n"
            printf "    ./allow.sh -n example.com        # allow domain only (no wildcard)\n"
            printf "    ./allow.sh -r example.com        # remove from allowlist\n\n"
        else
            CONF_TSIG_KEY_FILE=""
            CONF_ALLOW_SERVER=""
            CONF_ALLOW_ZONE=""
        fi
    fi

    # ── Section 3d: Incremental (IXFR) zones ─────────────────────────────

    if [ "$CONF_PER_SOURCE" = "yes" ] && [ -n "$CONF_TSIG_KEY_FILE" ]; then
        printf "\n─── Incremental (IXFR) Zone Updates ─────────────────────────\n\n"

        printf "  With incremental mode enabled for a zone, run-rpz.sh diffs the\n"
        printf "  previous feed snapshot against the freshly generated zone and\n"
        printf "  applies only the additions and deletions via nsupdate. BIND\n"
        printf "  writes the delta to the zone's journal (.jnl) and bumps the\n"
        printf "  SOA serial. Secondaries then receive NOTIFY → IXFR, transferring\n"
        printf "  only the changes instead of re-AXFR'ing the whole zone.\n\n"
        printf "  Requirements for each incremental zone:\n"
        printf "    • BIND zone definition has: allow-update { key \"<keyname>\"; };\n"
        printf "    • TSIG key is trusted for that zone\n"
        printf "    • First-ever run for the zone falls back to full rebuild (seed)\n\n"

        printf "  Available per-source zones: allowlist.rpz urlhaus.rpz cisa-kev.rpz\n"
        printf "                              spamhaus-drop.rpz scamsniffer.rpz cryptoscamdb.rpz\n"
        printf "                              et-compromised.rpz\n\n"
        printf "  Enter a space-separated list of zones to enable, or:\n"
        printf "    all   = enable incremental for every per-source zone (recommended)\n"
        printf "    none  = disable incremental, use full rebuild only\n\n"

        _def_incr="${CONF_INCREMENTAL_ZONES:-all}"
        _incr_choice=$(prompt_value "Incremental zones" "$_def_incr")

        case "$_incr_choice" in
            all|ALL)
                CONF_INCREMENTAL_ZONES="allowlist.rpz urlhaus.rpz cisa-kev.rpz spamhaus-drop.rpz scamsniffer.rpz cryptoscamdb.rpz et-compromised.rpz"
                printf "  ✓ All per-source zones enabled for incremental updates\n"
                ;;
            none|NONE|"")
                CONF_INCREMENTAL_ZONES=""
                printf "  ✓ Incremental updates disabled (full rebuild only)\n"
                ;;
            *)
                CONF_INCREMENTAL_ZONES="$_incr_choice"
                printf "  ✓ Incremental zones: %s\n" "$CONF_INCREMENTAL_ZONES"
                ;;
        esac

        if [ -n "$CONF_INCREMENTAL_ZONES" ]; then
            _def_ttl="${CONF_INCREMENTAL_TTL:-300}"
            CONF_INCREMENTAL_TTL=$(prompt_value "TTL for nsupdate records" "$_def_ttl")
        fi
    else
        if [ "$CONF_PER_SOURCE" = "yes" ] && [ -z "$CONF_TSIG_KEY_FILE" ]; then
            printf "\n  Incremental updates require a TSIG key — disabled.\n"
        fi
        CONF_INCREMENTAL_ZONES=""
    fi

    # ── Save configuration ────────────────────────────────────────────────

    printf "\n─── Saving Configuration ───────────────────────────────────\n\n"

    _conf_file="${RPZ_DIR}/.run-rpz.conf"

    cat > "$_conf_file" <<CONF
# run-rpz.sh configuration — generated by --setup
# $(date)
#
# This file is sourced by run-rpz.sh on startup.
# Edit manually or re-run: ./run-rpz.sh --setup

RPZ_DIR="${RPZ_DIR}"
PYTHON_BIN="${PYTHON_BIN}"
VENV_NAME="${VENV_NAME}"
RNDC_BIN="${RNDC_BIN}"

# Output configuration
CONF_OUTPUT="${CONF_OUTPUT}"
CONF_ZONE_NAME="${CONF_ZONE_NAME}"
CONF_OUTPUT_FILE="${CONF_OUTPUT_FILE}"
CONF_SOURCES="${CONF_SOURCES}"
CONF_VERBOSITY="${CONF_VERBOSITY}"

# BIND reload
CONF_RELOAD="${CONF_RELOAD}"
CONF_RELOAD_ZONE="${CONF_RELOAD_ZONE}"

# Zone validation and compilation
CONF_CHECKZONE="${CONF_CHECKZONE}"
CONF_COMPILE_ZONE="${CONF_COMPILE_ZONE}"

# Per-source mode
CONF_PER_SOURCE="${CONF_PER_SOURCE}"
CONF_ALLOWLIST_FILE="${CONF_ALLOWLIST_FILE}"
CONF_FEEDS_DIR="${CONF_FEEDS_DIR}"

# Dynamic updates (TSIG) — shared by allow.sh and incremental zone updates
CONF_TSIG_KEY_FILE="${CONF_TSIG_KEY_FILE}"
CONF_ALLOW_SERVER="${CONF_ALLOW_SERVER}"
CONF_ALLOW_ZONE="${CONF_ALLOW_ZONE}"

# Incremental (IXFR) zone updates — see v0.6.0 release notes
CONF_INCREMENTAL_ZONES="${CONF_INCREMENTAL_ZONES}"
CONF_INCREMENTAL_TTL="${CONF_INCREMENTAL_TTL}"
CONF

    printf "  ✓ Configuration saved to: %s\n" "$_conf_file"
    printf "\n  Future runs will use these settings automatically.\n"
    printf "  Override any value with CLI args or environment variables.\n"

    # ── Section 4: Cron Setup ─────────────────────────────────────────────

    printf "\n─── Cron Setup ─────────────────────────────────────────────\n\n"

    if prompt_yn "Generate a cron entry?" "y"; then

        _freq=$(prompt_choice "Run frequency:" "1" \
            "Every 4 hours (recommended for RPZ)" \
            "Every 6 hours" \
            "Every 12 hours" \
            "Daily at 3:00 AM" \
            "Custom (you provide the schedule)")

        _cron_schedule=""
        case "$_freq" in
            "Every 4"*)  _cron_schedule="15 */4 * * *" ;;
            "Every 6"*)  _cron_schedule="15 */6 * * *" ;;
            "Every 12"*) _cron_schedule="15 */12 * * *" ;;
            "Daily"*)    _cron_schedule="0 3 * * *" ;;
            "Custom"*)
                printf "\n"
                _cron_schedule=$(prompt_value "Cron schedule (5 fields)" "15 */4 * * *")
                ;;
        esac

        # Build the command
        _script_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
        # If we can't resolve, use a sensible default
        if [ ! -f "$_script_path" ]; then
            _script_path="${RPZ_DIR}/run-rpz.sh"
        fi

        _cron_cmd="$_script_path"

        # Add reload if configured
        if [ "$CONF_RELOAD" = "yes" ] && [ -n "$CONF_RELOAD_ZONE" ]; then
            _cron_cmd="$_cron_cmd --reload-bind ${CONF_RELOAD_ZONE}"
        fi

        # Build rpz-zone-factory args
        _rpz_args="--output ${CONF_OUTPUT}"
        if [ "$CONF_OUTPUT" = "rpz" ] && [ -n "$CONF_ZONE_NAME" ]; then
            _rpz_args="$_rpz_args --zone-name ${CONF_ZONE_NAME}"
        fi
        if [ -n "$CONF_OUTPUT_FILE" ]; then
            _rpz_args="$_rpz_args --output-file ${CONF_OUTPUT_FILE}"
        fi
        if [ -n "$CONF_SOURCES" ] && [ "$CONF_SOURCES" != "all" ]; then
            _rpz_args="$_rpz_args --sources ${CONF_SOURCES}"
        fi
        case "$CONF_VERBOSITY" in
            1) _rpz_args="$_rpz_args -v" ;;
            2) _rpz_args="$_rpz_args -vv" ;;
        esac

        printf "\n  ┌─────────────────────────────────────────────────────────┐\n"
        printf "  │ Add this line to your crontab (crontab -e):             │\n"
        printf "  └─────────────────────────────────────────────────────────┘\n"
        printf "\n"
        printf "  %s %s -- %s\n" "$_cron_schedule" "$_cron_cmd" "$_rpz_args"
        printf "\n"

        # Also show an alternative using saved config (no args needed)
        printf "  Or, since the config is saved, you can use the shorter form:\n"
        printf "\n"
        printf "  %s %s\n" "$_cron_schedule" "$_cron_cmd"
        printf "\n"
        printf "  (The script reads .run-rpz.conf and builds args automatically.)\n"

        # Ask about a second entry for Pi-hole if they chose RPZ
        if [ "$CONF_OUTPUT" = "rpz" ]; then
            printf "\n"
            if prompt_yn "Also generate a Pi-hole flat-file cron entry?" "n"; then
                _ph_file=$(prompt_value "Pi-hole output file" "/usr/local/www/rpz-zone-factory/block.txt")
                _ph_schedule=$(prompt_value "Cron schedule" "5 3 * * *")
                printf "\n  %s %s -- --output pihole --output-file %s\n" \
                    "$_ph_schedule" "$_script_path" "$_ph_file"
                printf "\n"
            fi
        fi
    fi

    # ── Section 5: BIND Configuration Example ─────────────────────────────

    printf "\n─── BIND Configuration ─────────────────────────────────────\n\n"

    if prompt_yn "Show example BIND response-policy configuration?" "y"; then

        if [ "$CONF_PER_SOURCE" = "yes" ]; then
            # Per-source BIND config example
            _ex_dir="${CONF_OUTPUT_FILE:-/usr/local/etc/namedb/master/rpz}"

            printf "\n"
            printf "  ┌─────────────────────────────────────────────────────────┐\n"
            printf "  │ 1. Zone definitions (named.conf or included file)      │\n"
            printf "  └─────────────────────────────────────────────────────────┘\n"
            printf "\n"

            # Show allowlist zone first
            printf "  // Allowlist zone (passthru overrides)\n"
            printf "  zone \"allowlist.rpz\" {\n"
            printf "      type primary;\n"
            printf "      file \"%s/allowlist.rpz.db\";\n" "$_ex_dir"
            if [ "$CONF_COMPILE_ZONE" = "yes" ]; then
                printf "      masterfile-format raw;\n"
            fi
            if [ -n "$CONF_TSIG_KEY_FILE" ]; then
                _tsig_keyname=$(basename "$CONF_TSIG_KEY_FILE" | sed 's/\.key$//')
                printf "      allow-update { key \"%s\"; };\n" "$_tsig_keyname"
            fi
            printf "      allow-query { localhost; };\n"
            printf "      allow-transfer { none; };\n"
            printf "  };\n\n"

            # Show TSIG key include if configured
            if [ -n "$CONF_TSIG_KEY_FILE" ]; then
                printf "  // TSIG key for dynamic allowlist updates (allow.sh)\n"
                printf "  include \"%s\";\n\n" "$CONF_TSIG_KEY_FILE"
            fi

            # Show each source zone. If TSIG is configured AND the zone is
            # in CONF_INCREMENTAL_ZONES, include allow-update so run-rpz.sh
            # can deliver IXFR-style incremental updates via nsupdate.
            for _src_zone in urlhaus.rpz cisa-kev.rpz spamhaus-drop.rpz scamsniffer.rpz cryptoscamdb.rpz et-compromised.rpz; do
                printf "  zone \"%s\" {\n" "$_src_zone"
                printf "      type primary;\n"
                printf "      file \"%s/%s.db\";\n" "$_ex_dir" "$_src_zone"
                if [ "$CONF_COMPILE_ZONE" = "yes" ]; then
                    printf "      masterfile-format raw;\n"
                fi
                if [ -n "$CONF_TSIG_KEY_FILE" ] && is_incremental_zone "$_src_zone"; then
                    printf "      allow-update { key \"%s\"; };  // v0.6.0+ incremental updates\n" "$_tsig_keyname"
                fi
                printf "      allow-query { localhost; };\n"
                printf "      allow-transfer { none; };\n"
                printf "  };\n\n"
            done

            printf "  ┌─────────────────────────────────────────────────────────┐\n"
            printf "  │ 2. Response policy (inside options { } block)          │\n"
            printf "  └─────────────────────────────────────────────────────────┘\n"
            printf "\n"
            printf "  options {\n"
            printf "      // ... existing options ...\n"
            printf "\n"
            printf "      response-policy {\n"
            printf "          zone \"allowlist.rpz\" policy passthru;\n"
            printf "          zone \"urlhaus.rpz\";\n"
            printf "          zone \"cisa-kev.rpz\";\n"
            printf "          zone \"spamhaus-drop.rpz\";\n"


            printf "          zone \"scamsniffer.rpz\";\n"
            printf "          zone \"cryptoscamdb.rpz\";\n"
            printf "          zone \"et-compromised.rpz\";\n"
            printf "      };\n"
            printf "  };\n"

        else
            # Combined mode BIND config (original)
            _ex_zone="${CONF_ZONE_NAME:-block.rpz}"
            _ex_file="$CONF_OUTPUT_FILE"
            # Sanity check: if output file looks like a directory or is empty, build a path
            case "$_ex_file" in
                "") _ex_file="/usr/local/etc/namedb/master/${_ex_zone}.db" ;;
                */) _ex_file="${_ex_file}${_ex_zone}.db" ;;
            esac

            printf "\n"
            printf "  ┌─────────────────────────────────────────────────────────┐\n"
            printf "  │ 1. Zone definition (named.conf or included file)       │\n"
            printf "  └─────────────────────────────────────────────────────────┘\n"
            printf "\n"
            printf "  zone \"%s\" {\n" "$_ex_zone"
            printf "      type primary;\n"
            printf "      file \"%s\";\n" "$_ex_file"
            if [ "$CONF_COMPILE_ZONE" = "yes" ]; then
                printf "      masterfile-format raw;   // compiled binary — faster loading\n"
            fi
            printf "      allow-query { localhost; };\n"
            printf "      allow-transfer { none; };\n"
            printf "  };\n"
            printf "\n"
            printf "  ┌─────────────────────────────────────────────────────────┐\n"
            printf "  │ 2. Response policy (inside options { } block)          │\n"
            printf "  └─────────────────────────────────────────────────────────┘\n"
            printf "\n"
            printf "  options {\n"
            printf "      // ... existing options ...\n"
            printf "\n"
            printf "      response-policy {\n"
            printf "          zone \"%s\" policy given;\n" "$_ex_zone"
            printf "          // Add more RPZ zones here, evaluated in order:\n"
            printf "          // zone \"whitelist.rpz\" policy passthru;\n"
            printf "          // zone \"malware.rpz\";\n"
            printf "      };\n"
            printf "  };\n"
        fi
        printf "\n"
        printf "  ┌─────────────────────────────────────────────────────────┐\n"
        printf "  │ Notes                                                  │\n"
        printf "  └─────────────────────────────────────────────────────────┘\n"
        printf "\n"
        printf "  • 'policy given' uses the action specified in each RPZ record\n"
        printf "    (rpz-zone-factory writes CNAME . records → NXDOMAIN).\n"
        printf "\n"
        if [ -n "$CONF_INCREMENTAL_ZONES" ]; then
            printf "  • Incremental (IXFR) zones: %s\n" "$CONF_INCREMENTAL_ZONES"
            printf "    These zones MUST have 'allow-update { key ... };' in the zone\n"
            printf "    statement. run-rpz.sh applies diffs via nsupdate; BIND bumps\n"
            printf "    the SOA serial automatically and secondaries IXFR the delta.\n"
            printf "  • Force a full rebuild (bypassing incremental) with:\n"
            printf "      %s --full-rebuild\n" "$(basename "$0")"
            printf "\n"
        fi
        if [ "$CONF_COMPILE_ZONE" = "yes" ]; then
            printf "  • Zone is compiled to binary (raw) format for faster loading.\n"
            printf "    The 'masterfile-format raw;' directive is REQUIRED in the zone\n"
            printf "    statement above. Without it, BIND will fail to parse the file.\n"
            printf "\n"
            printf "  • The text zone is written to a .tmp file, validated with\n"
            printf "    named-checkzone, then compiled with named-compilezone.\n"
            printf "    If either step fails, the previous zone file is untouched.\n"
            printf "\n"
        elif [ "$CONF_CHECKZONE" = "yes" ]; then
            printf "  • Zone is validated with named-checkzone before deployment.\n"
            printf "    If validation fails, the previous zone file is untouched.\n"
            printf "\n"
        fi
        printf "  • RPZ zones are evaluated in order. Put whitelists first\n"
        printf "    with 'policy passthru' to override subsequent blocks.\n"
        printf "\n"
        printf "  • To log RPZ actions, add to the logging section:\n"
        printf "\n"
        printf "    channel rpz_log {\n"
        printf "        file \"/var/log/named/rpz.log\" versions 5 size 20m;\n"
        printf "        severity info;\n"
        printf "        print-time yes;\n"
        printf "        print-category yes;\n"
        printf "    };\n"
        printf "    category rpz { rpz_log; };\n"
        printf "\n"
        printf "  • After adding the zone, run:  rndc reconfig\n"
        printf "    Subsequent updates only need:  rndc reload %s\n" "$_ex_zone"
        printf "\n"
        printf "  • Test with:  dig @localhost known-bad-domain.example\n"
        printf "    Should return NXDOMAIN if the domain is in the blocklist.\n"
        printf "\n"
    fi

    # ── Done ──────────────────────────────────────────────────────────────

    printf "─── Setup Complete ─────────────────────────────────────────\n\n"
    printf "  Config saved:  %s/.run-rpz.conf\n" "$RPZ_DIR"
    printf "  Test run:      %s -i\n" "$0"
    printf "  Full help:     %s --help\n" "$0"
    printf "  Allowlist:     ./allow.sh <domain>  (see ./allow.sh --setup for TSIG setup)\n"
    printf "\n"

    return 0
}

# ─── Build args from config ───────────────────────────────────────────────────

# When no RPZ_ARGS are given on the CLI, build them from saved config
build_args_from_config() {
    if [ -z "$CONF_OUTPUT" ]; then
        return 1  # No saved config
    fi

    RPZ_ARGS="--output ${CONF_OUTPUT}"

    # Per-source mode
    if [ "$CONF_PER_SOURCE" = "yes" ]; then
        RPZ_ARGS="$RPZ_ARGS --per-source"

        if [ -n "$CONF_OUTPUT_FILE" ]; then
            # In per-source mode with validation, write to .tmp subdirectory
            if [ "$CONF_OUTPUT" = "rpz" ] && \
               { [ "$CONF_CHECKZONE" = "yes" ] || [ "$CONF_COMPILE_ZONE" = "yes" ]; }; then
                RPZ_ARGS="$RPZ_ARGS --output-file ${CONF_OUTPUT_FILE}/.tmp"
            else
                RPZ_ARGS="$RPZ_ARGS --output-file ${CONF_OUTPUT_FILE}"
            fi
        fi

        if [ -n "$CONF_ALLOWLIST_FILE" ]; then
            RPZ_ARGS="$RPZ_ARGS --allowlist ${CONF_ALLOWLIST_FILE}"
        fi
    else
        # Combined mode
        if [ "$CONF_OUTPUT" = "rpz" ] && [ -n "$CONF_ZONE_NAME" ]; then
            RPZ_ARGS="$RPZ_ARGS --zone-name ${CONF_ZONE_NAME}"
        fi

        if [ -n "$CONF_OUTPUT_FILE" ]; then
            # When checkzone or compilezone is enabled, write to a temp file first
            # so the previous zone file is preserved until validation passes.
            if [ "$CONF_OUTPUT" = "rpz" ] && \
               { [ "$CONF_CHECKZONE" = "yes" ] || [ "$CONF_COMPILE_ZONE" = "yes" ]; }; then
                RPZ_ARGS="$RPZ_ARGS --output-file ${CONF_OUTPUT_FILE}.tmp"
            else
                RPZ_ARGS="$RPZ_ARGS --output-file ${CONF_OUTPUT_FILE}"
            fi
        fi
    fi

    if [ -n "$CONF_SOURCES" ] && [ "$CONF_SOURCES" != "all" ]; then
        RPZ_ARGS="$RPZ_ARGS --sources ${CONF_SOURCES}"
    fi

    case "$CONF_VERBOSITY" in
        1) RPZ_ARGS="$RPZ_ARGS -v" ;;
        2) RPZ_ARGS="$RPZ_ARGS -vv" ;;
    esac

    # Pass --force through to rpz-zone-factory to bypass the v0.7.0
    # all-sources-unchanged fast-path.
    if [ $DO_FORCE -eq 1 ]; then
        RPZ_ARGS="$RPZ_ARGS --force"
    fi

    log_info "Using saved config from .run-rpz.conf"
    return 0
}

# ─── BIND tool discovery ──────────────────────────────────────────────────────

# Find a named-* tool (named-checkzone, named-compilezone) in common locations.
# Echoes the path if found, empty string if not.
find_named_tool() {
    _tool_name="$1"

    # Check PATH first
    if command -v "$_tool_name" >/dev/null 2>&1; then
        command -v "$_tool_name"
        return 0
    fi

    # Common locations
    for _try in /usr/sbin/"$_tool_name" /usr/local/sbin/"$_tool_name" \
                /usr/bin/"$_tool_name" /usr/local/bin/"$_tool_name"; do
        if [ -x "$_try" ]; then
            echo "$_try"
            return 0
        fi
    done

    return 1
}

# ─── Incremental (IXFR) zone updates ────────────────────────────
#
# Architecture (v0.6.0):
#
#   For each zone listed in CONF_INCREMENTAL_ZONES we maintain two feed
#   snapshots in CONF_FEEDS_DIR:
#
#     <feeds>/<zone>.list.previous   domains from last successful run
#     <feeds>/<zone>.list.current    domains from this run (extracted from .db)
#
#   On each run:
#     1. Python renders a fresh zone file to <output>/.tmp/<zone>.db
#     2. For each incremental zone:
#          a. If .previous is missing → seed path:
#               - full rebuild (checkzone, compilezone, freeze/reload/thaw)
#               - extract .current from the new .db, rename to .previous
#          b. If .previous exists → incremental path:
#               - rndc sync <zone>    flush journal to .db (reconcile state)
#               - extract .current from the new .db
#               - diff .previous vs .current → additions + deletions
#               - empty diff → no-op, discard .current, skip zone
#               - non-empty → send nsupdate batch with TSIG, BIND bumps serial
#                 and writes to journal; secondaries receive NOTIFY and IXFR
#               - on success: rename .current → .previous
#               - on failure: fall back to full rebuild for this zone
#
# CNAME target:
#     allowlist.rpz     → CNAME rpz-passthru.   (policy passthru)
#     all other zones   → CNAME .               (NXDOMAIN block)

# Echo the CNAME target for a given zone name.
incremental_cname_target() {
    case "$1" in
        allowlist.rpz|allowlist)
            echo "rpz-passthru."
            ;;
        *)
            echo "."
            ;;
    esac
}

# Check if a zone name is listed in CONF_INCREMENTAL_ZONES.
# Returns 0 if yes, 1 if no.
is_incremental_zone() {
    _zone="$1"
    [ -z "$CONF_INCREMENTAL_ZONES" ] && return 1
    case " $CONF_INCREMENTAL_ZONES " in
        *\ "$_zone"\ *) return 0 ;;
        *) return 1 ;;
    esac
}

# Extract sorted unique bare domain names from a rendered RPZ zone file.
# Input:  path to a .db file containing "<domain>.<zone>. CNAME ." lines
#         (or "rpz-passthru." for the allowlist zone).
# Output: one bare domain per line, sorted, unique. Wildcard twins are
#         stripped. SOA, NS, comments, and TTL directives are ignored.
#
# Args: <db_file> <zone_name>
extract_domains_from_zone() {
    _zone_file="$1"
    _zone="$2"

    if [ ! -f "$_zone_file" ]; then
        return 1
    fi

    # Match lines like: example.com.<zone>. CNAME .
    # Capture everything before .<zone>. and skip the wildcard (*.) twin lines
    # which produce duplicates after we strip the leading "*.".
    # RPZ IP triggers (N.reversed-ip.rpz-ip.<zone>.) are passed through
    # verbatim as bare keys so they round-trip through the diff/nsupdate path.
    awk -v z="$_zone" '
        BEGIN { suffix = "." z "." }
        /^[[:space:]]*;/   { next }   # comments
        /^[[:space:]]*\$/  { next }   # directives ($TTL)
        /^[[:space:]]*@/   { next }   # SOA/NS apex records
        /CNAME/ {
            # Field 1 is the left-hand side including trailing dot
            name = $1
            # Strip trailing dot if present
            sub(/\.$/, "", name)
            # Must end with the zone suffix (minus trailing dot)
            zs = z
            sub(/\.$/, "", zs)
            n = length(name) - length(zs) - 1
            if (n < 0) next
            # Check the suffix matches
            if (substr(name, n + 2) != zs) next
            bare = substr(name, 1, n)
            # Skip wildcard twins — we only want one row per domain
            if (substr(bare, 1, 2) == "*.") next
            print bare
        }
    ' "$_zone_file" | LC_ALL=C sort -u
}

# Build an nsupdate input file for the given zone from additions/deletions.
#
# Args: <zone_name> <additions_file> <deletions_file> <out_nsupdate_file>
build_nsupdate_batch() {
    _zone="$1"
    _adds="$2"
    _dels="$3"
    _out="$4"

    _target=$(incremental_cname_target "$_zone")
    _ttl="${CONF_INCREMENTAL_TTL:-300}"
    _server="${CONF_ALLOW_SERVER:-localhost}"

    # Domain names ending in ".rpz-ip" are IP triggers — they never have
    # a wildcard twin in the rendered zone, so skip emitting one.
    _emit_update() {
        _op="$1"          # "add" or "delete"
        _bare="$2"
        _is_iptrig=0
        case "$_bare" in
            *.rpz-ip) _is_iptrig=1 ;;
        esac

        if [ "$_op" = "add" ]; then
            printf 'update add %s.%s. %s IN CNAME %s\n' "$_bare" "$_zone" "$_ttl" "$_target"
            if [ $_is_iptrig -eq 0 ]; then
                printf 'update add *.%s.%s. %s IN CNAME %s\n' "$_bare" "$_zone" "$_ttl" "$_target"
            fi
        else
            printf 'update delete %s.%s. CNAME\n' "$_bare" "$_zone"
            if [ $_is_iptrig -eq 0 ]; then
                printf 'update delete *.%s.%s. CNAME\n' "$_bare" "$_zone"
            fi
        fi
    }

    {
        printf 'server %s\n' "$_server"
        printf 'zone %s\n' "$_zone"

        # Deletions first — if a domain is re-added we want the delete+add to
        # register as a net change in the journal.
        if [ -s "$_dels" ]; then
            while IFS= read -r _d; do
                [ -z "$_d" ] && continue
                _emit_update "delete" "$_d"
            done < "$_dels"
        fi

        if [ -s "$_adds" ]; then
            while IFS= read -r _d; do
                [ -z "$_d" ] && continue
                _emit_update "add" "$_d"
            done < "$_adds"
        fi

        printf 'send\n'
    } > "$_out"
}

# Apply an incremental update for a single zone.
#
# Args: <zone_name> <new_db_file>
#
# Returns:
#   0 = success (nsupdate applied or no-op)
#   1 = fatal — caller should fall back to full rebuild for this zone
#   2 = seed required — .previous missing, caller should full-rebuild and seed
run_incremental_for_zone() {
    _zone="$1"
    _new_db="$2"

    _feeds_dir="${CONF_FEEDS_DIR}"
    if [ -z "$_feeds_dir" ]; then
        log_err "CONF_FEEDS_DIR is not set — cannot run incremental update for $_zone"
        return 1
    fi

    if [ ! -d "$_feeds_dir" ]; then
        if ! mkdir -p "$_feeds_dir" 2>/dev/null; then
            log_err "Cannot create feeds dir: $_feeds_dir"
            return 1
        fi
    fi

    _prev="${_feeds_dir}/${_zone}.list.previous"
    _curr="${_feeds_dir}/${_zone}.list.current"

    # Seed path: no previous snapshot, caller should full-rebuild and then
    # write <zone>.list.previous from the rendered .db.
    if [ ! -f "$_prev" ]; then
        log_info "Incremental: no previous snapshot for $_zone — seed required"
        return 2
    fi

    if [ ! -f "$_new_db" ] || [ ! -s "$_new_db" ]; then
        log_err "Incremental: new zone file missing or empty for $_zone: $_new_db"
        return 1
    fi

    # Preflight: TSIG key, nsupdate binary
    if [ -z "$CONF_TSIG_KEY_FILE" ] || [ ! -f "$CONF_TSIG_KEY_FILE" ]; then
        log_err "Incremental: TSIG key file missing: $CONF_TSIG_KEY_FILE"
        return 1
    fi
    if ! command -v nsupdate >/dev/null 2>&1; then
        log_err "Incremental: nsupdate not found in PATH"
        return 1
    fi

    # Reconcile on-disk .db with BIND's in-memory state by flushing the
    # journal to disk. Any dynamic changes made since the last scheduled
    # run (e.g. via allow.sh) are now reflected in the .previous snapshot
    # via the next seed, but for the running zone we rely on nsupdate's
    # idempotent behavior to handle overlap.
    log_info "Incremental[$_zone]: rndc sync \u2192 flushing journal to .db"
    _sync_output=$($RNDC_BIN sync "$_zone" 2>&1)
    _sync_rc=$?
    if [ $_sync_rc -ne 0 ]; then
        log_warn "Incremental[$_zone]: rndc sync failed ($_sync_rc): $_sync_output"
        # Not fatal — nsupdate can still proceed, diff may just be noisier.
    fi

    # Extract fresh domain list from the new zone
    if ! extract_domains_from_zone "$_new_db" "$_zone" > "$_curr"; then
        log_err "Incremental[$_zone]: failed to extract domains from $_new_db"
        rm -f "$_curr"
        return 1
    fi

    _new_count=$(wc -l < "$_curr" | tr -d ' ')
    _old_count=$(wc -l < "$_prev" | tr -d ' ')

    if [ "$_new_count" = "0" ]; then
        log_warn "Incremental[$_zone]: extracted zero domains from new zone — skipping (kept .previous)"
        rm -f "$_curr"
        return 1
    fi

    # Compute additions (in new not old) and deletions (in old not new)
    _adds=$(mktemp "/tmp/rpz-adds-${_zone}.XXXXXX" 2>/dev/null || echo "/tmp/rpz-adds-${_zone}.$$")
    _dels=$(mktemp "/tmp/rpz-dels-${_zone}.XXXXXX" 2>/dev/null || echo "/tmp/rpz-dels-${_zone}.$$")

    LC_ALL=C comm -13 "$_prev" "$_curr" > "$_adds"
    LC_ALL=C comm -23 "$_prev" "$_curr" > "$_dels"

    _add_count=$(wc -l < "$_adds" | tr -d ' ')
    _del_count=$(wc -l < "$_dels" | tr -d ' ')

    log_info "Incremental[$_zone]: prev=$_old_count curr=$_new_count adds=$_add_count dels=$_del_count"

    # No changes — no-op, keep .previous as-is, discard .current
    if [ "$_add_count" = "0" ] && [ "$_del_count" = "0" ]; then
        log_info "Incremental[$_zone]: no changes, skipping nsupdate"
        rm -f "$_adds" "$_dels" "$_curr"
        return 0
    fi

    # Build nsupdate batch
    _batch=$(mktemp "/tmp/rpz-nsupdate-${_zone}.XXXXXX" 2>/dev/null || echo "/tmp/rpz-nsupdate-${_zone}.$$")
    build_nsupdate_batch "$_zone" "$_adds" "$_dels" "$_batch"

    # Apply
    log_info "Incremental[$_zone]: applying nsupdate (+$_add_count -$_del_count)"
    _nsupd_output=$(nsupdate -k "$CONF_TSIG_KEY_FILE" < "$_batch" 2>&1)
    _nsupd_rc=$?

    if [ $_nsupd_rc -ne 0 ]; then
        log_err "Incremental[$_zone]: nsupdate failed (rc=$_nsupd_rc): $_nsupd_output"
        # Keep intermediate files for post-mortem
        log_err "Incremental[$_zone]: kept for debugging: adds=$_adds dels=$_dels batch=$_batch"
        rm -f "$_curr"
        return 1
    fi

    log_info "Incremental[$_zone]: nsupdate succeeded"

    # Rotate: current becomes the new previous
    if ! mv "$_curr" "$_prev"; then
        log_warn "Incremental[$_zone]: failed to rotate $_curr → $_prev"
    fi

    # Flush journal to disk so .db stays in sync
    _sync_output=$($RNDC_BIN sync "$_zone" 2>&1)
    _sync_rc=$?
    if [ $_sync_rc -ne 0 ]; then
        log_warn "Incremental[$_zone]: post-update rndc sync failed ($_sync_rc): $_sync_output"
    fi

    # Clean up tmp files on success
    rm -f "$_adds" "$_dels" "$_batch"

    return 0
}

# Seed (or re-seed) the previous feed snapshot for a zone from its .db file.
# Called after a full rebuild for a zone that is managed incrementally, so
# the next scheduled run has a baseline to diff against.
#
# Args: <zone_name> <db_file>
seed_feed_snapshot() {
    _zone="$1"
    _db_file="$2"

    if [ -z "$CONF_FEEDS_DIR" ]; then
        return 0  # nothing to do
    fi
    if [ ! -d "$CONF_FEEDS_DIR" ]; then
        mkdir -p "$CONF_FEEDS_DIR" 2>/dev/null || return 1
    fi

    _prev="${CONF_FEEDS_DIR}/${_zone}.list.previous"
    _curr="${CONF_FEEDS_DIR}/${_zone}.list.current"

    if ! extract_domains_from_zone "$_db_file" "$_zone" > "$_curr"; then
        log_warn "Seed[$_zone]: failed to extract domains from $_db_file"
        rm -f "$_curr"
        return 1
    fi

    _count=$(wc -l < "$_curr" | tr -d ' ')
    if [ "$_count" = "0" ]; then
        log_warn "Seed[$_zone]: extracted zero domains from $_db_file"
        rm -f "$_curr"
        return 1
    fi

    if ! mv "$_curr" "$_prev"; then
        log_warn "Seed[$_zone]: failed to move $_curr → $_prev"
        rm -f "$_curr"
        return 1
    fi

    log_info "Seed[$_zone]: saved baseline snapshot ($_count domains)"
    return 0
}

# ─── Main run ─────────────────────────────────────────────────────────────────

run_rpz() {
    _venv_py="${RPZ_DIR}/${VENV_NAME}/bin/python"
    _run_py="${RPZ_DIR}/run.py"

    # Validate project directory
    if [ ! -d "$RPZ_DIR" ]; then
        log_err "RPZ_DIR does not exist: $RPZ_DIR"
        return 1
    fi

    if [ ! -f "$_run_py" ]; then
        log_err "run.py not found in RPZ_DIR: $RPZ_DIR"
        return 1
    fi

    # If no args provided, try to load from config
    if [ -z "$RPZ_ARGS" ]; then
        if ! build_args_from_config; then
            log_err "No arguments given and no .run-rpz.conf found."
            log_err "Run '$0 --setup' first, or pass arguments after --"
            return 1
        fi
    fi

    # Apply reload from config if not set via CLI. This runs regardless of
    # whether args came from build_args_from_config or from "-- <args>" on
    # the CLI, so that explicit-arg runs still get BIND reload/freeze/thaw.
    if [ $DO_RELOAD -eq 0 ] && [ "$CONF_RELOAD" = "yes" ]; then
        if [ "$CONF_PER_SOURCE" = "yes" ]; then
            DO_RELOAD=1
            RELOAD_ZONE="__per_source__"
        elif [ -n "$CONF_RELOAD_ZONE" ]; then
            DO_RELOAD=1
            RELOAD_ZONE="$CONF_RELOAD_ZONE"
        fi
    fi

    # Seed-gap detection: if any incremental zone is missing its .list.previous
    # snapshot, the v0.7.0 fast-path would skip rendering and prevent the shell
    # from ever seeding. Inject --force so Python renders all zones, letting
    # the shell seed the new ones. This is a one-time cost per new zone.
    if [ $DO_FORCE -eq 0 ] && [ -n "$CONF_INCREMENTAL_ZONES" ] && [ -n "$CONF_FEEDS_DIR" ]; then
        _need_force=0
        for _iz in $CONF_INCREMENTAL_ZONES; do
            if [ ! -f "${CONF_FEEDS_DIR}/${_iz}.list.previous" ]; then
                log_info "Seed-gap: ${_iz} has no .list.previous — adding --force"
                _need_force=1
            fi
        done
        if [ $_need_force -eq 1 ]; then
            RPZ_ARGS="$RPZ_ARGS --force"
        fi
    fi

    # Check Python
    if ! check_python_version "$PYTHON_BIN"; then
        return 1
    fi

    # Check venv — create if missing
    if ! check_venv; then
        log_info "Venv not ready, attempting auto-setup..."
        if ! create_venv; then
            log_err "Auto-setup failed. Run '$0 --setup' interactively to diagnose."
            return 1
        fi
    fi

    # Build command
    log_info "Running rpz-zone-factory..."
    log_info "  RPZ_DIR: $RPZ_DIR"
    if [ -n "$RPZ_ARGS" ]; then
        log_info "  Args: $RPZ_ARGS"
    fi

    # Execute
    if [ "$MODE" = "interactive" ]; then
        eval "\"$_venv_py\" \"$_run_py\" $RPZ_ARGS"
        EXIT_CODE=$?
    else
        _stderr_tmp=$(mktemp /tmp/rpz-run.XXXXXX 2>/dev/null || echo "/tmp/rpz-run.$$")
        eval "\"$_venv_py\" \"$_run_py\" $RPZ_ARGS" 2>"$_stderr_tmp"
        EXIT_CODE=$?

        if [ -s "$_stderr_tmp" ]; then
            while IFS= read -r _line; do
                [ -z "$_line" ] && continue
                log_info "$_line"
            done < "$_stderr_tmp"
        fi
        rm -f "$_stderr_tmp"
    fi

    # Exit code 2 from rpz-zone-factory means "no upstream changes; nothing
    # rendered" (the v0.7.0 fast-path). Treat as a successful no-op and skip
    # the entire post-processing pipeline (validation, IXFR, reload, seed).
    if [ $EXIT_CODE -eq 2 ]; then
        log_info "rpz-zone-factory: no upstream changes — skipping post-processing"
        return 0
    fi

    if [ $EXIT_CODE -ne 0 ]; then
        log_err "rpz-zone-factory exited with code: $EXIT_CODE"
        return $EXIT_CODE
    fi

    log_info "rpz-zone-factory completed successfully"

    # ── Per-source mode: incremental (IXFR) and/or full rebuild ───────────
    #
    # Per-zone decision:
    #   • Zone listed in CONF_INCREMENTAL_ZONES + .previous exists + TSIG ok
    #     → apply diff via nsupdate (no freeze, zone stays live)
    #   • Otherwise (seed, fallback, or not configured for incremental)
    #     → freeze/write/reload/thaw full-rebuild path
    #
    # --full-rebuild on the CLI forces every zone through the full path.

    if [ "$CONF_PER_SOURCE" = "yes" ] && [ "$CONF_OUTPUT" = "rpz" ] && [ -n "$CONF_OUTPUT_FILE" ]; then

        _tmp_dir="${CONF_OUTPUT_FILE}/.tmp"
        mkdir -p "$CONF_OUTPUT_FILE"

        if [ ! -d "$_tmp_dir" ]; then
            log_err "Temp directory missing: $_tmp_dir — aborting"
            return 1
        fi

        _checkzone_bin=""
        if [ "$CONF_CHECKZONE" = "yes" ]; then
            _checkzone_bin=$(find_named_tool "named-checkzone")
            if [ -z "$_checkzone_bin" ]; then
                log_warn "named-checkzone not found — skipping validation"
            fi
        fi

        _compilezone_bin=""
        if [ "$CONF_COMPILE_ZONE" = "yes" ]; then
            _compilezone_bin=$(find_named_tool "named-compilezone")
            if [ -z "$_compilezone_bin" ]; then
                log_warn "named-compilezone not found — will use text format"
            fi
        fi

        # Phase 1: validate every fresh .db with named-checkzone.
        # If a zone fails validation, we skip it entirely (leave the live
        # zone untouched). Build a list of zones that pass.
        _valid_zones=""
        _any_failed=0
        for _db_file in "$_tmp_dir"/*.db; do
            [ ! -f "$_db_file" ] && continue
            _basename=$(basename "$_db_file")
            _zone_name=$(echo "$_basename" | sed 's/\.db$//')

            if [ ! -s "$_db_file" ]; then
                log_warn "Zone file is empty, skipping: $_db_file"
                _any_failed=1
                continue
            fi

            if [ -n "$_checkzone_bin" ]; then
                log_info "Validating $_zone_name with named-checkzone..."
                _cz_output=$("$_checkzone_bin" "$_zone_name" "$_db_file" 2>&1)
                _cz_rc=$?
                if [ $_cz_rc -ne 0 ]; then
                    log_err "named-checkzone failed for $_zone_name (rc=$_cz_rc): $_cz_output"
                    log_err "Keeping previous zone file intact for $_zone_name."
                    _any_failed=1
                    continue
                fi
                log_info "named-checkzone passed for $_zone_name"
            fi

            _valid_zones="${_valid_zones} ${_zone_name}"
        done

        # Phase 2: sort valid zones into two buckets — incremental and full.
        _incremental_bucket=""
        _full_bucket=""
        for _zone_name in $_valid_zones; do
            _db_file="${_tmp_dir}/${_zone_name}.db"

            # --full-rebuild flag forces full path for every zone
            if [ $DO_FULL_REBUILD -eq 1 ]; then
                _full_bucket="${_full_bucket} ${_zone_name}"
                continue
            fi

            # Not listed for incremental → full
            if ! is_incremental_zone "$_zone_name"; then
                _full_bucket="${_full_bucket} ${_zone_name}"
                continue
            fi

            # Needs TSIG configuration
            if [ -z "$CONF_TSIG_KEY_FILE" ] || [ ! -f "$CONF_TSIG_KEY_FILE" ]; then
                log_warn "Incremental[$_zone_name]: TSIG key missing — falling back to full rebuild"
                _full_bucket="${_full_bucket} ${_zone_name}"
                continue
            fi

            # Needs .previous snapshot (otherwise it's a seed → full rebuild)
            if [ -z "$CONF_FEEDS_DIR" ] || [ ! -f "${CONF_FEEDS_DIR}/${_zone_name}.list.previous" ]; then
                log_info "Incremental[$_zone_name]: no previous snapshot — seeding via full rebuild"
                _full_bucket="${_full_bucket} ${_zone_name}"
                continue
            fi

            _incremental_bucket="${_incremental_bucket} ${_zone_name}"
        done

        # Phase 3: incremental zones — apply while BIND is live.
        # On nsupdate failure, push the zone into the full-rebuild bucket.
        _incr_applied_count=0
        for _zone_name in $_incremental_bucket; do
            _db_file="${_tmp_dir}/${_zone_name}.db"

            run_incremental_for_zone "$_zone_name" "$_db_file"
            _incr_rc=$?

            case $_incr_rc in
                0)
                    _incr_applied_count=$(( _incr_applied_count + 1 ))
                    # Successful incremental: BIND owns the zone file now.
                    # run_incremental_for_zone already called 'rndc sync' so
                    # the on-disk .db reflects BIND's authoritative state
                    # including the nsupdate deltas and the bumped serial.
                    #
                    # Do NOT overwrite the .db with our freshly Python-rendered
                    # copy from .tmp — it has a stale Python-computed serial
                    # (hour-based) that would regress BIND's state and produce
                    # "serial has gone backwards" errors, potentially breaking
                    # IXFR for secondaries.
                    #
                    # The .tmp/.db file is still useful as the input to the
                    # next scheduled run's diff (via .list.current vs
                    # .list.previous extraction) but it does NOT go to the
                    # final zone location.
                    log_info "Incremental[$_zone_name]: BIND owns the .db file; skipping post-copy"
                    ;;
                2)
                    # Seed required — shouldn't happen (we pre-checked .previous
                    # above) but handle defensively by routing to full rebuild.
                    log_info "Incremental[$_zone_name]: seed required at apply time — routing to full rebuild"
                    _full_bucket="${_full_bucket} ${_zone_name}"
                    ;;
                *)
                    log_warn "Incremental[$_zone_name]: failed — falling back to full rebuild"
                    _full_bucket="${_full_bucket} ${_zone_name}"
                    ;;
            esac
        done

        # Phase 4+5: full-rebuild zones — per-zone freeze/replace/thaw.
        #
        # For each zone in the full bucket we:
        #   1. Try `rndc freeze <zone>`. Success (or "already frozen") means
        #      the zone is dynamic — we'll thaw it at the end to re-read the
        #      file synchronously. "not dynamic" means it's a static zone and
        #      we'll use `rndc reload <zone>` instead.
        #   2. Stage the new .db to <final>.new.$$, atomic mv into place.
        #   3. Remove any orphaned journal (safe now: dyn zone is frozen,
        #      static zone has no journal).
        #   4. Per-zone thaw (dyn) or reload (static) to activate.
        #
        # Per-zone thaw is required for dynamic zones because:
        #   • `rndc reload <zone>` flatly fails on a dynamic zone
        #     ("rndc: 'reload' failed: dynamic zone").
        #   • A global `rndc thaw` is asynchronous and races against the
        #     freshly-replaced file, producing "zone serial has gone
        #     backwards" warnings as BIND catches up out-of-order.
        #   • Per-zone `rndc thaw <zone>` re-reads the file synchronously
        #     for that zone alone, eliminating the race.
        _full_has_work=0
        for _zone_name in $_full_bucket; do
            _full_has_work=1
            break
        done

        if [ $_full_has_work -eq 1 ] && [ $DO_RELOAD -eq 1 ]; then
            # Sync journals to disk first so any in-flight dynamic updates
            # are persisted before we replace files. With -clean BIND also
            # removes the journal after writing, leaving us a clean slate.
            log_info "Syncing all dynamic zones: rndc sync -clean"
            _sync_output=$($RNDC_BIN sync -clean 2>&1)
            _sync_rc=$?
            if [ $_sync_rc -ne 0 ]; then
                log_warn "rndc sync -clean failed: $_sync_output"
            fi

            for _zone_name in $_full_bucket; do
                _db_file="${_tmp_dir}/${_zone_name}.db"
                _final_file="${CONF_OUTPUT_FILE}/${_zone_name}.db"
                _stage_file="${_final_file}.new.$$"

                if [ ! -s "$_db_file" ]; then
                    log_warn "Full rebuild: source .db missing or empty for $_zone_name"
                    continue
                fi

                # Detect dynamic vs static by attempting a per-zone freeze.
                # Success or "already frozen" → dynamic; "not dynamic" → static.
                _is_dynamic=0
                _freeze_output=$($RNDC_BIN freeze "$_zone_name" 2>&1)
                _freeze_rc=$?
                if [ $_freeze_rc -eq 0 ]; then
                    _is_dynamic=1
                    log_info "Frozen $_zone_name (dynamic)"
                else
                    case "$_freeze_output" in
                        *"already frozen"*)
                            _is_dynamic=1
                            log_warn "rndc freeze $_zone_name: already frozen — proceeding"
                            ;;
                        *"not dynamic"*|*"not a dynamic"*)
                            _is_dynamic=0
                            ;;
                        *)
                            log_warn "rndc freeze $_zone_name: $_freeze_output"
                            ;;
                    esac
                fi

                # Stage to <final>.new.$$ first, then atomic rename. This
                # only needs dir-write permission, not write access to the
                # existing file — important because BIND may own a zone file
                # after dynamic update journal flushes.
                if [ -n "$_compilezone_bin" ]; then
                    log_info "Compiling $_zone_name to raw format..."
                    _compile_output=$("$_compilezone_bin" -o "$_stage_file" -F raw \
                        "$_zone_name" "$_db_file" 2>&1)
                    _compile_rc=$?
                    if [ $_compile_rc -ne 0 ]; then
                        log_err "named-compilezone failed for $_zone_name (rc=$_compile_rc): $_compile_output"
                        rm -f "$_stage_file"
                        if [ $_is_dynamic -eq 1 ]; then
                            $RNDC_BIN thaw "$_zone_name" >/dev/null 2>&1 || true
                        fi
                        continue
                    fi
                    log_info "Zone compiled: $_compile_output"
                else
                    if ! cp "$_db_file" "$_stage_file"; then
                        log_err "Failed to stage $_db_file → $_stage_file"
                        rm -f "$_stage_file"
                        if [ $_is_dynamic -eq 1 ]; then
                            $RNDC_BIN thaw "$_zone_name" >/dev/null 2>&1 || true
                        fi
                        continue
                    fi
                fi

                chmod 664 "$_stage_file" 2>/dev/null || true
                if ! mv "$_stage_file" "$_final_file"; then
                    log_err "Failed to rename $_stage_file → $_final_file"
                    rm -f "$_stage_file"
                    if [ $_is_dynamic -eq 1 ]; then
                        $RNDC_BIN thaw "$_zone_name" >/dev/null 2>&1 || true
                    fi
                    continue
                fi

                # Remove any orphaned journal — for dyn zones the freeze
                # ensures no writer holds it; for static zones it shouldn't
                # exist in the first place.
                _jnl_file="${_final_file}.jnl"
                if [ -f "$_jnl_file" ]; then
                    rm -f "$_jnl_file"
                    log_info "Removed orphaned journal: ${_zone_name}.db.jnl"
                fi

                # Activate the new file.
                if [ $_is_dynamic -eq 1 ]; then
                    log_info "Thawing $_zone_name (re-read from disk)"
                    _thaw_output=$($RNDC_BIN thaw "$_zone_name" 2>&1)
                    _thaw_rc=$?
                    if [ $_thaw_rc -ne 0 ]; then
                        log_err "rndc thaw $_zone_name failed: $_thaw_output"
                    fi
                else
                    log_info "Reloading $_zone_name"
                    _reload_output=$($RNDC_BIN reload "$_zone_name" 2>&1)
                    _reload_rc=$?
                    if [ $_reload_rc -ne 0 ]; then
                        log_warn "rndc reload $_zone_name: $_reload_output"
                    fi
                fi
            done
        fi

        # Phase 6: seed feed snapshots for every zone that took the full path
        # AND is configured as incremental. This gives the next scheduled run
        # a baseline to diff against — how a zone transitions from seed to
        # incremental. Extract from the text .db in .tmp (compilezone does
        # not consume its input so the file is still there).
        if [ -n "$CONF_FEEDS_DIR" ]; then
            for _zone_name in $_full_bucket; do
                if is_incremental_zone "$_zone_name"; then
                    _seed_src="${_tmp_dir}/${_zone_name}.db"
                    if [ -f "$_seed_src" ]; then
                        seed_feed_snapshot "$_zone_name" "$_seed_src" || true
                    fi
                fi
            done
        fi

        # Clean up tmp directory
        rm -rf "$_tmp_dir"

        _total_zones=0
        for _zone_name in $_valid_zones; do
            _total_zones=$(( _total_zones + 1 ))
        done
        _full_count=0
        for _zone_name in $_full_bucket; do
            _full_count=$(( _full_count + 1 ))
        done

        log_info "Per-source run complete: zones=$_total_zones incremental=$_incr_applied_count full=$_full_count"

        if [ $_any_failed -eq 1 ]; then
            return 1
        fi
        return 0
    fi

    # ── Combined mode guards and validation ───────────────────────────────

    # Zero-length file guard: abort before validating/reloading if output is empty
    # When checkzone/compilezone is enabled, the output went to .tmp
    if [ -n "$CONF_OUTPUT_FILE" ]; then
        if { [ "$CONF_CHECKZONE" = "yes" ] || [ "$CONF_COMPILE_ZONE" = "yes" ]; } && \
           [ "$CONF_OUTPUT" = "rpz" ]; then
            _guard_file="${CONF_OUTPUT_FILE}.tmp"
        else
            _guard_file="$CONF_OUTPUT_FILE"
        fi
        if [ ! -s "$_guard_file" ]; then
            log_err "Output file is empty or missing: $_guard_file — aborting"
            return 1
        fi
    fi

    # ── Zone validation and compilation (RPZ output only) ─────────────────

    if [ "$CONF_OUTPUT" = "rpz" ] && [ -n "$CONF_OUTPUT_FILE" ] && [ -n "$CONF_ZONE_NAME" ]; then

        # When checkzone/compilezone is enabled, Python wrote to .tmp via
        # build_args_from_config; the final path still has the old zone file.
        _final_file="$CONF_OUTPUT_FILE"
        _text_file="$CONF_OUTPUT_FILE"

        if [ "$CONF_CHECKZONE" = "yes" ] || [ "$CONF_COMPILE_ZONE" = "yes" ]; then
            _text_file="${CONF_OUTPUT_FILE}.tmp"

            if [ ! -s "$_text_file" ]; then
                log_err "Text zone file is empty or missing: $_text_file — aborting"
                return 1
            fi
        fi

        # Step 1: named-checkzone validation
        if [ "$CONF_CHECKZONE" = "yes" ]; then
            _checkzone_bin=$(find_named_tool "named-checkzone")
            if [ -n "$_checkzone_bin" ]; then
                log_info "Validating zone with named-checkzone..."
                _cz_output=$("$_checkzone_bin" "$CONF_ZONE_NAME" "$_text_file" 2>&1)
                _cz_rc=$?
                if [ $_cz_rc -ne 0 ]; then
                    log_err "named-checkzone failed (exit code: $_cz_rc)"
                    log_err "$_cz_output"
                    log_err "Keeping previous zone file intact. Fix the issue and re-run."
                    rm -f "$_text_file"
                    return 1
                fi
                log_info "named-checkzone passed: $_cz_output"
            else
                log_warn "named-checkzone not found — skipping validation"
            fi
        fi

        # Step 2: named-compilezone (text → raw binary format)
        if [ "$CONF_COMPILE_ZONE" = "yes" ]; then
            _compilezone_bin=$(find_named_tool "named-compilezone")
            if [ -n "$_compilezone_bin" ]; then
                log_info "Compiling zone to raw format with named-compilezone..."
                _compile_output=$("$_compilezone_bin" -o "$_final_file" -F raw \
                    "$CONF_ZONE_NAME" "$_text_file" 2>&1)
                _compile_rc=$?
                if [ $_compile_rc -ne 0 ]; then
                    log_err "named-compilezone failed (exit code: $_compile_rc)"
                    log_err "$_compile_output"
                    log_err "Keeping previous zone file intact."
                    rm -f "$_text_file"
                    return 1
                fi
                log_info "Zone compiled: $_compile_output"
                rm -f "$_text_file"

                if [ ! -s "$_final_file" ]; then
                    log_err "Compiled zone file is empty: $_final_file — aborting"
                    return 1
                fi
            else
                log_warn "named-compilezone not found — falling back to text format"
                mv "$_text_file" "$_final_file"
            fi
        elif [ "$CONF_CHECKZONE" = "yes" ]; then
            # Checkzone passed, no compilation — move validated text to final path
            mv "$_text_file" "$_final_file"
        fi
    fi

    # Optional BIND reload
    if [ $DO_RELOAD -eq 1 ]; then
        reload_bind
        return $?
    fi

    return 0
}

# ─── BIND reload ──────────────────────────────────────────────────────────────

reload_bind() {
    if ! command -v "$RNDC_BIN" >/dev/null 2>&1; then
        for _try in /usr/sbin/rndc /usr/local/sbin/rndc /usr/bin/rndc; do
            if [ -x "$_try" ]; then
                RNDC_BIN="$_try"
                break
            fi
        done
    fi

    if ! command -v "$RNDC_BIN" >/dev/null 2>&1; then
        log_err "rndc not found. Cannot reload zone: $RELOAD_ZONE"
        log_err "Install BIND utilities or set RNDC_BIN to the correct path."
        return 1
    fi

    log_info "Reloading BIND zone: $RELOAD_ZONE"
    _rndc_output=$($RNDC_BIN reload "$RELOAD_ZONE" 2>&1)
    _rndc_rc=$?

    if [ $_rndc_rc -ne 0 ]; then
        log_err "rndc reload failed (exit code: $_rndc_rc): $_rndc_output"
        log_err "Check rndc key permissions. See: $0 --help"
        return 1
    fi

    log_info "BIND zone reloaded: $RELOAD_ZONE"
    return 0
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    if [ $DO_SETUP -eq 1 ]; then
        run_setup
        exit $?
    fi

    run_rpz
    exit $?
}

main "$@"
