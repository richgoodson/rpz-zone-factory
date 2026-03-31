#!/bin/sh
# run-rpz.sh — Cron/interactive wrapper for rpz-zone-factory
# Version: 0.3.0
# Portable: Debian, Ubuntu, FreeBSD 13+
# POSIX sh — no bashisms.
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

# Source config file if it exists (overrides defaults above)
_conf_file="${RPZ_DIR}/.run-rpz.conf"
if [ -f "$_conf_file" ]; then
    # shellcheck source=/dev/null
    . "$_conf_file"
fi

# ─── Version ──────────────────────────────────────────────────────────────────

VERSION="0.3.0"

# ─── Globals ──────────────────────────────────────────────────────────────────

MODE="cron"       # "cron" or "interactive"
DO_SETUP=0
DO_RELOAD=0
RELOAD_ZONE=""
RPZ_ARGS=""
EXIT_CODE=0

# ─── Logging ──────────────────────────────────────────────────────────────────

log_info() {
    if [ "$MODE" = "cron" ]; then
        logger -t "$LOG_TAG" -p "${LOG_FACILITY}.info" "$1"
    else
        printf "[INFO]  %s\n" "$1" >&2
    fi
}

log_warn() {
    if [ "$MODE" = "cron" ]; then
        logger -t "$LOG_TAG" -p "${LOG_FACILITY}.warning" "$1"
    else
        printf "[WARN]  %s\n" "$1" >&2
    fi
}

log_err() {
    if [ "$MODE" = "cron" ]; then
        logger -t "$LOG_TAG" -p "${LOG_FACILITY}.err" "$1"
    else
        printf "[ERROR] %s\n" "$1" >&2
    fi
}

log_notice() {
    if [ "$MODE" = "cron" ]; then
        logger -t "$LOG_TAG" -p "${LOG_FACILITY}.notice" "$1"
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
  --rpz-dir DIR       Override RPZ_DIR
  --python BIN        Override PYTHON_BIN

ARGS:
  Everything after "--" is passed directly to rpz-zone-factory.
  If no args are given, the script looks for .run-rpz.conf in its
  own directory (created by --setup) and uses the saved config.

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
        _def_zone="${CONF_ZONE_NAME:-block.rpz}"
        CONF_ZONE_NAME=$(prompt_value "RPZ zone name" "$_def_zone")

        _def_outfile="${CONF_OUTPUT_FILE:-/usr/local/etc/namedb/master/block-combined.rpz.db}"
        CONF_OUTPUT_FILE=$(prompt_value "Output file path" "$_def_outfile")
    else
        CONF_ZONE_NAME=""
        _def_outfile="${CONF_OUTPUT_FILE:-/usr/local/etc/pihole/custom.list}"
        CONF_OUTPUT_FILE=$(prompt_value "Output file path" "$_def_outfile")
    fi

    printf "\n  Available threat intel sources:\n"
    printf "    urlhaus      — Abuse.ch URLhaus (malware distribution URLs)\n"
    printf "    cisa         — CISA Known Exploited Vulnerabilities\n"
    printf "    drop         — Spamhaus DROP (hijacked IP blocks)\n"
    printf "    edrop        — Spamhaus EDROP (extended DROP)\n"
    printf "    dbl          — Spamhaus DBL (domain blocklist)\n"
    printf "    scamsniffer  — Scam Sniffer crypto scam domains\n"
    printf "    cryptoscamdb — CryptoScamDB phishing/scam domains\n"
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

        if [ "$CONF_OUTPUT" = "rpz" ] && [ -n "$CONF_ZONE_NAME" ]; then
            _def_rzone="$CONF_ZONE_NAME"
        else
            _def_rzone="${CONF_RELOAD_ZONE:-block.rpz}"
        fi
        CONF_RELOAD_ZONE=$(prompt_value "Zone to reload" "$_def_rzone")

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

                # Also test the actual reload (dry-ish: reload is idempotent)
                _rndc_reload=$($RNDC_BIN reload "$CONF_RELOAD_ZONE" 2>&1)
                _rndc_rrc=$?
                if [ $_rndc_rrc -eq 0 ]; then
                    printf "  ✓ rndc reload %s succeeded\n" "$CONF_RELOAD_ZONE"
                else
                    printf "  ✗ rndc reload %s failed: %s\n" "$CONF_RELOAD_ZONE" "$_rndc_reload"
                    printf "    The zone may not exist yet. This is OK if you haven't\n"
                    printf "    added the zone to named.conf yet (see BIND config below).\n"
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
        printf "\n"
        printf "  ┌─────────────────────────────────────────────────────────┐\n"
        printf "  │ Notes                                                  │\n"
        printf "  └─────────────────────────────────────────────────────────┘\n"
        printf "\n"
        printf "  • 'policy given' uses the action specified in each RPZ record\n"
        printf "    (rpz-zone-factory writes CNAME . records → NXDOMAIN).\n"
        printf "\n"
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

    if [ "$CONF_OUTPUT" = "rpz" ] && [ -n "$CONF_ZONE_NAME" ]; then
        RPZ_ARGS="$RPZ_ARGS --zone-name ${CONF_ZONE_NAME}"
    fi

    if [ -n "$CONF_OUTPUT_FILE" ]; then
        RPZ_ARGS="$RPZ_ARGS --output-file ${CONF_OUTPUT_FILE}"
    fi

    if [ -n "$CONF_SOURCES" ] && [ "$CONF_SOURCES" != "all" ]; then
        RPZ_ARGS="$RPZ_ARGS --sources ${CONF_SOURCES}"
    fi

    case "$CONF_VERBOSITY" in
        1) RPZ_ARGS="$RPZ_ARGS -v" ;;
        2) RPZ_ARGS="$RPZ_ARGS -vv" ;;
    esac

    # Apply reload from config if not set via CLI
    if [ $DO_RELOAD -eq 0 ] && [ "$CONF_RELOAD" = "yes" ] && [ -n "$CONF_RELOAD_ZONE" ]; then
        DO_RELOAD=1
        RELOAD_ZONE="$CONF_RELOAD_ZONE"
    fi

    log_info "Using saved config from .run-rpz.conf"
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

    if [ $EXIT_CODE -ne 0 ]; then
        log_err "rpz-zone-factory exited with code: $EXIT_CODE"
        return $EXIT_CODE
    fi

    log_info "rpz-zone-factory completed successfully"

    # Zero-length file guard: abort before reloading if output is empty
    if [ -n "$CONF_OUTPUT_FILE" ] && [ ! -s "$CONF_OUTPUT_FILE" ]; then
        log_err "Output file is empty or missing: $CONF_OUTPUT_FILE — aborting reload"
        return 1
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
