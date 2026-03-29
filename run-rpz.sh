#!/bin/sh
# run-rpz.sh — Cron/interactive wrapper for rpz-zone-factory
# Portable: Debian, Ubuntu, FreeBSD 13+
# POSIX sh — no bashisms.
#
# Usage:
#   ./run-rpz.sh --setup                  First-run: create venv, install deps
#   ./run-rpz.sh [OPTIONS] [-- RPZ_ARGS]  Run rpz-zone-factory
#
# See usage() below or run with -h/--help.

# ─── Configuration ────────────────────────────────────────────────────────────
# Override these via environment or edit in place.

# Path to the rpz-zone-factory project directory (contains run.py, requirements.txt)
RPZ_DIR="${RPZ_DIR:-/opt/rpz-zone-factory}"

# Python binary (must be >= 3.9). Searches PATH if not absolute.
PYTHON_BIN="${PYTHON_BIN:-python3}"

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

# ─── Globals ──────────────────────────────────────────────────────────────────

MODE="cron"          # "cron" or "interactive"
DO_SETUP=0
DO_RELOAD=0
RELOAD_ZONE=""
RPZ_ARGS=""
EXIT_CODE=0

# ─── Logging ──────────────────────────────────────────────────────────────────
# In cron mode:        logger (syslog)
# In interactive mode: stderr

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

# ─── Usage ────────────────────────────────────────────────────────────────────

usage() {
    cat <<'USAGE'
run-rpz.sh — Cron/interactive wrapper for rpz-zone-factory

USAGE:
  ./run-rpz.sh --setup                     First-run setup (interactive)
  ./run-rpz.sh [OPTIONS] [-- RPZ_ARGS...]  Run rpz-zone-factory

OPTIONS:
  -h, --help              Show this help and exit
  -i, --interactive       Interactive mode (output to stdout/stderr)
                          Default when stdin is a terminal.
  -c, --cron              Cron mode (log via syslog/logger)
                          Default when stdin is NOT a terminal.
  --setup                 Create/verify venv and install dependencies,
                          then exit. Run this once before adding to cron.
  --reload-bind ZONE      After successful run, execute: rndc reload ZONE
                          Requires rndc access (see BIND RELOAD below).
  --rpz-dir DIR           Override RPZ_DIR (default: /opt/rpz-zone-factory)
  --python BIN            Override PYTHON_BIN (default: python3)

RPZ_ARGS:
  Everything after "--" is passed directly to rpz-zone-factory. Example:

  ./run-rpz.sh -i -- --output rpz --zone-name block.rpz --output-file /etc/namedb/rpz/block.rpz.db -v
  ./run-rpz.sh -c --reload-bind block.rpz -- --output rpz --zone-name block.rpz --output-file /etc/namedb/rpz/block.rpz.db

rpz-zone-factory arguments (for reference):
  --output {rpz,pihole}   Output format (default: rpz)
  --zone-name ZONE_NAME   RPZ zone name (default: rpz.local)
  --output-file FILE      Write to file (default: stdout)
  --sources SRC [SRC...]  Sources: urlhaus, cisa, drop, edrop, dbl (default: all)
  -v                      Increase verbosity (-v INFO, -vv DEBUG)

ENVIRONMENT VARIABLES:
  RPZ_DIR       Path to rpz-zone-factory project (default: /opt/rpz-zone-factory)
  PYTHON_BIN    Python interpreter (default: python3)
  VENV_NAME     Venv directory name (default: .venv)
  RNDC_BIN      Path to rndc binary (default: rndc)

BIND RELOAD (--reload-bind):
  The script runs: rndc reload <ZONE>

  For this to work, the user running the script needs rndc access.
  Options (pick one):

  1. rndc.key file (most common):
     - rndc reads /etc/namedb/rndc.key or /etc/bind/rndc.key by default
     - Ensure the cron user can read the key file:
         chgrp named /etc/namedb/rndc.key && chmod 640 /etc/namedb/rndc.key
         usermod -aG named <cron_user>    # Linux
         pw groupmod named -m <cron_user> # FreeBSD

  2. rndc.conf with explicit key:
     - Create /etc/namedb/rndc.conf (or /etc/bind/rndc.conf) with key block
     - rndc uses this automatically

  3. Run the cron job as the 'named' or 'bind' user:
         sudo -u named ./run-rpz.sh ...
     (also needs write access to the output file directory)

  4. sudo without password (least recommended):
         rpzuser ALL=(ALL) NOPASSWD: /usr/sbin/rndc reload *
     Then set RNDC_BIN="sudo rndc"

EXAMPLES:
  # First-time setup
  RPZ_DIR=/opt/rpz-zone-factory ./run-rpz.sh --setup

  # Interactive test run
  ./run-rpz.sh -i -- --output rpz --zone-name block.rpz --output-file /tmp/test.rpz.db -v

  # Cron entry (RPZ for BIND, reload after):
  15 */4 * * * /usr/local/sbin/run-rpz.sh --reload-bind block.rpz -- --output rpz --zone-name block.rpz --output-file /etc/namedb/rpz/block.rpz.db

  # Cron entry (Pi-hole flat file, no reload):
  30 3 * * * /usr/local/sbin/run-rpz.sh -- --output pihole --output-file /etc/pihole/custom.list

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
                MODE="interactive"  # setup is always interactive
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

VENV_DIR=""  # set after RPZ_DIR is finalized

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

    # Verify pip is available inside the venv
    if ! "$_venv_py" -m pip --version >/dev/null 2>&1; then
        log_warn "Venv exists but pip is not available inside it"
        log_warn "On FreeBSD, you may need to install py39-pip (or equivalent) system-wide first"
        return 1
    fi

    # Verify requirements are installed
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

    # Check that venv module is available
    if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
        log_err "Python venv module is not available"
        log_err "Install it:"
        log_err "  Debian/Ubuntu: apt install python3-venv"
        log_err "  FreeBSD:       pkg install py39-venv (adjust version)"
        return 1
    fi

    # Create the venv
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
        log_err "Failed to create virtual environment"
        return 1
    fi

    log_info "Virtual environment created"

    # Check pip is available
    _venv_py="${VENV_DIR}/bin/python"
    if ! "$_venv_py" -m pip --version >/dev/null 2>&1; then
        log_err "pip is not available in the new virtual environment"
        log_err "This commonly happens on FreeBSD where pip is a separate package."
        log_err "Fix:"
        log_err "  FreeBSD: pkg install py39-pip (adjust for your Python version)"
        log_err "  Debian/Ubuntu: apt install python3-pip"
        log_err "Then re-run: $0 --setup"
        # Clean up broken venv
        rm -rf "$VENV_DIR"
        return 1
    fi

    # Upgrade pip (suppress output in cron mode)
    log_info "Upgrading pip..."
    if [ "$MODE" = "interactive" ]; then
        "$_venv_py" -m pip install --upgrade pip
    else
        "$_venv_py" -m pip install --upgrade pip >/dev/null 2>&1
    fi

    # Install requirements
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

    # Verify
    if ! "$_venv_py" -c "import requests" >/dev/null 2>&1; then
        log_err "Dependencies installed but import check failed"
        return 1
    fi

    log_info "Dependencies installed successfully"
    return 0
}

# ─── Setup mode ───────────────────────────────────────────────────────────────

run_setup() {
    log_notice "=== rpz-zone-factory setup ==="

    # Validate RPZ_DIR
    if [ ! -d "$RPZ_DIR" ]; then
        log_err "RPZ_DIR does not exist: $RPZ_DIR"
        log_err "Clone the repository first, then set RPZ_DIR."
        return 1
    fi

    if [ ! -f "${RPZ_DIR}/run.py" ]; then
        log_err "run.py not found in RPZ_DIR: $RPZ_DIR"
        log_err "This doesn't look like the rpz-zone-factory project directory."
        return 1
    fi

    # Check Python
    if ! check_python_version "$PYTHON_BIN"; then
        return 1
    fi

    # Create or verify venv
    if check_venv; then
        log_notice "Existing venv is healthy. Nothing to do."
        log_notice "To force recreation, remove ${VENV_DIR} and re-run --setup."
    else
        if ! create_venv; then
            log_err "Setup failed."
            return 1
        fi
    fi

    # Test run
    log_notice "Running quick test (--help)..."
    _venv_py="${RPZ_DIR}/${VENV_NAME}/bin/python"
    if "$_venv_py" "${RPZ_DIR}/run.py" --help >/dev/null 2>&1; then
        log_notice "rpz-zone-factory responds to --help. Setup complete."
    else
        log_err "rpz-zone-factory failed to respond to --help"
        return 1
    fi

    log_notice ""
    log_notice "=== Setup complete ==="
    log_notice ""
    log_notice "Test interactively:"
    log_notice "  $0 -i -- --output rpz --zone-name block.rpz -v"
    log_notice ""
    log_notice "Add to cron (example, every 4 hours):"
    log_notice "  15 */4 * * * RPZ_DIR=${RPZ_DIR} $0 -- --output rpz --zone-name block.rpz --output-file /path/to/block.rpz.db"
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

    # Execute rpz-zone-factory
    # In cron mode, capture stderr for logging; stdout goes to output-file via rpz args.
    # In interactive mode, let everything flow naturally.
    if [ "$MODE" = "interactive" ]; then
        eval "\"$_venv_py\" \"$_run_py\" $RPZ_ARGS"
        EXIT_CODE=$?
    else
        _stderr_tmp=$(mktemp /tmp/rpz-run.XXXXXX 2>/dev/null || echo "/tmp/rpz-run.$$")
        eval "\"$_venv_py\" \"$_run_py\" $RPZ_ARGS" 2>"$_stderr_tmp"
        EXIT_CODE=$?

        # Log stderr output line by line
        if [ -s "$_stderr_tmp" ]; then
            while IFS= read -r _line; do
                # Skip blank lines
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
        # Try common locations
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
