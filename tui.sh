#!/bin/bash
cd "$(dirname "$0")"

# Debug log
LAUNCH_LOG="/tmp/tui_launch.log"
: > "$LAUNCH_LOG"
echo "=== TUI LAUNCH $(date) ===" >> "$LAUNCH_LOG"
echo "PWD: $(pwd)" >> "$LAUNCH_LOG"
echo "TERM: ${TERM:-unset}" >> "$LAUNCH_LOG"
echo "USER: $(whoami)" >> "$LAUNCH_LOG"
echo "TTY: $(test -t 1 && echo yes || echo no)" >> "$LAUNCH_LOG"

# Activate venv
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "VENV python: $(which python3)" >> "$LAUNCH_LOG"
fi

# Env vars
export RECON_ENV="${RECON_ENV:-kali}"
export RECON_CONFIG_DIR="kali/config"
export RECON_PLUGINS_DIR="kali/plugins"

# TTY check (fail fast with clear message)
if [ ! -t 1 ]; then
    echo "ERROR: TUI requires an interactive terminal (stdout is not a TTY)" | tee -a "$LAUNCH_LOG"
    exit 1
fi

# Run as current user (NO sudo - phases handle sudo internally)
python3 -m ui.tui.app 2>>"$LAUNCH_LOG"
EXIT_CODE=$?
echo "=== TUI EXIT code=$EXIT_CODE $(date) ===" >> "$LAUNCH_LOG"
exit $EXIT_CODE
