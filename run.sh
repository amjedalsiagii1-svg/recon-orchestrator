#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"
PYTHON="${PYTHON:-python3}"
export PYTHONPATH="$SCRIPT_DIR:${PYTHONPATH:-}"

[[ -f config/scope.txt ]] || { echo "Error: config/scope.txt missing. Run 'bash install.sh' first." >&2; exit 1; }
command -v "$PYTHON" &>/dev/null || { echo "Error: $PYTHON not found." >&2; exit 1; }

# Platform detection
PLATFORM="unknown"
if [[ -n "${PREFIX:-}" && "$PREFIX" == *"com.termux"* ]]; then
  PLATFORM="termux"
elif [[ -f /etc/os-release ]] && grep -qi '^ID=kali' /etc/os-release 2>/dev/null; then
  PLATFORM="kali"
fi

MODE=""
DEMO=""
RESUME=""
for arg in "$@"; do
  case "$arg" in
    --platform)
      exec "${PYTHON:-python3}" -c "from core import platform; print(platform.get().label)"
      ;;
    --capabilities)
      exec "${PYTHON:-python3}" -c "from core import platform, capabilities; p=platform.get(); c=capabilities.get(); print(f'Platform: {p.label}'); print(f'Capabilities: {c.available_count}/{c.total_count}'); print(f'Missing: {chr(44).join(c.missing_features()) or chr(110)+chr(111)+chr(110)+chr(101)}')"
      ;;
    --demo)      DEMO="--demo" ;;
    --resume)
      MODE="cli"
      if [[ -z "${2:-}" ]]; then
        echo "Error: --resume needs a SESSION_ID" >&2
        exit 1
      fi
      RESUME="--resume $2"
      shift ;;
    --cli)       MODE="cli" ;;
    --tui)       MODE="tui" ;;
    --help|-h)
      cat <<EOF
recon-orchestrator launcher

Usage:
  bash run.sh              Auto: CLI on Termux, TUI on Kali
  bash run.sh --demo       Demo mode
  bash run.sh --cli        Force CLI (Rich)
  bash run.sh --tui        Force Textual TUI
EOF
      exit 0 ;;
  esac
done

# Default mode
if [[ -z "$MODE" ]]; then
  if [[ "$PLATFORM" == "termux" ]]; then MODE="cli"; else MODE="tui"; fi
fi

if [[ "$MODE" == "cli" ]]; then
  exec "$PYTHON" -m ui.cli $DEMO $RESUME
else
  exec "$PYTHON" -m ui.app $DEMO
fi
