#!/usr/bin/env bash
# Smoke test wrapper — runs the full pipeline against 127.0.0.1
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
cd "$ROOT"
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"
exec python3 scripts/smoke.py "$@"
