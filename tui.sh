#!/bin/bash
cd "$(dirname "$0")"
if [ -d "venv" ]; then source venv/bin/activate; fi
export RECON_ENV="${RECON_ENV:-kali}"
export RECON_CONFIG_DIR="kali/config"
export RECON_PLUGINS_DIR="kali/plugins"
sudo -E env PATH="$PATH" RECON_ENV="kali" RECON_CONFIG_DIR="kali/config" \
    python3 -m ui.tui.app "$@"
