#!/bin/bash
cd "$(dirname "$0")"

echo "===================================="
echo "1) Kali Linux (Root / Advanced)"
echo "2) Termux (Android / No Root)"
echo "===================================="
read -p "Choice [1-2]: " env_choice

if [ "$env_choice" == "2" ]; then
    export RECON_ENV="termux"
    if [ -d "venv" ]; then source venv/bin/activate; fi
    python3 -m ui.cli "$@"
else
    export RECON_ENV="kali"
    sudo -E env PATH="$PATH" venv/bin/python3 -m ui.cli "$@"
fi
