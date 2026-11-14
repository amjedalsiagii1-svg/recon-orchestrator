"""Kali Edition Launcher - Orchestrator"""
import sys
import os

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

os.environ.setdefault("RECON_ENV", "kali")
os.environ.setdefault("RECON_CONFIG_DIR", os.path.join(_here, "config"))
os.environ.setdefault("RECON_PLUGINS_DIR", os.path.join(_here, "plugins"))

from kali.hooks import (
    install_network_hook,
    install_playbook_hook,
    install_webscan_hook,
    install_phase8_hook,
)

_hooks = []

if install_network_hook():
    _hooks.append("extended-info")
if install_webscan_hook():
    _hooks.append("webscan-suggest")
if install_playbook_hook():
    _hooks.append("playbook+enricher")
if install_phase8_hook():
    _hooks.append("phase8-web")

if _hooks:
    print(f"\033[92m[OK] Kali Edition hooks: {', '.join(_hooks)}\033[0m")

from ui.cli import main
sys.exit(main())
