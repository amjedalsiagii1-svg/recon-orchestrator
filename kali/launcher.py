"""Kali Edition launcher - installs patch then runs CLI"""
import sys
import os

_here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _here not in sys.path:
    sys.path.insert(0, _here)

os.environ.setdefault("RECON_ENV", "kali")
os.environ.setdefault("RECON_CONFIG_DIR", os.path.join(_here, "kali", "config"))

try:
    from kali.extended_info import install
    if install():
        print("\033[92m✅ Kali Edition: 25 network types loaded\033[0m")
except Exception:
    pass

from ui.cli import main
sys.exit(main())
