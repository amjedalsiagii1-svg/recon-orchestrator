"""Capabilities detection — what works in the current environment.

Determines which scan types, tools, and features are available.
Used by scan profiles to pick optimal flags automatically.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from core import platform as platform_mod


_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _has_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _has_sudo_bin() -> bool:
    return _has_cmd("sudo") or _has_cmd("tsu") or _has_cmd("doas")


def _can_sudo_noprompt() -> bool:
    """Check if sudo works without password (NOPASSWD)."""
    if not _has_cmd("sudo"):
        return False
    try:
        r = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True, timeout=2,
        )
        return r.returncode == 0
    except Exception:
        return False


@dataclass
class Capabilities:
    """Detected capabilities of the current environment."""
    platform: str = "unknown"

    # Privileges
    root: bool = False
    sudo: bool = False
    can_elevate: bool = False

    # Scan types (require raw sockets = root/sudo)
    syn_scan: bool = False
    udp_scan: bool = False
    os_detection: bool = False
    arp_scan: bool = False
    packet_capture: bool = False

    # Tools
    nmap: bool = False
    nuclei: bool = False
    searchsploit: bool = False
    msfconsole: bool = False
    masscan: bool = False
    arp_scan_bin: bool = False

    # Interfaces
    cli: bool = True
    web: bool = True
    textual_tui: bool = False
    pdf: bool = False

    @property
    def total_count(self) -> int:
        return 12

    @property
    def available_count(self) -> int:
        items = [
            self.syn_scan, self.udp_scan, self.os_detection, self.arp_scan,
            self.packet_capture, self.nuclei, self.searchsploit,
            self.msfconsole, self.textual_tui, self.pdf,
            self.web, self.cli,
        ]
        return sum(1 for x in items if x)

    @property
    def summary_short(self) -> str:
        missing = self.missing_features()
        if not missing:
            return "100% (all features available)"
        return f"{self.available_count}/{self.total_count} ({len(missing)} locked)"

    def missing_features(self) -> list[str]:
        """Return list of unavailable features (consistent with available_count)."""
        all_features = [
            ("syn_scan", self.syn_scan),
            ("udp_scan", self.udp_scan),
            ("os_detection", self.os_detection),
            ("arp_scan", self.arp_scan),
            ("packet_capture", self.packet_capture),
            ("nuclei", self.nuclei),
            ("searchsploit", self.searchsploit),
            ("msfconsole", self.msfconsole),
            ("textual_tui", self.textual_tui),
            ("pdf", self.pdf),
            ("web", self.web),
            ("cli", self.cli),
        ]
        return [name for name, ok in all_features if not ok]

    def has_scan_type(self, kind: str) -> bool:
        """Check if a specific scan type is available."""
        return {
            "syn": self.syn_scan,
            "udp": self.udp_scan,
            "os": self.os_detection,
            "arp": self.arp_scan,
        }.get(kind.lower(), False)



def _find_nuclei() -> str | None:
    """Return nuclei binary path or None."""
    candidates = []
    p = shutil.which("nuclei")
    if p:
        candidates.append(p)
    local = _PROJECT_ROOT / "tools" / "bin" / "nuclei"
    if local.exists():
        candidates.append(str(local))
    return candidates[0] if candidates else None


def _nuclei_works() -> bool:
    """Verify nuclei actually runs (not just exists)."""
    path = _find_nuclei()
    if not path:
        return False
    try:
        r = subprocess.run(
            [path, "-version"],
            capture_output=True, text=True, timeout=5,
        )
        out = (r.stdout + r.stderr).lower()
        return "nuclei" in out or r.returncode == 0
    except Exception:
        return False


def detect(platform: platform_mod.PlatformInfo | None = None) -> Capabilities:
    """Detect all capabilities."""
    if platform is None:
        platform = platform_mod.get()

    root = _is_root()
    has_sudo = _has_sudo_bin()
    can_elevate = root or _can_sudo_noprompt()

    # Tool detection
    has_nmap = _has_cmd("nmap")
    has_nuclei = _nuclei_works()
    has_searchsploit = _has_cmd("searchsploit")
    has_msf = _has_cmd("msfconsole")
    has_masscan = _has_cmd("masscan")
    has_arp = _has_cmd("arp-scan")
    has_tcpdump = _has_cmd("tcpdump")

    # WeasyPrint (PDF)
    has_pdf = False
    try:
        import weasyprint  # noqa: F401
        has_pdf = True
    except ImportError:
        pass

    # Textual TUI works reliably on Kali (konsole/kitty BiDi support)
    has_tui = platform.is_kali

    return Capabilities(
        platform=platform.name,
        root=root,
        sudo=has_sudo,
        can_elevate=can_elevate,
        syn_scan=can_elevate and has_nmap,
        udp_scan=can_elevate and has_nmap,
        os_detection=can_elevate and has_nmap,
        arp_scan=can_elevate and has_arp,
        packet_capture=can_elevate and has_tcpdump,
        nmap=has_nmap,
        nuclei=has_nuclei,
        searchsploit=has_searchsploit,
        msfconsole=has_msf,
        masscan=has_masscan,
        arp_scan_bin=has_arp,
        textual_tui=has_tui,
        pdf=has_pdf,
    )


_cached: Capabilities | None = None


def get() -> Capabilities:
    """Return cached capabilities."""
    global _cached
    if _cached is None:
        _cached = detect()
    return _cached


def reset_cache() -> None:
    global _cached
    _cached = None
