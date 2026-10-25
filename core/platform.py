"""Platform detection — Termux / Kali / Debian / unknown."""
from __future__ import annotations

import os
import platform as _py_platform
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PlatformInfo:
    """Detected platform information."""
    name: str                    # "termux" | "kali" | "debian" | "unknown"
    python_version: str
    os_name: str                 # "Android" | "Kali" | "Linux"
    os_version: str              # "14" | "2024.1"
    kernel: str
    arch: str
    is_termux: bool = False
    is_kali: bool = False
    is_debian_based: bool = False

    @property
    def label(self) -> str:
        if self.is_termux:
            return f"Termux (Android {self.os_version})"
        if self.is_kali:
            return f"Kali Linux {self.os_version}"
        return f"{self.os_name} {self.os_version}".strip()


def _read_os_release() -> dict[str, str]:
    """Parse /etc/os-release (Debian/Kali)."""
    p = Path("/etc/os-release")
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return out


def _detect_termux() -> bool:
    """Check if running under Termux."""
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        return True
    if Path("/data/data/com.termux/files/usr").exists():
        return True
    return False


def _detect_kali(os_rel: dict[str, str]) -> bool:
    """Check if running under Kali Linux."""
    if os_rel.get("ID", "").lower() == "kali":
        return True
    if "kali" in os_rel.get("ID_LIKE", "").lower():
        return True
    return False


def _android_version() -> str:
    """Get Android release version via getprop."""
    try:
        r = subprocess.run(
            ["getprop", "ro.build.version.release"],
            capture_output=True, text=True, timeout=2,
        )
        return r.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _kali_version(os_rel: dict[str, str]) -> str:
    return (
        os_rel.get("VERSION_ID", "")
        or os_rel.get("VERSION", "")
        or "unknown"
    )


def detect() -> PlatformInfo:
    """Detect the current platform."""
    os_rel = _read_os_release()
    is_termux = _detect_termux()
    is_kali = _detect_kali(os_rel)
    is_debian = (
        os_rel.get("ID", "").lower() in ("debian", "ubuntu", "linuxmint")
        or "debian" in os_rel.get("ID_LIKE", "").lower()
    )

    if is_termux:
        name, os_name, os_version = "termux", "Android", _android_version()
    elif is_kali:
        name, os_name, os_version = "kali", "Kali", _kali_version(os_rel)
    elif is_debian:
        name = "debian"
        os_name = os_rel.get("NAME", "Debian")
        os_version = os_rel.get("VERSION_ID", "unknown")
    else:
        name = "unknown"
        os_name = _py_platform.system()
        os_version = _py_platform.release()

    return PlatformInfo(
        name=name,
        python_version=_py_platform.python_version(),
        os_name=os_name,
        os_version=os_version,
        kernel=_py_platform.release(),
        arch=_py_platform.machine(),
        is_termux=is_termux,
        is_kali=is_kali,
        is_debian_based=is_debian or is_kali,
    )


_cached: PlatformInfo | None = None


def get() -> PlatformInfo:
    """Return cached platform info (detect once)."""
    global _cached
    if _cached is None:
        _cached = detect()
    return _cached


def reset_cache() -> None:
    """Clear cache (testing helper)."""
    global _cached
    _cached = None
