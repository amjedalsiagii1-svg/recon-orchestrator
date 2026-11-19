"""Read-only local diagnostics for the SF desktop shell.

This module intentionally performs no network discovery, port checks, packet
capture, privilege escalation, or external command execution.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOL_NAMES = ("nmap", "nuclei", "arp-scan", "tcpdump", "searchsploit")


@dataclass(frozen=True)
class ScopeEntry:
    value: str
    kind: str
    valid: bool
    message: str


@dataclass(frozen=True)
class EnvironmentSnapshot:
    operating_system: str
    distribution: str
    distribution_version: str
    python_version: str
    architecture: str
    is_root: bool
    tools: dict[str, bool]


def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Parse the standard os-release file as plain text; never execute it."""
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return result

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'") and len(value) >= 2:
            value = value[1:-1]
        if key and re.fullmatch(r"[A-Z0-9_]+", key):
            result[key] = value
    return result


def detect_environment() -> EnvironmentSnapshot:
    """Return local system facts using read-only Python APIs."""
    release = _read_os_release()
    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        is_root = False

    return EnvironmentSnapshot(
        operating_system=platform.system() or "غير معروف",
        distribution=release.get("PRETTY_NAME") or release.get("NAME") or platform.system(),
        distribution_version=release.get("VERSION_ID", "غير معروف"),
        python_version=platform.python_version(),
        architecture=platform.machine() or "غير معروف",
        is_root=is_root,
        tools={name: shutil.which(name) is not None for name in TOOL_NAMES},
    )


def parse_scope_lines(lines: list[str]) -> tuple[list[ScopeEntry], int]:
    """Validate configured IP/CIDR/hostname entries without contacting them."""
    import ipaddress

    entries: list[ScopeEntry] = []
    ignored = 0
    hostname_re = re.compile(
        r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
    )

    for raw in lines:
        value = raw.strip()
        if not value or value.startswith("#"):
            ignored += 1
            continue
        try:
            if "/" in value:
                ipaddress.ip_network(value, strict=False)
                entries.append(ScopeEntry(value, "CIDR", True, "صيغة شبكة صحيحة"))
            else:
                ipaddress.ip_address(value)
                entries.append(ScopeEntry(value, "IP", True, "عنوان صحيح"))
        except ValueError:
            if hostname_re.fullmatch(value):
                entries.append(ScopeEntry(value, "اسم مضيف", True, "اسم مضيف بصيغة صحيحة"))
            else:
                entries.append(ScopeEntry(value, "غير معروف", False, "صيغة غير صالحة"))
    return entries, ignored


def read_scope_file(path: Path | None = None) -> tuple[list[ScopeEntry], str | None]:
    """Read the configured scope file; never resolve or contact its entries."""
    scope_path = path or (PROJECT_ROOT / "config" / "scope.txt")
    try:
        lines = scope_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return [], str(exc)
    entries, _ignored = parse_scope_lines(lines)
    return entries, None


def list_html_reports(directory: Path | None = None) -> list[Path]:
    """List regular HTML report files only; do not parse or execute their content."""
    output_dir = directory or (PROJECT_ROOT / "reports" / "output")
    try:
        return sorted(
            (item for item in output_dir.iterdir()
             if item.is_file() and not item.is_symlink() and item.suffix.lower() == ".html"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return []
