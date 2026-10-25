"""Plugin loader — discovers and loads YAML plugins.

Structure:
  plugins/cves/*.yaml     → CVE + exploit metadata
  plugins/profiles/*.yaml → scan profiles (future)
  plugins/probes/*.py     → custom protocols (future)
  plugins/reports/*.py    → custom outputs (future)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CVES_DIR = _PROJECT_ROOT / "plugins" / "cves"
_PROFILES_DIR = _PROJECT_ROOT / "plugins" / "profiles"


# Required fields per CVE YAML
_REQUIRED_FIELDS = ("cve", "cvss", "description", "impact", "remediation")
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


# ============================================================
# Validation
# ============================================================
class PluginError(Exception):
    """Raised when a plugin file is invalid."""


def validate_cve(data: dict, path: Path) -> None:
    """Validate required fields and basic format."""
    if not isinstance(data, dict):
        raise PluginError(f"{path.name}: not a dict")
    for field in _REQUIRED_FIELDS:
        if field not in data:
            raise PluginError(f"{path.name}: missing field '{field}'")
    cve = data["cve"]
    if not _CVE_ID_RE.match(cve):
        raise PluginError(f"{path.name}: invalid CVE id '{cve}'")
    if not isinstance(data["cvss"], (int, float)):
        raise PluginError(f"{path.name}: cvss must be numeric")
    if not (0.0 <= float(data["cvss"]) <= 10.0):
        raise PluginError(f"{path.name}: cvss out of range")

    # Exploit section (optional) — validate if present
    ex = data.get("exploit")
    if ex is not None:
        if not isinstance(ex, dict):
            raise PluginError(f"{path.name}: exploit must be a dict")
        if "module" not in ex or "tool" not in ex:
            raise PluginError(f"{path.name}: exploit needs 'module' + 'tool'")


# ============================================================
# Discovery & loading
# ============================================================
def discover_cve_files() -> list[Path]:
    """Return sorted list of CVE yaml files."""
    if not _CVES_DIR.exists():
        return []
    return sorted(_CVES_DIR.glob("CVE-*.yaml"))


def load_cve_file(path: Path) -> dict:
    """Load and validate one CVE yaml file."""
    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise PluginError(f"{path.name}: yaml error — {e}") from e
    if data is None:
        raise PluginError(f"{path.name}: empty file")
    validate_cve(data, path)
    return data


def load_all_cves(strict: bool = False) -> list[dict]:
    """Load all CVE files. Returns list of validated dicts.

    strict=False: skip invalid files with warning (safe)
    strict=True:  raise on first error (for CI/tests)
    """
    out: list[dict] = []
    for path in discover_cve_files():
        try:
            out.append(load_cve_file(path))
        except PluginError as e:
            if strict:
                raise
            print(f"[!] plugin skipped: {e}")
    return out


# ============================================================
# Builders — transform plugin data into runtime dicts
# ============================================================
def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"


def build_vuln_db(cves: list[dict]) -> dict[str, list[dict]]:
    """Build VULN_DB: {product: [cve_entry, ...]} — scannable CVEs only."""
    db: dict[str, list[dict]] = {}
    for data in cves:
        product = data.get("product")
        if not product:
            continue  # reference-only CVE (no version range)
        product_lower = product.lower()
        entry = {
            "id": data["cve"],
            "cvss": float(data["cvss"]),
            "min": str(data.get("version_min", "0.0")),
            "max": str(data.get("version_max", "999.0")),
            "desc": data["description"],
            "impact": data["impact"],
            "famous": bool(data.get("famous", False)),
            "remediation": data["remediation"],
        }
        db.setdefault(product_lower, []).append(entry)
    return db


def build_exploit_db(cves: list[dict]) -> dict[str, dict]:
    """Build EXPLOIT_DB: {cve_id: exploit_dict} — CVEs with exploit section."""
    db: dict[str, dict] = {}
    for data in cves:
        exploit = data.get("exploit")
        if not exploit:
            continue
        db[data["cve"]] = exploit
    return db


def build_cve_catalog(cves: list[dict]) -> list[dict]:
    """Build reference catalog for the report."""
    out: list[dict] = []
    for data in cves:
        exploit = data.get("exploit") or {}
        ag = exploit.get("access_gained") or {}
        out.append({
            "cve": data["cve"],
            "product": data.get("product") or "—",
            "cvss": float(data["cvss"]),
            "severity": data.get("severity") or _severity_from_cvss(float(data["cvss"])),
            "module": exploit.get("module", "—"),
            "tool": exploit.get("tool", "—"),
            "level": ag.get("level", "unknown"),
            "impact": data["impact"],
            "risk": exploit.get("risk_note", "—"),
            "skill": exploit.get("skill_required", "unknown"),
            "methods_count": len(exploit.get("methods", [])),
            "famous": bool(data.get("famous", False)),
        })
    order = {"root": 0, "system": 0, "admin": 1, "user": 2,
             "www-data": 2, "info": 3, "none": 4}
    return sorted(out, key=lambda x: (order.get(x["level"], 9), x["cve"]))


# ============================================================
# Profile loading (for future use)
# ============================================================
def discover_profile_files() -> list[Path]:
    if not _PROFILES_DIR.exists():
        return []
    return sorted(_PROFILES_DIR.glob("*.yaml"))


def load_all_profiles() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in discover_profile_files():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "name" in data:
                out[data["name"]] = data
        except Exception as e:
            print(f"[!] profile skipped: {path.name}: {e}")
    return out
