"""Built-in CVE fingerprints for known vulnerable product versions.

Offline — works on Termux without any network or searchsploit.
Every entry has: id (CVE), affected range, cvss, desc, impact, remediation,
famous flag (widely exploited in the wild).
"""
from __future__ import annotations

import re
from typing import Any


# Loaded from plugins/cves/*.yaml
from core.plugin_loader import load_all_cves, build_vuln_db

try:
    _ALL_CVES = load_all_cves(strict=False)
    VULN_DB: dict[str, list[dict[str, Any]]] = build_vuln_db(_ALL_CVES)
except Exception as e:
    print(f"[!] vuln_db: plugin load failed ({e}) — using empty DB")
    _ALL_CVES = []
    VULN_DB = {}


def _parse_version(v: str | None) -> tuple[int, ...]:
    if not v:
        return ()
    parts = re.findall(r"\d+", str(v))
    return tuple(int(p) for p in parts)


def _version_in_range(version: str | None, min_v: str, max_v: str) -> bool:
    if not version:
        return False
    v = _parse_version(version)
    if not v:
        return False
    mn = _parse_version(min_v)
    mx = _parse_version(max_v)
    if mn and v < mn:
        return False
    if mx and v > mx:
        return False
    return True


def _normalize(text: str | None) -> str:
    if not text:
        return ""
    return text.lower().replace("_", " ").replace("-", " ").strip()


def lookup(product: str | None, version: str | None) -> list[dict[str, Any]]:
    """Return matching CVEs for a product+version pair."""
    if not product:
        return []
    p = _normalize(product)
    matches: list[dict[str, Any]] = []

    # Try exact key, then substring key
    candidate_keys = []
    if p in VULN_DB:
        candidate_keys.append(p)
    else:
        for key in VULN_DB:
            if key in p or p in key:
                candidate_keys.append(key)

    for key in candidate_keys:
        for entry in VULN_DB[key]:
            if _version_in_range(version, entry["min"], entry["max"]):
                matches.append({
                    "id": entry["id"],
                    "cvss": entry["cvss"],
                    "desc": entry["desc"],
                    "impact": entry["impact"],
                    "remediation": entry["remediation"],
                    "famous": entry["famous"],
                    "matched_product": product,
                    "matched_version": version or "unknown",
                })
    return matches


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"
