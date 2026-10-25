"""Phase 5 — Vulnerability scan: offline vuln_db + optional nuclei + banner grab."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any

import httpx

from core.scope import Scope
from core.vuln_db import lookup as db_lookup, severity_from_cvss
from integrations.nuclei_runner import find_nuclei, run_web_scan
from core.cred_tester import test_default_creds
from core.dir_bruteforce import brute_force
from core.sensitive_files import classify as classify_path


HTTP_PORTS = (80, 443, 8080, 8443, 8000, 8888)
HTTPS_PORTS = (443, 8443)


@dataclass
class Vuln:
    id: str
    severity: str
    source: str           # "vuln_db" | "banner" | "nuclei"
    port: int | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cvss: float | None = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    famous: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VulnScanResult:
    target: str
    duration_seconds: float
    vulns: list[Vuln] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "duration_seconds": self.duration_seconds,
            "vulns": [v.to_dict() for v in self.vulns],
            "sources_used": self.sources_used,
            "warnings": self.warnings,
            "error": self.error,
        }

    def severity_summary(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in self.vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts


def _match_ports_via_db(ports: list[dict[str, Any]]) -> list[Vuln]:
    """Layer 1: match nmap-detected products/versions against VULN_DB."""
    found: list[Vuln] = []
    for p in ports:
        product = p.get("product")
        version = p.get("version")
        if not product:
            continue
        for match in db_lookup(product, version):
            found.append(Vuln(
                id=match["id"],
                severity=severity_from_cvss(match["cvss"]),
                source="vuln_db",
                port=p.get("port"),
                service=p.get("service"),
                product=product,
                version=version,
                cvss=match["cvss"],
                description=match["desc"],
                impact=match["impact"],
                remediation=match["remediation"],
                famous=match["famous"],
            ))
    return found


async def _grab_banner(
    target: str, port: int, timeout: float = 3.0
) -> dict[str, Any] | None:
    """Layer 2: grab Server header + version hints from HTTP services."""
    scheme = "https" if port in HTTPS_PORTS else "http"
    url = f"{scheme}://{target}:{port}/"
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=False
        ) as c:
            r = await c.get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}
            return {
                "url": url,
                "status": r.status_code,
                "server": headers.get("server"),
                "x_powered_by": headers.get("x-powered-by"),
                "auth_realm": headers.get("www-authenticate"),
            }
    except Exception:
        return None


async def _run_nuclei_for_http(
    target: str, ports: list[dict[str, Any]], timeout: int = 180
) -> tuple[list[Vuln], str | None]:
    """Layer 3: run nuclei against each detected HTTP/HTTPS port."""
    binary = await find_nuclei()
    if not binary:
        return [], "nuclei not installed"

    vulns: list[Vuln] = []
    last_err: str | None = None
    for p in ports:
        port = p.get("port")
        if port not in HTTP_PORTS:
            continue
        scheme = "https" if port in HTTPS_PORTS else "http"
        url = f"{scheme}://{target}:{port}"
        findings, err = await run_web_scan(url, timeout=timeout)
        if err and not findings:
            last_err = err
            continue
        for f in findings:
            vulns.append(Vuln(
                id=f["template_id"],
                severity=f.get("severity", "info"),
                source="nuclei",
                port=port,
                service=p.get("service"),
                description=f.get("name") or f.get("description", ""),
                impact="See template reference",
                remediation="See template reference",
                raw=f,
            ))
    return vulns, last_err


def _dedup(vulns: list[Vuln]) -> list[Vuln]:
    seen: set[tuple] = set()
    out: list[Vuln] = []
    for v in vulns:
        key = (v.id, v.port)
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    out.sort(key=lambda v: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(v.severity, 5),
        -(v.cvss or 0),
        v.id,
    ))
    return out




async def _run_deep_web_checks(
    target: str, http_ports: list[dict[str, Any]], timeout: int = 30,
) -> tuple[list[Vuln], list[str]]:
    """New in v0.7: default creds + directory brute + sensitive files."""
    vulns: list[Vuln] = []
    warnings: list[str] = []

    for p in http_ports:
        port = p.get("port")
        if not port:
            continue

        # ── Default creds test (safe: Basic Auth only) ──
        try:
            cred_result = await test_default_creds(target, port, timeout=3.0)
            if cred_result.testable and cred_result.matched:
                user, pwd = cred_result.matched
                vulns.append(Vuln(
                    id=f"DEFAULT-CRED-{port}",
                    severity="critical",
                    source="cred_test",
                    port=port,
                    service=p.get("service"),
                    description=(
                        f"Default credentials accepted: {user}:{pwd} "
                        f"on http://{target}:{port}{cred_result.url.split(str(port))[-1]}"
                    ),
                    impact="Full administrative access with default creds",
                    remediation=(
                        "Change the default password immediately. "
                        "Enforce strong password policy. Disable unused admin accounts."
                    ),
                ))
            elif cred_result.testable:
                # Auth required but no default creds worked → info
                vulns.append(Vuln(
                    id=f"BASIC-AUTH-{port}",
                    severity="info",
                    source="cred_test",
                    port=port,
                    service=p.get("service"),
                    description=(
                        f"HTTP Basic Auth detected (realm: {cred_result.auth_realm or '?'}). "
                        f"Tested {cred_result.attempts} default creds — none matched."
                    ),
                    impact="Auth present but proper",
                    remediation="Ensure strong password policy.",
                ))
        except Exception as e:
            warnings.append(f"cred test on {port}: {e}")

        # ── Directory brute-force ──
        try:
            hits = await brute_force(target, port, timeout=3.0)
            for hit in hits:
                base_url = f"http://{target}:{port}"
                classified = classify_path(hit, base_url)
                if not classified:
                    continue
                vulns.append(Vuln(
                    id=classified["id"],
                    severity=classified["severity"],
                    source="dir_bruteforce",
                    port=port,
                    service=p.get("service"),
                    description=f"{classified['title']} — {classified['url']}",
                    impact=classified["description"],
                    remediation=classified["remediation"],
                ))
        except Exception as e:
            warnings.append(f"dirbrute on {port}: {e}")

    return vulns, warnings


async def scan(
    target: str,
    ports: list[dict[str, Any]],
    scope: Scope | None = None,
    run_nuclei: bool = True,
    timeout: int = 300,
) -> VulnScanResult:
    """Run Phase 5 vuln scan against the ports discovered in Phase 4."""
    start = time.monotonic()
    if scope is not None:
        scope.require_allowed(target)

    warnings: list[str] = []
    sources: list[str] = []
    all_vulns: list[Vuln] = []

    # Layer 1 — vuln_db
    db_vulns = _match_ports_via_db(ports)
    if db_vulns:
        sources.append("vuln_db")
    all_vulns.extend(db_vulns)

    # Layer 2 — banner grab (informational + may enable nuclei targeting)
    banners: list[dict[str, Any]] = []
    http_ports = [p for p in ports if p.get("port") in HTTP_PORTS]
    if http_ports:
        for p in http_ports:
            b = await _grab_banner(target, p["port"])
            if b:
                banners.append(b)
                # If banner reveals a version we didn't have, try DB again
                if b.get("server"):
                    srv = b["server"].split("/")
                    if len(srv) == 2:
                        for match in db_lookup(srv[0], srv[1]):
                            all_vulns.append(Vuln(
                                id=match["id"],
                                severity=severity_from_cvss(match["cvss"]),
                                source="banner",
                                port=p["port"],
                                service=p.get("service"),
                                product=srv[0],
                                version=srv[1],
                                cvss=match["cvss"],
                                description=match["desc"],
                                impact=match["impact"],
                                remediation=match["remediation"],
                                famous=match["famous"],
                            ))
        if banners:
            sources.append("banner")

    # Layer 3 — nuclei (optional)
    if run_nuclei and http_ports:
        nuclei_vulns, n_err = await _run_nuclei_for_http(target, ports, timeout=timeout)
        if nuclei_vulns:
            all_vulns.extend(nuclei_vulns)
            sources.append("nuclei")
        elif n_err:
            warnings.append(f"nuclei: {n_err}")

    # Layer 4 (v0.7) — deep web checks: creds + dirbrute + sensitive files
    deep_vulns: list[Vuln] = []
    if http_ports:
        try:
            deep_vulns, deep_warnings = await _run_deep_web_checks(
                target, http_ports, timeout=60,
            )
            warnings.extend(deep_warnings)
            if deep_vulns:
                all_vulns.extend(deep_vulns)
                sources.append("web_deep")
        except Exception as e:
            warnings.append(f"deep web checks failed: {e}")

    vulns = _dedup(all_vulns)
    if not sources:
        warnings.append("No scan sources produced findings")

    return VulnScanResult(
        target=target,
        duration_seconds=round(time.monotonic() - start, 2),
        vulns=vulns,
        sources_used=sources,
        warnings=warnings,
    )
