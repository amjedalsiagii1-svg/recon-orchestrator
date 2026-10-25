"""Phase 4 — Port scan with auto-interpretation."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any

from core.port_db import enrich as enrich_port
from core.service_probes import probe_ports_parallel
from core.privilege import detect as detect_priv
from core.scope import Scope
from integrations.nmap_runner import scan_ports_xml


PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "args": ["-sT", "-T4", "-F", "-sV", "--version-light"],
        "description": "Top 100 ports + light service detection",
        "estimated": "30-90s",
    },
    "comprehensive": {
        "args": ["-sT", "-T4", "-p-", "-sV"],
        "description": "Full TCP 1-65535 + service detection",
        "estimated": "5-30 min",
    },
    "stealth": {
        "args": ["-sS", "-T2", "-F", "-sV"],
        "description": "SYN stealth (needs root) — falls back to -sT if not root",
        "estimated": "1-3 min",
    },
    "udp": {
        "args": ["-sU", "--top-ports", "50", "-T4"],
        "description": "Top 50 UDP ports (needs root)",
        "estimated": "1-5 min",
    },
    "nse": {
        "args": ["-sT", "-sV", "--script", "default,safe", "-F"],
        "description": "Default+safe NSE scripts on top 100",
        "estimated": "2-10 min",
    },
    "full": {
        "args": ["-sT", "-T4", "-p-", "-sV", "-sC"],
        "description": "Full TCP + default scripts",
        "estimated": "10-40 min",
    },
}


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str
    product: str | None = None
    version: str | None = None
    description: str = ""
    risk: str = "low"
    notes: list[str] = field(default_factory=list)
    probe: dict[str, Any] | None = None


@dataclass
class ScanResult:
    target: str
    profile: str
    duration_seconds: float
    ports: list[PortResult] = field(default_factory=list)
    os_guess: str | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    raw_nmap: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "profile": self.profile,
            "duration_seconds": self.duration_seconds,
            "ports": [asdict(p) for p in self.ports],
            "os_guess": self.os_guess,
            "error": self.error,
            "warnings": self.warnings,
        }

    def risk_summary(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for p in self.ports:
            counts[p.risk] = counts.get(p.risk, 0) + 1
        return counts


async def scan(
    target: str,
    profile: str = "quick",
    scope: Scope | None = None,
    timeout: int = 900,
) -> ScanResult:
    """Run a port scan for the given target and profile, then enrich."""
    start = time.monotonic()
    warnings: list[str] = []

    if scope is not None:
        scope.require_allowed(target)  # raises ScopeError

    if profile not in PROFILES:
        return ScanResult(
            target=target, profile=profile,
            duration_seconds=0.0,
            error=f"unknown profile '{profile}' (choose from {list(PROFILES)})",
        )

    args = list(PROFILES[profile]["args"])

    priv = detect_priv()
    if profile == "stealth" and not priv.is_root:
        args = ["-sT" if a == "-sS" else a for a in args]
        warnings.append("Not root: stealth profile fell back to -sT (connect scan)")
    if profile == "udp" and not priv.is_root:
        warnings.append("UDP scan usually requires root — results may be empty")
    if profile in ("comprehensive", "full"):
        warnings.append(
            f"Profile '{profile}' scans all 65535 ports — may take "
            f"{PROFILES[profile]['estimated']} on mobile"
        )

    findings, os_guess, raw = await scan_ports_xml(target, args, timeout=timeout)

    if raw in ("timeout", "nmap not found"):
        return ScanResult(
            target=target, profile=profile,
            duration_seconds=round(time.monotonic() - start, 2),
            error=raw, warnings=warnings,
        )

    ports: list[PortResult] = []
    for f in findings:
        if f.state != "open":
            continue
        info = enrich_port(
            f.port, f.protocol, f.service, f.product, f.version
        )
        ports.append(PortResult(
            port=f.port, protocol=f.protocol, state=f.state,
            service=info["service"], product=f.product, version=f.version,
            description=info["description"], risk=info["risk"],
            notes=info["notes"],
        ))
    ports.sort(key=lambda p: (p.port, p.protocol))

    # ── Enrich with service probes (parallel, ~3s) ──────────────────
    if ports:
        try:
            probe_input = [
                {"port": prt.port, "service": prt.service} for prt in ports
            ]
            probe_results = await probe_ports_parallel(
                target, probe_input, timeout=3.0,
            )
            probe_map = {pr.port: pr.to_dict() for pr in probe_results}
            for prt in ports:
                prt.probe = probe_map.get(prt.port)
        except Exception as e:
            warnings.append(f"service probes failed: {e}")

    return ScanResult(
        target=target, profile=profile,
        duration_seconds=round(time.monotonic() - start, 2),
        ports=ports, os_guess=os_guess,
        warnings=warnings,
        raw_nmap=raw[:8000],
    )
