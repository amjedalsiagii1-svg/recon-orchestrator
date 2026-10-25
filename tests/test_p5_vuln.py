"""Tests for phases.p5_vuln_scan — no network."""
from pathlib import Path

import pytest

from core.scope import Scope, ScopeError
from phases.p5_vuln_scan import Vuln, VulnScanResult, scan, _match_ports_via_db


def _scope(tmp_path: Path) -> Scope:
    p = tmp_path / "scope.txt"
    p.write_text("127.0.0.1" + chr(10), encoding="utf-8")
    return Scope(p)


def test_match_dnsmasq_ports() -> None:
    ports = [{"port": 53, "service": "dns", "product": "dnsmasq", "version": "2.71"}]
    vulns = _match_ports_via_db(ports)
    assert len(vulns) >= 6
    assert all(v.source == "vuln_db" for v in vulns)
    assert any(v.id == "CVE-2017-14491" for v in vulns)


def test_match_skips_no_product() -> None:
    ports = [{"port": 53, "service": "dns", "product": None, "version": None}]
    assert _match_ports_via_db(ports) == []


def test_severity_summary() -> None:
    r = VulnScanResult(
        target="127.0.0.1", duration_seconds=1.0,
        vulns=[
            Vuln(id="CVE-A", severity="critical", source="vuln_db"),
            Vuln(id="CVE-B", severity="critical", source="vuln_db"),
            Vuln(id="CVE-C", severity="high", source="vuln_db"),
            Vuln(id="CVE-D", severity="low", source="vuln_db"),
        ],
    )
    s = r.severity_summary()
    assert s["critical"] == 2
    assert s["high"] == 1
    assert s["low"] == 1


@pytest.mark.asyncio
async def test_scan_rejects_out_of_scope(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    with pytest.raises(ScopeError):
        await scan("8.8.8.8", [], scope=scope, run_nuclei=False)


@pytest.mark.asyncio
async def test_scan_no_ports_no_vulns(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    r = await scan("127.0.0.1", [], scope=scope, run_nuclei=False)
    assert r.error is None
    assert r.vulns == []
    assert r.sources_used == []


@pytest.mark.asyncio
async def test_scan_matches_from_port_list(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    ports = [{"port": 80, "service": "http", "product": "lighttpd", "version": "1.4.59"}]
    r = await scan("127.0.0.1", ports, scope=scope, run_nuclei=False)
    assert r.error is None
    assert any(v.id == "CVE-2022-22707" for v in r.vulns)
    assert "vuln_db" in r.sources_used
