"""Tests for phases.p4_port_scan — no network required."""
from pathlib import Path

import pytest

from core.scope import Scope, ScopeError
from phases.p4_port_scan import PROFILES, ScanResult, PortResult, scan


def _scope(tmp_path: Path, content: str = "127.0.0.1" + chr(10)) -> Scope:
    p = tmp_path / "scope.txt"
    p.write_text(content, encoding="utf-8")
    return Scope(p)


def test_profiles_present() -> None:
    for name in ("quick", "comprehensive", "stealth", "udp", "nse", "full"):
        assert name in PROFILES
        assert "args" in PROFILES[name]
        assert "description" in PROFILES[name]
        assert "estimated" in PROFILES[name]


def test_scan_result_to_dict() -> None:
    r = ScanResult(
        target="127.0.0.1", profile="quick", duration_seconds=1.5,
        ports=[PortResult(port=22, protocol="tcp", state="open",
                          service="ssh", risk="medium")],
        os_guess="Linux",
    )
    d = r.to_dict()
    assert d["target"] == "127.0.0.1"
    assert len(d["ports"]) == 1
    assert d["ports"][0]["port"] == 22


def test_risk_summary() -> None:
    r = ScanResult(
        target="127.0.0.1", profile="quick", duration_seconds=1.0,
        ports=[
            PortResult(port=22, protocol="tcp", state="open",
                       service="ssh", risk="medium"),
            PortResult(port=23, protocol="tcp", state="open",
                       service="telnet", risk="critical"),
            PortResult(port=80, protocol="tcp", state="open",
                       service="http", risk="low"),
        ],
    )
    s = r.risk_summary()
    assert s["medium"] == 1
    assert s["critical"] == 1
    assert s["low"] == 1
    assert s["high"] == 0


@pytest.mark.asyncio
async def test_scan_rejects_out_of_scope(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    with pytest.raises(ScopeError):
        await scan("8.8.8.8", profile="quick", scope=scope, timeout=5)


@pytest.mark.asyncio
async def test_scan_unknown_profile(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    r = await scan("127.0.0.1", profile="bogus", scope=scope, timeout=5)
    assert r.error is not None
    assert "unknown profile" in r.error
