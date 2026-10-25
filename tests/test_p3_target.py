"""Tests for Phase 3 — target selection."""
from pathlib import Path

import pytest

from core.scope import Scope, ScopeError
from phases.p3_target_select import select_target


def _scope(tmp_path: Path, content: str = "192.168.8.0/24\n") -> Scope:
    p = tmp_path / "scope.txt"
    p.write_text(content, encoding="utf-8")
    return Scope(p)


DEVICES = [
    {"ip": "192.168.8.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Huawei",
     "hostname": "mobile.router", "device_type": "router", "is_gateway": True},
    {"ip": "192.168.8.20", "mac": None, "vendor": None,
     "hostname": "printer", "device_type": "printer", "is_gateway": False},
    {"ip": "192.168.8.30", "mac": None, "vendor": "Apple",
     "hostname": None, "device_type": "mobile", "is_gateway": False},
]


def test_select_existing_device(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    t = select_target("192.168.8.1", DEVICES, scope)
    assert t.ip == "192.168.8.1"
    assert t.device_type == "router"
    assert t.is_gateway is True
    assert t.in_scope is True
    assert len(t.recommended_next) > 0


def test_select_printer(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    t = select_target("192.168.8.20", DEVICES, scope)
    assert t.device_type == "printer"
    assert any("9100" in r for r in t.recommended_next)


def test_select_unknown_still_allowed_if_in_scope(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    t = select_target("192.168.8.99", DEVICES, scope)
    assert t.device_type == "unknown"
    assert t.mac is None
    assert t.in_scope is True


def test_reject_out_of_scope(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    with pytest.raises(ScopeError):
        select_target("8.8.8.8", DEVICES, scope)


def test_reject_empty() -> None:
    with pytest.raises(ValueError):
        select_target("", [], Scope(Path(__file__)))


def test_mobile_recommendations_warn(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    t = select_target("192.168.8.30", DEVICES, scope)
    assert t.device_type == "mobile"
    joined = " ".join(t.recommended_next).lower()
    assert "limited" in joined or "sandbox" in joined
