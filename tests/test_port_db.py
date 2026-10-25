"""Tests for core.port_db."""
from core.port_db import get_port_info, enrich


def test_ssh_medium() -> None:
    info = get_port_info(22)
    assert info["service"] == "ssh"
    assert info["risk"] == "medium"
    assert isinstance(info["notes"], list)


def test_telnet_critical() -> None:
    info = get_port_info(23)
    assert info["service"] == "telnet"
    assert info["risk"] == "critical"
    assert any("cleartext" in n.lower() for n in info["notes"])


def test_unknown_port() -> None:
    info = get_port_info(65000)
    assert info["service"] == "unknown"
    assert info["risk"] == "low"
    assert info["notes"] == []


def test_enrich_preserves_nmap_service() -> None:
    out = enrich(22, "tcp", "ssh", "OpenSSH", "8.2")
    assert out["nmap_service"] == "ssh"
    assert out["product"] == "OpenSSH"
    assert out["version"] == "8.2"
    assert "version_note" in out


def test_enrich_escalates_telnet_on_odd_port() -> None:
    out = enrich(2222, "tcp", "telnet", None, None)
    assert out["risk"] in ("high", "critical")


def test_enrich_unknown_port_with_banner() -> None:
    out = enrich(9999, "tcp", None, "weird-service", "1.0")
    assert out["service"] == "unknown"
    assert out["risk"] == "medium"
    assert any("banner" in n.lower() for n in out["notes"])
