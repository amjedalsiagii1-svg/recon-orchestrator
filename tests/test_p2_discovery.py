"""Tests for Phase 2 — no network required."""
from integrations.nmap_runner import _parse_nmap_sn
from phases.p2_discovery import classify_device


def test_parse_nmap_simple() -> None:
    raw = """Starting Nmap 7.99
Nmap scan report for 192.168.1.1
Host is up (0.0023s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Huawei Technologies)
Nmap scan report for printer.local (192.168.1.20)
Host is up (0.0050s latency).
Nmap scan report for 192.168.1.30
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.5 seconds
"""
    hosts = _parse_nmap_sn(raw)
    assert len(hosts) == 3
    assert hosts[0].ip == "192.168.1.1"
    assert hosts[0].mac == "aa:bb:cc:dd:ee:ff"
    assert "huawei" in (hosts[0].vendor or "").lower()
    assert hosts[1].ip == "192.168.1.20"
    assert hosts[1].hostname == "printer.local"
    assert hosts[2].ip == "192.168.1.30"


def test_classify_gateway() -> None:
    assert classify_device("192.168.1.1", "192.168.1.1", None, None) == "router"


def test_classify_printer_by_hostname() -> None:
    assert classify_device("192.168.1.20", "192.168.1.1", "hp-laserjet", None) == "printer"


def test_classify_camera_by_hostname() -> None:
    assert classify_device("192.168.1.30", "192.168.1.1", "hikvision-cam", None) == "camera"


def test_classify_mobile_by_vendor() -> None:
    assert classify_device("192.168.1.40", "192.168.1.1", None, "Samsung Electronics") == "mobile"


def test_classify_router_by_vendor() -> None:
    assert classify_device("192.168.1.2", "192.168.1.1", None, "TP-Link") == "router"


def test_classify_iot_by_vendor() -> None:
    assert classify_device("192.168.1.60", "192.168.1.1", None, "Espressif Inc.") == "iot"


def test_classify_unknown() -> None:
    assert classify_device("192.168.1.99", "192.168.1.1", None, None) == "unknown"
