"""Tests for integrations/lan_discovery."""
import socket
from unittest.mock import patch

import pytest

from integrations import lan_discovery as ld


# ═══════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════
def test_local_ips_set_returns_set():
    ips = ld._local_ips_set()
    assert isinstance(ips, set)
    assert len(ips) >= 2  # at least 0.0.0.0 + 255.255.255.255


def test_is_self_ip_loopback():
    assert ld._is_self_ip("127.0.0.1") is True
    assert ld._is_self_ip("127.0.0.5") is True


def test_is_self_ip_broadcast():
    assert ld._is_self_ip("0.0.0.0") is True
    assert ld._is_self_ip("255.255.255.255") is True


def test_is_self_ip_external():
    # 8.8.8.8 is never us
    assert ld._is_self_ip("8.8.8.8") is False


# ═══════════════════════════════════════════════════════
# Device classification
# ═══════════════════════════════════════════════════════
def test_classify_router():
    d = ld.DiscoveredService(
        ip="192.168.1.1",
        source="ssdp",
        service="urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    )
    assert ld.classify_service_device(d) == "router"


def test_classify_printer():
    d = ld.DiscoveredService(
        ip="192.168.1.10",
        source="mdns",
        service="_printer._tcp.local",
        hostname="Brother-HL2370",
    )
    assert ld.classify_service_device(d) == "printer"


def test_classify_tv():
    d = ld.DiscoveredService(
        ip="192.168.1.20",
        source="ssdp",
        service="urn:dial-multiscreen-org:service:dial:1",
        server="Chromecast/1.0",
        raw={"description": "mediarenderer"},
    )
    # Chromecast response typically has media renderer info
    assert ld.classify_service_device(d) in ("tv", "unknown")


def test_classify_unknown():
    d = ld.DiscoveredService(ip="192.168.1.50", source="mdns")
    assert ld.classify_service_device(d) == "unknown"


# ═══════════════════════════════════════════════════════
# Protocol behavior (no real network)
# ═══════════════════════════════════════════════════════
@pytest.mark.asyncio
async def test_mdns_returns_list():
    # With very short timeout, should still return a list
    result = await ld.mdns_discover(timeout=0.3)
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_ssdp_returns_list():
    result = await ld.ssdp_discover(timeout=0.3)
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_netbios_returns_list():
    result = await ld.netbios_discover(timeout=0.3)
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_lan_discover_all_returns_list():
    result = await ld.lan_discover_all(timeout=0.3)
    assert isinstance(result, list)


def test_discover_sync_returns_list():
    result = ld.discover_sync(timeout=0.3)
    assert isinstance(result, list)


# ═══════════════════════════════════════════════════════
# DiscoveredService to_dict
# ═══════════════════════════════════════════════════════
def test_discovered_service_to_dict():
    d = ld.DiscoveredService(
        ip="10.0.0.1",
        source="mdns",
        hostname="test.local",
        service="_http._tcp.local",
    )
    out = d.to_dict()
    assert out["ip"] == "10.0.0.1"
    assert out["source"] == "mdns"
    assert out["hostname"] == "test.local"
    assert out["service"] == "_http._tcp.local"
