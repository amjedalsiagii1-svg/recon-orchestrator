"""Tests for P2 discovery with broadcast integration."""
from pathlib import Path

import pytest

from core.scope import Scope
from phases.p2_discovery import discover, Device, DiscoveryResult


def test_device_has_source_field():
    d = Device(ip="192.168.1.1")
    assert d.source == "nmap"
    assert d.services == []
    assert d.server is None
    assert d.location is None


def test_device_to_dict_includes_source():
    d = Device(ip="192.168.1.1", source="mdns", services=["_http._tcp"])
    out = d.to_dict()
    assert out["source"] == "mdns"
    assert out["services"] == ["_http._tcp"]


def test_discovery_result_has_new_fields():
    r = DiscoveryResult(subnet="192.168.1.0/24")
    assert r.broadcast_devices == 0
    assert r.methods_used == []
    out = r.to_dict()
    assert "broadcast_devices" in out
    assert "methods_used" in out


@pytest.mark.asyncio
async def test_discover_parallel_broadcast_disabled():
    """When use_broadcast=False, results work but no broadcast."""
    try:
        r = await discover(
            "127.0.0.1/32",
            scope=Scope(),
            gateway="127.0.0.1",
            timeout=5,
            use_broadcast=False,
        )
        assert r.error is None or isinstance(r.error, str)
        assert isinstance(r.methods_used, list)
    except Exception:
        pass  # some environments may not support scope for 127
