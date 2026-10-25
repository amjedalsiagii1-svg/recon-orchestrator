"""Tests for core.service_probes — no external network needed."""
import pytest

from core.service_probes import (
    ProbeResult, probe_port, probe_ports_parallel,
    HTTP_PORTS, HTTPS_PORTS, _SECURITY_HEADERS,
)


def test_constants() -> None:
    assert 80 in HTTP_PORTS
    assert 443 in HTTPS_PORTS
    assert "strict-transport-security" in _SECURITY_HEADERS


def test_probe_result_defaults() -> None:
    r = ProbeResult(port=80)
    assert r.port == 80
    assert r.service == "unknown"
    assert r.http_cookies == []
    assert r.tls_self_signed is False


def test_probe_result_to_dict() -> None:
    r = ProbeResult(
        port=443, service="https",
        http_title="Login", http_server="nginx",
        tls_version="TLSv1.3", tls_self_signed=True,
    )
    d = r.to_dict()
    assert d["port"] == 443
    assert d["http_title"] == "Login"
    assert d["tls_self_signed"] is True


@pytest.mark.asyncio
async def test_probe_closed_port_timeout() -> None:
    # Port 1 will almost certainly be closed → timeout or connection refused
    r = await probe_port("127.0.0.1", 1, "unknown", timeout=0.5)
    assert r.port == 1
    assert r.error is not None


@pytest.mark.asyncio
async def test_probe_ports_parallel_empty() -> None:
    results = await probe_ports_parallel("127.0.0.1", [], timeout=0.5)
    assert results == []


@pytest.mark.asyncio
async def test_probe_ports_parallel_multiple() -> None:
    ports = [{"port": 1, "service": "unknown"}, {"port": 2, "service": "unknown"}]
    results = await probe_ports_parallel("127.0.0.1", ports, timeout=0.5)
    assert len(results) == 2
    assert {r.port for r in results} == {1, 2}
