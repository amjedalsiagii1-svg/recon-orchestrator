"""Tests for phases — no network required."""
import asyncio

import pytest

from phases.p1_network_type import (
    NetworkInfo,
    CaptiveCheck,
    TLSCheck,
    classify,
    _guess_subnet,
)


def test_guess_subnet_v4() -> None:
    assert _guess_subnet("192.168.1.5") == "192.168.1.5/24"


def test_classify_hotspot() -> None:
    net = NetworkInfo(local_ips=["192.168.43.7"], default_gateway="192.168.43.1")
    c = classify(net, CaptiveCheck(status=204), TLSCheck(connected=True, is_suspicious=False), True)
    assert c.type == "hotspot"
    assert c.confidence > 0


def test_classify_captive_portal() -> None:
    net = NetworkInfo(local_ips=["10.20.30.40"], default_gateway="10.20.30.1")
    cap = CaptiveCheck(status=302, redirected=True, location="http://wifi.example.com/login")
    c = classify(net, cap, TLSCheck(connected=True, is_suspicious=False), True)
    assert c.type == "commercial"
    assert "redirect" in " ".join(c.reasons).lower()


def test_classify_home_router() -> None:
    net = NetworkInfo(local_ips=["192.168.1.10"], default_gateway="192.168.1.1")
    c = classify(
        net,
        CaptiveCheck(status=204),
        TLSCheck(connected=True, issuer_cn="Let's Encrypt", is_suspicious=False),
        True,
    )
    assert c.type in ("home_router", "hotspot")
    assert c.confidence >= 0


def test_classify_suspicious_tls() -> None:
    net = NetworkInfo(local_ips=["10.0.0.5"], default_gateway="10.0.0.1")
    c = classify(
        net,
        CaptiveCheck(status=204),
        TLSCheck(connected=True, issuer_cn="Fake CA Inc", is_suspicious=True),
        True,
    )
    assert c.type == "commercial"


def test_classify_unknown() -> None:
    net = NetworkInfo(local_ips=[], default_gateway=None)
    c = classify(
        net,
        CaptiveCheck(error="offline"),
        TLSCheck(error="offline"),
        False,
    )
    # no signals or commercial (dns fail + tls fail)
    assert c.type in ("unknown", "commercial")
