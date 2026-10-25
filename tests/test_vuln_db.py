"""Tests for core.vuln_db — no network."""
from core.vuln_db import lookup, severity_from_cvss


def test_dnsmasq_271_matches_six_cves() -> None:
    hits = lookup("dnsmasq", "2.71")
    assert len(hits) >= 6
    ids = {h["id"] for h in hits}
    assert "CVE-2017-14491" in ids


def test_dnsmasq_279_clean() -> None:
    assert lookup("dnsmasq", "2.79") == []


def test_apache_2449_critical() -> None:
    hits = lookup("Apache httpd", "2.4.49")
    assert any(h["id"] == "CVE-2021-41773" for h in hits)
    assert hits[0]["cvss"] >= 9.0


def test_lighttpd_banner_version() -> None:
    hits = lookup("lighttpd", "1.4.59")
    assert any(h["id"] == "CVE-2022-22707" for h in hits)


def test_unknown_product_empty() -> None:
    assert lookup("unknown-product", "1.0") == []
    assert lookup(None, "1.0") == []
    assert lookup("dnsmasq", None) == []


def test_severity_mapping() -> None:
    assert severity_from_cvss(9.8) == "critical"
    assert severity_from_cvss(7.5) == "high"
    assert severity_from_cvss(5.0) == "medium"
    assert severity_from_cvss(2.0) == "low"
    assert severity_from_cvss(0.0) == "info"
