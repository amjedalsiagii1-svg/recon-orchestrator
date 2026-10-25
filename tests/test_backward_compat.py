"""Backward-compat: existing APIs must work identically."""
from core.vuln_db import VULN_DB, lookup, severity_from_cvss
from core.exploit_db import EXPLOIT_DB, get_exploit, get_all_cves, plan_exploitation


def test_vuln_db_loaded():
    assert isinstance(VULN_DB, dict)
    assert "dnsmasq" in VULN_DB
    assert len(VULN_DB["dnsmasq"]) >= 3


def test_lookup_works():
    hits = lookup("dnsmasq", "2.71")
    assert len(hits) >= 3
    ids = {h["id"] for h in hits}
    assert "CVE-2017-14491" in ids


def test_lookup_clean_version():
    assert lookup("dnsmasq", "2.79") == []


def test_severity_mapping():
    assert severity_from_cvss(9.8) == "critical"
    assert severity_from_cvss(7.5) == "high"
    assert severity_from_cvss(5.0) == "medium"
    assert severity_from_cvss(2.0) == "low"


def test_exploit_db_loaded():
    assert isinstance(EXPLOIT_DB, dict)
    assert "CVE-2017-14491" in EXPLOIT_DB


def test_get_exploit_works():
    e = get_exploit("CVE-2017-14491")
    assert e is not None
    assert "module" in e
    assert "impact" in e


def test_get_exploit_unknown():
    assert get_exploit("CVE-9999-00000") is None


def test_get_all_cves_works():
    cat = get_all_cves()
    assert isinstance(cat, list)
    assert len(cat) >= 20
    # Must be sorted with root first
    first = cat[0]
    assert "cve" in first


def test_plan_exploitation_works():
    vulns = [{
        "id": "CVE-2017-14491", "severity": "critical", "cvss": 9.8,
        "port": 53, "product": "dnsmasq", "version": "2.71",
    }]
    plans = plan_exploitation(vulns)
    assert len(plans) >= 1
    assert plans[0]["cve"] == "CVE-2017-14491"
