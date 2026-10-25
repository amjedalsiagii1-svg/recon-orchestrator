"""Tests for core.plugin_loader."""
from pathlib import Path

import pytest

from core import plugin_loader as pl


def test_discover_cve_files():
    files = pl.discover_cve_files()
    assert len(files) >= 20
    for f in files:
        assert f.name.startswith("CVE-")
        assert f.suffix == ".yaml"


def test_load_all_cves_strict():
    cves = pl.load_all_cves(strict=True)
    assert len(cves) >= 20
    for c in cves:
        assert "cve" in c
        assert "cvss" in c


def test_build_vuln_db():
    cves = pl.load_all_cves()
    db = pl.build_vuln_db(cves)
    assert isinstance(db, dict)
    assert "dnsmasq" in db
    entries = db["dnsmasq"]
    assert len(entries) >= 3
    ids = {e["id"] for e in entries}
    assert "CVE-2017-14491" in ids


def test_build_exploit_db():
    cves = pl.load_all_cves()
    db = pl.build_exploit_db(cves)
    assert isinstance(db, dict)
    assert "CVE-2017-14491" in db
    ex = db["CVE-2017-14491"]
    assert "module" in ex
    assert "tool" in ex


def test_build_catalog():
    cves = pl.load_all_cves()
    cat = pl.build_cve_catalog(cves)
    assert isinstance(cat, list)
    assert len(cat) >= 20
    for entry in cat:
        assert "cve" in entry
        assert "severity" in entry


def test_validate_rejects_bad_cve():
    with pytest.raises(pl.PluginError):
        pl.validate_cve({}, Path("dummy.yaml"))
    with pytest.raises(pl.PluginError):
        pl.validate_cve({"cve": "BAD"}, Path("dummy.yaml"))


def test_validate_accepts_minimal():
    good = {
        "cve": "CVE-2024-99999",
        "cvss": 7.5,
        "description": "test",
        "impact": "test",
        "remediation": "test",
    }
    pl.validate_cve(good, Path("dummy.yaml"))  # no raise


def test_load_cve_file_real():
    files = pl.discover_cve_files()
    if not files:
        pytest.skip("no CVE files present")
    data = pl.load_cve_file(files[0])
    assert data["cve"].startswith("CVE-")
