"""Tests for core.reporter + phases.p7_report."""
from pathlib import Path

import pytest

from core.reporter import build_context, render_report
from core.session import Session
from phases.p7_report import generate as generate_p7


TEMPLATE_DIR = Path("reports/templates")


@pytest.mark.asyncio
async def test_render_empty_session(tmp_path: Path) -> None:
    """Empty session renders without errors."""
    s = await Session.open(tmp_path / "t.db")
    try:
        await s.create("empty")
        from core.reporter import collect_session_data
        data = await collect_session_data(s)
        out = tmp_path / "empty.html"
        render_report(data, TEMPLATE_DIR, out)
        html = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "Recon Report" in html
        assert "لم يتم اكتشاف أي ثغرة" in html or "No vulnerabilities" in html
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_render_with_vulns(tmp_path: Path) -> None:
    s = await Session.open(tmp_path / "t.db")
    try:
        await s.create("t")
        await s.log_event("p3", "info", "target", {"ip": "10.0.0.1"})
        await s.log_event("p5", "info", "v", {
            "target": "10.0.0.1", "duration_seconds": 1.0,
            "vulns": [
                {"id": "CVE-2017-14491", "severity": "critical", "cvss": 9.8,
                 "port": 53, "product": "dnsmasq", "version": "2.71",
                 "description": "DNS RCE", "remediation": "Upgrade",
                 "famous": True, "source": "vuln_db"},
                {"id": "CVE-2022-22707", "severity": "medium", "cvss": 5.3,
                 "port": 80, "product": "lighttpd", "version": "1.4.59",
                 "description": "OOB read", "remediation": "Upgrade",
                 "famous": False, "source": "vuln_db"},
            ],
            "sources_used": ["vuln_db"], "warnings": [], "error": None,
        })
        from core.reporter import collect_session_data
        data = await collect_session_data(s)
        out = tmp_path / "v.html"
        render_report(data, TEMPLATE_DIR, out)
        html = out.read_text(encoding="utf-8")
        assert "CVE-2017-14491" in html
        assert "CVE-2022-22707" in html
        assert "CRITICAL" in html
        assert "critical" in html.lower()
        assert "ثغرة حرجة" in html or "critical vulnerability" in html.lower()
        assert "10.0.0.1" in html
    finally:
        await s.close()


def test_build_context_severity_counts() -> None:
    data = {
        "session": {"id": "abc123"},
        "phases": {
            "p3": {"ip": "10.0.0.5"},
            "p5": {
                "target": "10.0.0.5",
                "vulns": [
                    {"id": "A", "severity": "critical", "cvss": 9.5, "port": 1,
                     "product": "x", "version": "1", "description": "",
                     "remediation": "", "famous": False},
                    {"id": "B", "severity": "critical", "cvss": 9.0, "port": 2,
                     "product": "x", "version": "1", "description": "",
                     "remediation": "", "famous": False},
                    {"id": "C", "severity": "medium", "cvss": 5.0, "port": 3,
                     "product": "x", "version": "1", "description": "",
                     "remediation": "", "famous": False},
                ],
                "sources_used": [], "warnings": [], "error": None,
            },
        },
        "events": [],
    }
    ctx = build_context(data)
    assert ctx["target"] == "10.0.0.5"
    assert ctx["severity"]["critical"] == 2
    assert ctx["severity"]["medium"] == 1
    assert len(ctx["remediation"]) == 3
    # Critical first
    assert ctx["remediation"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_generate_p7_creates_file(tmp_path: Path) -> None:
    s = await Session.open(tmp_path / "t.db")
    try:
        await s.create("p7test")
        out_dir = tmp_path / "reports"
        result = await generate_p7(
            s, out_dir=out_dir, template_dir=TEMPLATE_DIR
        )
        assert result["ok"] is True
        assert result["format"] == "html"
        p = Path(result["path"])
        assert p.exists()
        assert p.stat().st_size > 500
        assert p.name.startswith("recon-")
        assert p.suffix == ".html"
    finally:
        await s.close()
