"""Security and behavior tests for standalone SF HTML reports."""
from pathlib import Path

import pytest

from sf_desktop.reporting import ReportError, generate_session_report
from sf_desktop.storage import SFStore


def test_empty_session_report_is_honest_and_standalone(tmp_path):
    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("جلسة بلا فحص")
    report = generate_session_report(store, session["id"], tmp_path / "out")
    content = report.read_text(encoding="utf-8")
    assert report.suffix == ".html"
    assert "لا توجد أدلة مسجلة" in content
    assert "لا يمثل نتيجة فحص" in content
    assert "default-src 'none'" in content
    assert "<script" not in content.lower()


def test_report_escapes_untrusted_evidence_and_refreshes_same_file(tmp_path):
    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("تقرير آمن")
    store.add_evidence(
        session["id"],
        source="manual-note",
        category="ملاحظة",
        title='<img src=x onerror="alert(1)">',
        detail="<script>alert('x')</script>",
        confidence=0.75,
        payload={"input": "<svg onload=alert(1)>"},
    )
    output_dir = tmp_path / "out"
    report_one = generate_session_report(store, session["id"], output_dir)
    first = report_one.read_text(encoding="utf-8")
    report_two = generate_session_report(store, session["id"], output_dir)
    second = report_two.read_text(encoding="utf-8")

    assert report_one == report_two
    assert first == second
    assert "&lt;script&gt;" in first
    assert "&lt;img" in first
    assert "<script>alert" not in first
    assert len(list(output_dir.glob("*.html"))) == 1


def test_report_rejects_symlink_output_directory(tmp_path):
    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("symlink")
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not available")
    with pytest.raises(ReportError):
        generate_session_report(store, session["id"], link)
    assert not list(outside.iterdir())


def test_report_rejects_missing_session(tmp_path):
    store = SFStore(tmp_path / "sf.sqlite3")
    with pytest.raises(ReportError):
        generate_session_report(store, "missing", tmp_path / "out")


def test_report_contains_explainable_guidance_and_safe_commands(tmp_path):
    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("جلسة مراجعة خدمة")
    store.add_evidence(
        session["id"],
        source="user-entered",
        category="service",
        title="خدمة محلية",
        detail="خدمة تستمع محلياً وتحتاج إلى مراجعة سبب تشغيلها.",
        confidence=0.7,
        payload={"severity": "high", "verification_status": "unverified"},
    )
    report = generate_session_report(store, session["id"], tmp_path / "out")
    content = report.read_text(encoding="utf-8")
    assert "مراجعة الحاجة إلى الخدمة" in content
    assert "ip -br address" in content
    assert "ss -lntup" in content
    assert "ماذا يفعل؟" in content
    assert "unverified" in content  # user-entered evidence remains explicitly unverified
    assert "لا تُعرض نتائج فحص لم تُنفذ" in content
