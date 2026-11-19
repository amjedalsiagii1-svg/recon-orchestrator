"""Headless integration tests for SF desktop widgets and persistence."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from sf_desktop.advisor import SAFE_COMMANDS
from sf_desktop.reporting import generate_session_report
from sf_desktop.window import MainWindow


@pytest.fixture(scope="module")
def qapp():
    application = QApplication.instance() or QApplication([])
    yield application


def test_window_builds_arabic_pages_and_command_catalog(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    window = MainWindow()
    try:
        assert window.stack.count() == 8
        assert window.commands_table.rowCount() == len(SAFE_COMMANDS)
        assert window.sessions_table.columnCount() == 4
        assert window.evidence_table.columnCount() == 7
        assert window.store is not None
    finally:
        window.close()


def test_ui_evidence_flow_and_report_generation(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-flow"))
    window = MainWindow()
    try:
        session = window.store.create_session("اختبار واجهة SF")
        window._refresh_sessions_table()
        window._refresh_evidence_sessions()
        index = window.evidence_session_combo.findData(session["id"])
        assert index >= 0
        window.evidence_session_combo.setCurrentIndex(index)

        window.store.add_evidence(
            session["id"],
            source="user-entered",
            category="service",
            title="خدمة اختبارية",
            detail="سجل تجريبي محلي للاختبار الآلي فقط.",
            confidence=0.6,
            payload={"severity": "medium", "verification_status": "unverified"},
        )
        window._refresh_evidence_table()
        assert window.evidence_table.rowCount() == 1
        assert "مراجعة الحاجة إلى الخدمة" in window.evidence_advice.text()

        report = generate_session_report(
            window.store, session["id"], tmp_path / "reports"
        )
        html = report.read_text(encoding="utf-8")
        assert report.exists()
        assert "خدمة اختبارية" in html
        assert "ip -br address" in html
    finally:
        window.close()
