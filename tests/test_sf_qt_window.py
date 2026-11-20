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
        assert window.stack.count() == 9
        assert window.commands_table.rowCount() == len(SAFE_COMMANDS)
        assert window.sessions_table.columnCount() == 4
        assert window.evidence_table.columnCount() == 7
        assert window.inventory_assets_table.columnCount() == 6
        assert window.inventory_services_table.columnCount() == 7
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



def test_inventory_view_lists_imported_assets_and_services(qapp, tmp_path, monkeypatch):
    import hashlib

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-inventory"))
    window = MainWindow()
    try:
        session = window.store.create_session("اختبار سجل الأصول")
        window.store.import_inventory(
            session["id"],
            source_name="fixture.xml",
            sha256=hashlib.sha256(b"fixture").hexdigest(),
            assets=[{
                "ip": "192.168.8.15",
                "hostname": "lab-device.local",
                "mac": "aa:bb:cc:dd:ee:15",
                "vendor": "Example Vendor",
                "state": "up",
            }],
            services=[{
                "ip": "192.168.8.15",
                "protocol": "tcp",
                "port": 443,
                "state": "open",
                "name": "https",
                "product": "Example Server",
                "version": "1.2",
            }],
            authorization_confirmed=True,
        )
        window._refresh_inventory_sessions()
        index = window.inventory_session_combo.findData(session["id"])
        assert index >= 0
        window.inventory_session_combo.setCurrentIndex(index)
        window._refresh_inventory_tables()
        assert window.inventory_assets_table.rowCount() == 1
        assert window.inventory_services_table.rowCount() == 1
        assert window.inventory_assets_table.item(0, 0).text() == "192.168.8.15"
        assert window.inventory_services_table.item(0, 2).text() == "443"
    finally:
        window.close()



def test_one_click_local_audit_creates_session_and_saves_snapshot(qapp, tmp_path, monkeypatch):
    from sf_desktop.local_audit import LocalAuditSnapshot
    from sf_desktop import window as window_module

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-quick-audit"))
    snapshot = LocalAuditSnapshot(
        collected_at="2026-11-20T00:00:00+00:00",
        hostname="kali-test",
        interfaces=({
            "name": "eth0",
            "state": "UP",
            "mac": "aa:bb:cc:dd:ee:20",
            "addresses": ["192.168.8.20"],
        },),
        assets=({
            "ip": "192.168.8.20",
            "hostname": "kali-test",
            "mac": "aa:bb:cc:dd:ee:20",
            "vendor": None,
            "state": "up",
        },),
        services=({
            "ip": "192.168.8.20",
            "protocol": "tcp",
            "port": 631,
            "state": "listening",
            "name": "مستمع TCP محلي",
            "product": None,
            "version": None,
            "extra_info": "عنوان الربط المحلي: 127.0.0.1",
        },),
        default_gateway="192.168.8.1",
        default_interface="eth0",
        dns_servers=("192.168.8.1",),
        warnings=(),
    )
    monkeypatch.setattr(window_module, "collect_local_snapshot", lambda: snapshot)
    monkeypatch.setattr(
        window_module.QMessageBox,
        "information",
        lambda *args, **kwargs: window_module.QMessageBox.StandardButton.Ok,
    )

    window = MainWindow()
    try:
        assert window.inventory_session_combo.count() == 0
        window._run_local_audit()
        assert window.inventory_session_combo.count() == 1
        session_id = window.inventory_session_combo.currentData()
        assert session_id
        assert window.inventory_assets_table.rowCount() == 1
        assert window.inventory_services_table.rowCount() == 1
        assert window.inventory_assets_table.item(0, 0).text() == "192.168.8.20"
        assert window.inventory_services_table.item(0, 2).text() == "631"
        assert "192.168.8.1" in window.inventory_status.text()
        imports = window.store.list_imports(session_id)
        assert imports[0]["source_type"] == "local-readonly"
        assert imports[0]["authorization_confirmed"] == 0
        evidence = window.store.list_evidence(session_id)
        assert any(item["source"] == "local-readonly" for item in evidence)
    finally:
        window.close()
