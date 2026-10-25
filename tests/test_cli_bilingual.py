"""Tests for CLI bilingual support (Batch 3)."""
from core import i18n


def test_banner_subtitle_keys_exist():
    i18n.reset()
    ar = i18n.t("ui.banner_subtitle", lang="ar")
    en = i18n.t("ui.banner_subtitle", lang="en")
    assert ar != en
    assert len(ar) > 0
    assert len(en) > 0


def test_menu_header_keys_exist():
    i18n.reset()
    ar = i18n.t("ui.menu_header", lang="ar")
    en = i18n.t("ui.menu_header", lang="en")
    assert ar != en


def test_status_keys_exist():
    i18n.reset()
    for key in ("ui.target_unset", "ui.phase_prefix", "ui.scan_profiles"):
        ar = i18n.t(key, lang="ar")
        en = i18n.t(key, lang="en")
        assert ar != en, f"{key} has identical ar/en"


def test_phase_running_messages():
    i18n.reset()
    for p in ("p1", "p2", "p3", "p4", "p5", "p6", "p7"):
        ar = i18n.t(f"phase.{p}_running", lang="ar")
        en = i18n.t(f"phase.{p}_running", lang="en")
        assert ar != en, f"{p}_running has identical ar/en"


def test_phase_ar_dict_present():
    from ui.cli import PHASE_AR
    assert len(PHASE_AR) == 7
    for key in ("p1", "p2", "p3", "p4", "p5", "p6", "p7"):
        assert key in PHASE_AR
        assert len(PHASE_AR[key]) > 0


def test_cli_has_bil_helper():
    from ui.cli import CLI
    assert hasattr(CLI, "_bil")
    assert hasattr(CLI, "_bil_kv")


def test_all_phases_have_arabic_name():
    from ui.cli import PHASE_AR, PHASES
    for pid, _name, _desc in PHASES:
        assert pid in PHASE_AR, f"{pid} missing from PHASE_AR"
