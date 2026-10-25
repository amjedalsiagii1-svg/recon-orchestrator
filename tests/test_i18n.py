"""Tests for core.i18n."""
from core import i18n


def test_t_returns_string():
    i18n.reset()
    s = i18n.t("app.title")
    assert isinstance(s, str)
    assert len(s) > 0


def test_t_missing_key_returns_key():
    i18n.reset()
    s = i18n.t("nonexistent.key.xyz")
    assert s == "nonexistent.key.xyz"


def test_tb_returns_tuple():
    i18n.reset()
    ar, en = i18n.tb("app.title")
    assert isinstance(ar, str)
    assert isinstance(en, str)
    assert len(ar) > 0
    assert len(en) > 0


def test_set_mode():
    i18n.reset()
    i18n.set_mode("ar")
    assert i18n.get_mode() == "ar"
    i18n.set_mode("en")
    assert i18n.get_mode() == "en"
    i18n.set_mode("bilingual")
    assert i18n.get_mode() == "bilingual"


def test_phase_translations_differ():
    i18n.reset()
    ar = i18n.t("phase.p1", lang="ar")
    en = i18n.t("phase.p1", lang="en")
    assert ar != en


def test_format_kwargs_safe():
    i18n.reset()
    s = i18n.t("nonexistent", foo="bar")
    assert s == "nonexistent"


def test_bilingual_returns_both():
    i18n.reset()
    ar, en = i18n.tb("phase.p1")
    assert "شبكة" in ar or "Network" in en
    assert ar != en
