"""Tests for core.platform."""
from core import platform as plat


def test_detect_returns_info():
    p = plat.detect()
    assert p.name in ("termux", "kali", "debian", "unknown")
    assert isinstance(p.python_version, str)
    assert isinstance(p.os_name, str)
    assert isinstance(p.kernel, str)
    assert isinstance(p.arch, str)


def test_get_is_cached():
    a = plat.get()
    b = plat.get()
    assert a is b


def test_reset_cache():
    a = plat.get()
    plat.reset_cache()
    b = plat.get()
    assert a is not b


def test_label_format():
    p = plat.detect()
    label = p.label
    assert isinstance(label, str)
    assert len(label) > 0


def test_platform_name_consistency():
    """If is_termux, name must be 'termux'."""
    p = plat.detect()
    if p.is_termux:
        assert p.name == "termux"
    if p.is_kali:
        assert p.name == "kali"
