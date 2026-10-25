"""Tests for core.capabilities."""
from core import capabilities as caps


def test_detect_returns_object():
    c = caps.detect()
    assert c.platform in ("termux", "kali", "debian", "unknown")
    assert isinstance(c.root, bool)
    assert isinstance(c.nmap, bool)


def test_available_count_in_range():
    c = caps.detect()
    assert 0 <= c.available_count <= c.total_count
    assert c.total_count == 12


def test_missing_features_is_list():
    c = caps.detect()
    m = c.missing_features()
    assert isinstance(m, list)
    for item in m:
        assert isinstance(item, str)


def test_has_scan_type():
    c = caps.detect()
    assert isinstance(c.has_scan_type("syn"), bool)
    assert c.has_scan_type("nonexistent") is False


def test_summary_short():
    c = caps.detect()
    s = c.summary_short
    assert isinstance(s, str)
    assert "/" in s


def test_cache_works():
    a = caps.get()
    b = caps.get()
    assert a is b


def test_reset_cache():
    a = caps.get()
    caps.reset_cache()
    b = caps.get()
    assert a is not b
