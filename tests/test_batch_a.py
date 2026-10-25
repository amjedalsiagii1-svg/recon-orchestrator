"""Tests for Batch A — critical fixes."""
import pytest
from pathlib import Path

from core import capabilities


def test_nuclei_helper_exists():
    """_find_nuclei and _nuclei_works should be defined."""
    assert hasattr(capabilities, "_find_nuclei")
    assert hasattr(capabilities, "_nuclei_works")


def test_find_nuclei_returns_valid_path_or_none():
    path = capabilities._find_nuclei()
    assert path is None or Path(path).exists()


def test_nuclei_works_is_bool():
    result = capabilities._nuclei_works()
    assert isinstance(result, bool)


def test_capabilities_consistency_after_fix():
    c = capabilities.detect()
    # available + missing must equal total
    assert c.available_count + len(c.missing_features()) == c.total_count


def test_test_cve_removed():
    """The test CVE-2024-99999 should be deleted."""
    test_file = Path("plugins/cves/CVE-2024-99999.yaml")
    assert not test_file.exists(), "test CVE still present"


def test_p1_interface_helper():
    """_detect_iface must be importable from p1."""
    from phases.p1_network_type import _detect_iface
    assert callable(_detect_iface)


def test_p1_gather_network_info_uses_iface():
    """gather_network_info should return a NetworkInfo with proper structure."""
    from phases.p1_network_type import gather_network_info
    info = gather_network_info()
    assert hasattr(info, "default_iface")
    # iface may be None on some environments, but the field must exist
    assert info.default_iface is None or isinstance(info.default_iface, str)


def test_phase3_has_arabic():
    """ui/cli.py should contain Arabic in phase 3."""
    content = Path("ui/cli.py").read_text(encoding="utf-8")
    assert "المرحلة 3" in content
    assert "اختر الهدف" in content
    assert "الهدف المختار" in content


def test_stealth_warning_exists():
    """_phase4 should warn before stealth profile."""
    content = Path("ui/cli.py").read_text(encoding="utf-8")
    assert "يحتاج root عادة" in content
    assert "Continue? [y/N]" in content or "متابعة؟" in content
