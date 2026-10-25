"""Tests for core.scope."""
from pathlib import Path

import pytest

from core.scope import Scope, ScopeError


def _write_scope(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "scope.txt"
    p.write_text(content, encoding="utf-8")
    return p


def test_loopback_allowed(tmp_path: Path) -> None:
    s = Scope(_write_scope(tmp_path, "127.0.0.1\n::1\n"))
    assert s.is_allowed("127.0.0.1")
    assert s.is_allowed("::1")
    assert not s.is_allowed("8.8.8.8")
    assert not s.is_allowed("1.1.1.1")


def test_cidr(tmp_path: Path) -> None:
    s = Scope(_write_scope(tmp_path, "192.168.1.0/24\n"))
    assert s.is_allowed("192.168.1.10")
    assert s.is_allowed("192.168.1.255")
    assert not s.is_allowed("192.168.2.1")


def test_hostname(tmp_path: Path) -> None:
    s = Scope(_write_scope(tmp_path, "my-lab.local\n"))
    assert s.is_allowed("my-lab.local")
    assert s.is_allowed("MY-LAB.LOCAL")
    assert not s.is_allowed("other.local")


def test_comments_and_blank(tmp_path: Path) -> None:
    s = Scope(_write_scope(tmp_path, "# comment\n\n127.0.0.1\n  # indented\n"))
    assert s.is_allowed("127.0.0.1")
    assert not s.is_allowed("1.1.1.1")


def test_missing_file() -> None:
    with pytest.raises(ScopeError):
        Scope(Path("/nonexistent/scope.txt"))


def test_require_allowed_raises(tmp_path: Path) -> None:
    s = Scope(_write_scope(tmp_path, "127.0.0.1\n"))
    s.require_allowed("127.0.0.1")
    with pytest.raises(ScopeError):
        s.require_allowed("8.8.8.8")


def test_invalid_target(tmp_path: Path) -> None:
    s = Scope(_write_scope(tmp_path, "127.0.0.1\n"))
    assert not s.is_allowed("")
    assert not s.is_allowed("not-an-ip-or-hostname")

def test_cidr_target_matches_authorized_cidr(tmp_path: Path) -> None:
    """is_allowed() must accept a CIDR if it is contained in an authorized network."""
    s = Scope(_write_scope(tmp_path, "192.168.8.0/24\n"))
    assert s.is_allowed("192.168.8.0/24") is True
    assert s.is_allowed("192.168.8.128/25") is True   # narrower subnet
    assert s.is_allowed("192.168.0.0/16") is False    # broader than authorized
    assert s.is_allowed("10.0.0.0/8") is False


def test_cidr_target_via_single_ip_rule(tmp_path: Path) -> None:
    """A /32 or plain IP should still be allowed by prefix rule."""
    s = Scope(_write_scope(tmp_path, "10.0.0.5\n"))
    assert s.is_allowed("10.0.0.5") is True
    assert s.is_allowed("10.0.0.5/32") is True
    assert s.is_allowed("10.0.0.6") is False

