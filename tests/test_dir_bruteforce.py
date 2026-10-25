"""Tests for dir_bruteforce + sensitive_files."""
import pytest
from core.dir_bruteforce import PATHS, DirHit, CRITICAL_PATHS, HIGH_PATHS
from core.sensitive_files import classify


def test_paths_include_high_signal() -> None:
    assert "/.env" in PATHS
    assert "/.git/HEAD" in PATHS
    assert "/admin/" in PATHS
    assert len(PATHS) >= 50


def test_critical_paths() -> None:
    assert "/.env" in CRITICAL_PATHS
    assert "/.git/HEAD" in CRITICAL_PATHS


def test_classify_env_critical() -> None:
    hit = DirHit(path="/.env", status=200, length=500)
    c = classify(hit, "http://10.0.0.1:80")
    assert c is not None
    assert c["severity"] == "critical"


def test_classify_git_critical() -> None:
    hit = DirHit(path="/.git/HEAD", status=200, length=20)
    c = classify(hit, "http://10.0.0.1:80")
    assert c is not None
    assert c["severity"] == "critical"


def test_classify_admin_medium() -> None:
    hit = DirHit(path="/admin/", status=200, length=1000)
    c = classify(hit, "http://10.0.0.1:80")
    assert c is not None
    assert c["severity"] == "medium"


def test_classify_403_is_info() -> None:
    hit = DirHit(path="/admin/", status=403)
    c = classify(hit, "http://10.0.0.1:80")
    assert c is not None
    assert c["severity"] == "info"


def test_classify_unknown_path() -> None:
    hit = DirHit(path="/whatever", status=200, length=100)
    c = classify(hit, "http://10.0.0.1:80")
    assert c is not None
    assert c["severity"] == "low"


def test_classify_redirect_ignored() -> None:
    hit = DirHit(path="/redir", status=301, length=0)
    c = classify(hit, "http://10.0.0.1:80")
    assert c is None or c["severity"] == "info"


@pytest.mark.asyncio
async def test_brute_force_closed_port() -> None:
    from core.dir_bruteforce import brute_force
    hits = await brute_force("127.0.0.1", 1, timeout=0.2)
    assert hits == []
