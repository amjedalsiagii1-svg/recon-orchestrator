"""Tests for core.cred_tester."""
import pytest
from core.cred_tester import DEFAULT_CREDS, MAX_ATTEMPTS, CredTestResult


def test_creds_present() -> None:
    assert ("admin", "admin") in DEFAULT_CREDS
    assert ("root", "root") in DEFAULT_CREDS
    assert len(DEFAULT_CREDS) >= 10


def test_max_attempts_capped() -> None:
    assert MAX_ATTEMPTS <= 15


def test_result_no_match() -> None:
    r = CredTestResult(url="http://x", testable=False)
    d = r.to_dict()
    assert d["matched"] is None
    assert d["attempts"] == 0


def test_result_matched() -> None:
    r = CredTestResult(url="http://x", matched=("admin", "admin"))
    d = r.to_dict()
    assert d["matched"]["user"] == "admin"
    assert d["matched"]["pass"] == "admin"


@pytest.mark.asyncio
async def test_closed_port_not_testable() -> None:
    from core.cred_tester import test_default_creds
    r = await test_default_creds("127.0.0.1", 1, timeout=0.3)
    assert r.testable is False
    assert r.matched is None
