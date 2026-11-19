"""Tests for SF's local SQLite session store."""
import pytest

from sf_desktop.storage import SFStore, StoreError


def test_create_list_and_close_session(tmp_path):
    store = SFStore(tmp_path / "sf.sqlite3")
    created = store.create_session("تجربة محلية")
    listed = store.list_sessions()
    assert listed[0]["id"] == created["id"]
    assert listed[0]["status"] == "open"
    assert store.close_session(created["id"])
    assert store.list_sessions()[0]["status"] == "closed"


def test_evidence_is_structured_and_bounded(tmp_path):
    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("جلسة أدلة")
    evidence_id = store.add_evidence(
        session["id"],
        source="local-review",
        category="configuration",
        title="إعداد تجريبي",
        detail="معلومة محلية لا تتطلب اتصالاً.",
        confidence=0.8,
        payload={"key": "value"},
    )
    evidence = store.list_evidence(session["id"])
    assert evidence[0]["id"] == evidence_id
    assert evidence[0]["payload"] == {"key": "value"}
    with pytest.raises(ValueError):
        store.add_evidence(
            session["id"], source="x", category="x", title="x",
            detail="x", confidence=1.5,
        )


def test_reject_invalid_names_and_unknown_session(tmp_path):
    store = SFStore(tmp_path / "sf.sqlite3")
    with pytest.raises(ValueError):
        store.create_session("   ")
    with pytest.raises(StoreError):
        store.add_evidence(
            "nonexistent", source="x", category="x", title="x",
            detail="x", confidence=0.5,
        )


def test_reject_payload_over_limit(tmp_path):
    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("حجم")
    with pytest.raises(ValueError):
        store.add_evidence(
            session["id"], source="x", category="x", title="x",
            detail="x", confidence=0.5, payload={"large": "z" * 70000},
        )
