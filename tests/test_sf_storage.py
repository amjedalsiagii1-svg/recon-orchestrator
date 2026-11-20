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

def test_inventory_import_is_scoped_deduplicated_and_queryable(tmp_path):
    import hashlib

    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("جلسة أصول")
    assets = [{
        "ip": "192.168.8.10", "hostname": "device.local",
        "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Example", "state": "up",
    }]
    services = [{
        "ip": "192.168.8.10", "protocol": "tcp", "port": 22,
        "state": "open", "name": "ssh", "product": "OpenSSH",
        "version": "9.2", "extra_info": None,
    }]
    digest = hashlib.sha256(b"source").hexdigest()
    result = store.import_inventory(
        session["id"], source_name="sample.xml", sha256=digest,
        assets=assets, services=services, skipped_host_count=1,
        authorization_confirmed=True,
    )
    assert result["duplicate"] is False
    assert len(store.list_assets(session["id"])) == 1
    assert len(store.list_services(session["id"])) == 1
    assert store.list_services(session["id"])[0]["port"] == 22

    duplicate = store.import_inventory(
        session["id"], source_name="renamed.xml", sha256=digest,
        assets=assets, services=services, authorization_confirmed=True,
    )
    assert duplicate["duplicate"] is True
    assert len(store.list_assets(session["id"])) == 1
    assert len(store.list_imports(session["id"])) == 1


def test_inventory_rejects_closed_session_and_invalid_data(tmp_path):
    import hashlib
    import pytest

    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("مغلقة")
    store.close_session(session["id"])
    digest = hashlib.sha256(b"x").hexdigest()
    with pytest.raises(StoreError, match="مغلقة"):
        store.import_inventory(
            session["id"], source_name="x.xml", sha256=digest,
            assets=[{"ip": "192.168.8.10"}], services=[],
            authorization_confirmed=True,
        )



def test_inventory_import_requires_explicit_authorization_confirmation(tmp_path):
    import hashlib
    import pytest

    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("تأكيد مطلوب")
    with pytest.raises(ValueError, match="تأكيد صريح"):
        store.import_inventory(
            session["id"],
            source_name="source.xml",
            sha256=hashlib.sha256(b"source").hexdigest(),
            assets=[{"ip": "192.168.8.10"}],
            services=[],
        )



def test_local_readonly_snapshot_does_not_require_network_authorization(tmp_path):
    import hashlib

    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("تحليل محلي")
    result = store.import_inventory(
        session["id"],
        source_name="قراءة محلية لجهاز Kali",
        source_type="local-readonly",
        sha256=hashlib.sha256(b"local-snapshot").hexdigest(),
        assets=[{
            "ip": "192.168.8.20",
            "hostname": "kali",
            "mac": "aa:bb:cc:dd:ee:20",
            "state": "up",
        }],
        services=[{
            "ip": "192.168.8.20",
            "protocol": "tcp",
            "port": 631,
            "state": "listening",
            "name": "مستمع TCP محلي",
            "extra_info": "127.0.0.1",
        }],
        authorization_confirmed=False,
    )
    assert result["source_type"] == "local-readonly"
    assert result["authorization_confirmed"] is False
    assert store.list_assets(session["id"])[0]["source_type"] == "local-readonly"
    assert store.list_services(session["id"])[0]["state"] == "listening"
    assert store.list_imports(session["id"])[0]["source_type"] == "local-readonly"


def test_local_snapshot_rejects_network_authorization_flag(tmp_path):
    import hashlib
    import pytest

    store = SFStore(tmp_path / "sf.sqlite3")
    session = store.create_session("مصدر محلي")
    with pytest.raises(ValueError, match="لا يستخدم تأكيد تفويض شبكة"):
        store.import_inventory(
            session["id"],
            source_name="قراءة محلية",
            source_type="local-readonly",
            sha256=hashlib.sha256(b"local").hexdigest(),
            assets=[{"ip": "127.0.0.1"}],
            services=[],
            authorization_confirmed=True,
        )
