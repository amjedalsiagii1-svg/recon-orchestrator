"""Tests for core.session (async)."""
from pathlib import Path

import pytest

from core.session import Session


@pytest.mark.asyncio
async def test_create_and_get(tmp_path: Path) -> None:
    db = tmp_path / "test.db"
    s = await Session.open(db)
    try:
        sid = await s.create("test session")
        assert sid and len(sid) == 12
        row = await s.get(sid)
        assert row is not None
        assert row["name"] == "test session"
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_set_target_and_phase(tmp_path: Path) -> None:
    s = await Session.open(tmp_path / "test.db")
    try:
        await s.create("t")
        await s.set_target("127.0.0.1")
        await s.set_phase("p4", {"ports": [22, 80]})
        row = await s.get()
        assert row is not None
        assert row["target"] == "127.0.0.1"
        assert row["phase"] == "p4"
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_log_event(tmp_path: Path) -> None:
    s = await Session.open(tmp_path / "test.db")
    try:
        await s.create("t")
        await s.log_event("p1", "info", "hello", {"x": 1})
        await s.log_event("p2", "warn", "world")
        events = await s.list_events()
        assert len(events) == 2
        assert events[0]["message"] == "hello"
        p2 = await s.list_events(phase="p2")
        assert len(p2) == 1
        assert p2[0]["level"] == "warn"
    finally:
        await s.close()

@pytest.mark.asyncio
async def test_get_phase_data_survives_overwrites(tmp_path: Path) -> None:
    """get_phase_data must NOT be affected by later set_phase calls."""
    s = await Session.open(tmp_path / "test.db")
    try:
        await s.create("t")
        p2_payload = {"devices": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]}
        await s.log_event("p2", "info", "discovered", p2_payload)
        await s.set_phase("p2", p2_payload)

        # Simulate Phase 3 overwriting the data column
        await s.set_phase("p3", {"ip": "10.0.0.1"})
        await s.log_event("p3", "info", "target", {"ip": "10.0.0.1"})

        p2 = await s.get_phase_data("p2")
        assert p2 is not None
        assert len(p2["devices"]) == 2
        assert p2["devices"][0]["ip"] == "10.0.0.1"

        p3 = await s.get_phase_data("p3")
        assert p3 is not None
        assert p3["ip"] == "10.0.0.1"

        assert await s.get_phase_data("p9") is None
    finally:
        await s.close()

