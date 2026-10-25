"""Session persistence — SQLite with WAL mode."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    target TEXT,
    phase TEXT,
    data TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    phase TEXT,
    level TEXT,
    message TEXT,
    data TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Session:
    """Thin async wrapper around SQLite for one session."""

    def __init__(self, db: aiosqlite.Connection, session_id: str = "") -> None:
        self._db = db
        self.id = session_id

    @classmethod
    async def open(cls, db_path: str | Path = "data/sessions.db") -> "Session":
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(str(path))
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA foreign_keys=ON")
        await db.executescript(SCHEMA)
        await db.commit()
        return cls(db, session_id="")

    async def create(self, name: str = "session") -> str:
        sid = uuid.uuid4().hex[:12]
        now = _now()
        await self._db.execute(
            "INSERT INTO sessions (id, name, created_at, updated_at) VALUES (?,?,?,?)",
            (sid, name, now, now),
        )
        await self._db.commit()
        self.id = sid
        return sid

    async def get(self, session_id: str | None = None) -> dict[str, Any] | None:
        sid = session_id or self.id
        if not sid:
            return None
        cur = await self._db.execute("SELECT * FROM sessions WHERE id=?", (sid,))
        row = await cur.fetchone()
        if not row:
            return None
        cols = [c[0] for c in cur.description]
        await cur.close()
        return dict(zip(cols, row))

    async def set_target(self, target: str) -> None:
        await self._db.execute(
            "UPDATE sessions SET target=?, updated_at=? WHERE id=?",
            (target, _now(), self.id),
        )
        await self._db.commit()

    async def set_phase(self, phase: str, data: dict[str, Any] | None = None) -> None:
        payload = json.dumps(data) if data else None
        await self._db.execute(
            "UPDATE sessions SET phase=?, data=?, updated_at=? WHERE id=?",
            (phase, payload, _now(), self.id),
        )
        await self._db.commit()

    async def log_event(
        self,
        phase: str,
        level: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        await self._db.execute(
            "INSERT INTO events (session_id, ts, phase, level, message, data) VALUES (?,?,?,?,?,?)",
            (self.id, _now(), phase, level, message, json.dumps(data) if data else None),
        )
        await self._db.commit()

    async def list_events(self, phase: str | None = None) -> list[dict[str, Any]]:
        if phase:
            q = "SELECT * FROM events WHERE session_id=? AND phase=? ORDER BY id"
            args: tuple[Any, ...] = (self.id, phase)
        else:
            q = "SELECT * FROM events WHERE session_id=? ORDER BY id"
            args = (self.id,)
        cur = await self._db.execute(q, args)
        cols = [c[0] for c in cur.description]
        rows = await cur.fetchall()
        await cur.close()
        return [dict(zip(cols, r)) for r in rows]

    async def get_phase_data(self, phase: str) -> dict[str, Any] | None:
        """Fetch the most recent data payload for a phase from the events table.

        Unlike the `data` column (which is overwritten by each set_phase call),
        the events table preserves every phase's payload as an append-only log.
        This lets us retrieve p1/p2/p3... data even after later phases save.
        """
        cur = await self._db.execute(
            "SELECT data FROM events WHERE session_id=? AND phase=? "
            "AND data IS NOT NULL ORDER BY id DESC LIMIT 1",
            (self.id, phase),
        )
        row = await cur.fetchone()
        await cur.close()
        if not row or not row[0]:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None

    async def close(self) -> None:
        await self._db.close()

    async def __aenter__(self) -> "Session":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()
