"""Local SQLite persistence for SF sessions and structured evidence.

No networking, scanning, shell commands, or report generation occurs here.
All SQL values are parameterized and evidence payloads are size-bounded.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_SESSION_NAME = 80
MAX_EVIDENCE_TITLE = 160
MAX_EVIDENCE_DETAIL = 4000
MAX_PAYLOAD_BYTES = 64 * 1024


class StoreError(RuntimeError):
    """Raised when local SF storage cannot complete an operation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_database_path() -> Path:
    configured = os.environ.get("XDG_DATA_HOME", "").strip()
    candidate = Path(configured).expanduser() if configured else None
    base = (
        candidate if candidate is not None and candidate.is_absolute()
        else Path.home() / ".local" / "share"
    )
    return base / "sf" / "sf.sqlite3"


class SFStore:
    """Small connection-per-operation SQLite store for the desktop app."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_database_path()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                self.path.parent.chmod(0o700)
            self._initialize()
        except (OSError, sqlite3.Error) as exc:
            raise StoreError(f"تعذر تهيئة قاعدة بيانات SF المحلية: {exc}") from exc

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open one connection, commit or roll back, and always close it."""
        connection = sqlite3.connect(self.path, timeout=5.0)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('open', 'closed')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
                    observed_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_sf_sessions_updated
                    ON sessions(updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_sf_evidence_session
                    ON evidence(session_id, id);
                """
            )
        if os.name == "posix" and self.path.exists():
            self.path.chmod(0o600)

    @staticmethod
    def _clean_text(value: str, field: str, maximum: int) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field}: يجب أن تكون القيمة نصاً")
        clean = value.strip()
        if not clean:
            raise ValueError(f"{field}: لا يمكن ترك الحقل فارغاً")
        if len(clean) > maximum:
            raise ValueError(f"{field}: تجاوز الحد الأقصى ({maximum} حرفاً)")
        if any(ord(char) < 32 and char not in "\t\n\r" for char in clean):
            raise ValueError(f"{field}: يحتوي النص على محارف تحكم غير مسموحة")
        return clean

    def create_session(self, name: str) -> dict[str, str]:
        clean_name = self._clean_text(name, "اسم الجلسة", MAX_SESSION_NAME)
        now = _now()
        record = {
            "id": uuid.uuid4().hex[:16],
            "name": clean_name,
            "status": "open",
            "created_at": now,
            "updated_at": now,
        }
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO sessions(id, name, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (record["id"], record["name"], record["status"],
                     record["created_at"], record["updated_at"]),
                )
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر حفظ الجلسة: {exc}") from exc
        return record

    def list_sessions(self, limit: int = 50) -> list[dict[str, str]]:
        if not isinstance(limit, int) or limit < 1 or limit > 1000:
            raise ValueError("حد عرض الجلسات يجب أن يكون بين 1 و1000")
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT id, name, status, created_at, updated_at "
                    "FROM sessions ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر قراءة الجلسات: {exc}") from exc

    def close_session(self, session_id: str) -> bool:
        clean_id = self._clean_text(session_id, "معرّف الجلسة", 32)
        try:
            with self._connect() as connection:
                result = connection.execute(
                    "UPDATE sessions SET status='closed', updated_at=? "
                    "WHERE id=? AND status='open'",
                    (_now(), clean_id),
                )
            return result.rowcount == 1
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر إغلاق الجلسة: {exc}") from exc

    def add_evidence(
        self,
        session_id: str,
        *,
        source: str,
        category: str,
        title: str,
        detail: str,
        confidence: float,
        payload: dict[str, Any] | None = None,
    ) -> int:
        clean_id = self._clean_text(session_id, "معرّف الجلسة", 32)
        clean_source = self._clean_text(source, "المصدر", 64)
        clean_category = self._clean_text(category, "الفئة", 64)
        clean_title = self._clean_text(title, "عنوان الدليل", MAX_EVIDENCE_TITLE)
        clean_detail = self._clean_text(detail, "تفاصيل الدليل", MAX_EVIDENCE_DETAIL)
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("مستوى الثقة يجب أن يكون رقماً بين 0 و1")
        if not 0 <= float(confidence) <= 1:
            raise ValueError("مستوى الثقة يجب أن يكون بين 0 و1")

        raw_payload = payload if payload is not None else {}
        if not isinstance(raw_payload, dict):
            raise ValueError("حمولة الدليل يجب أن تكون كائناً منظماً")
        try:
            payload_json = json.dumps(
                raw_payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"حمولة الدليل غير قابلة للتخزين: {exc}") from exc
        if len(payload_json.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError("حمولة الدليل أكبر من الحد المسموح")

        try:
            with self._connect() as connection:
                result = connection.execute(
                    """
                    INSERT INTO evidence(
                        session_id, source, category, title, detail,
                        confidence, observed_at, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (clean_id, clean_source, clean_category, clean_title,
                     clean_detail, float(confidence), _now(), payload_json),
                )
                connection.execute(
                    "UPDATE sessions SET updated_at=? WHERE id=?",
                    (_now(), clean_id),
                )
                if result.lastrowid is None:
                    raise StoreError("لم يتم إنشاء سجل الدليل")
                return int(result.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise StoreError("الجلسة غير موجودة أو لا يمكن ربط الدليل بها") from exc
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر حفظ الدليل: {exc}") from exc

    def list_evidence(self, session_id: str) -> list[dict[str, Any]]:
        clean_id = self._clean_text(session_id, "معرّف الجلسة", 32)
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT id, session_id, source, category, title, detail, "
                    "confidence, observed_at, payload_json "
                    "FROM evidence WHERE session_id=? ORDER BY id",
                    (clean_id,),
                ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                try:
                    item["payload"] = json.loads(item.pop("payload_json"))
                except (TypeError, json.JSONDecodeError):
                    item["payload"] = {}
                result.append(item)
            return result
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر قراءة الأدلة: {exc}") from exc
