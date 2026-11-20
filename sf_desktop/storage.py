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
                CREATE TABLE IF NOT EXISTS imports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    source_type TEXT NOT NULL DEFAULT 'file'
                        CHECK(source_type IN ('file', 'local-readonly')),
                    sha256 TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    asset_count INTEGER NOT NULL,
                    service_count INTEGER NOT NULL,
                    skipped_host_count INTEGER NOT NULL,
                    authorization_confirmed INTEGER NOT NULL DEFAULT 0
                        CHECK(authorization_confirmed IN (0, 1)),
                    authorization_recorded_at TEXT,
                    UNIQUE(session_id, sha256),
                    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    mac TEXT,
                    vendor TEXT,
                    state TEXT NOT NULL DEFAULT 'up',
                    source_import_id INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(session_id, ip),
                    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                    FOREIGN KEY(source_import_id) REFERENCES imports(id)
                );

                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
                    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
                    state TEXT NOT NULL,
                    name TEXT,
                    product TEXT,
                    version TEXT,
                    extra_info TEXT,
                    source_import_id INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(asset_id, protocol, port),
                    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                    FOREIGN KEY(source_import_id) REFERENCES imports(id)
                );

                CREATE INDEX IF NOT EXISTS idx_sf_imports_session
                    ON imports(session_id, imported_at DESC);
                CREATE INDEX IF NOT EXISTS idx_sf_assets_session
                    ON assets(session_id, ip);
                CREATE INDEX IF NOT EXISTS idx_sf_services_asset
                    ON services(asset_id, protocol, port);
                """
            )
            # Forward-compatible additive migration for databases created by
            # an earlier SF development build.
            import_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(imports)")
            }
            if "source_type" not in import_columns:
                connection.execute(
                    "ALTER TABLE imports ADD COLUMN source_type "
                    "TEXT NOT NULL DEFAULT 'file'"
                )
            if "authorization_confirmed" not in import_columns:
                connection.execute(
                    "ALTER TABLE imports ADD COLUMN authorization_confirmed "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            if "authorization_recorded_at" not in import_columns:
                connection.execute(
                    "ALTER TABLE imports ADD COLUMN authorization_recorded_at TEXT"
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

    def get_session(self, session_id: str) -> dict[str, str] | None:
        """Return one session by its opaque local identifier."""
        clean_id = self._clean_text(session_id, "معرّف الجلسة", 32)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT id, name, status, created_at, updated_at "
                    "FROM sessions WHERE id=?",
                    (clean_id,),
                ).fetchone()
            return dict(row) if row else None
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر قراءة الجلسة: {exc}") from exc

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

    def import_inventory(
        self,
        session_id: str,
        *,
        source_name: str,
        sha256: str,
        assets: list[dict[str, Any]],
        services: list[dict[str, Any]],
        skipped_host_count: int = 0,
        authorization_confirmed: bool = False,
        source_type: str = "file",
    ) -> dict[str, Any]:
        """Store previously collected inventory with explicit provenance."""
        if source_type not in {"file", "local-readonly"}:
            raise ValueError("نوع مصدر البيانات غير مدعوم")
        if source_type == "file" and authorization_confirmed is not True:
            raise ValueError(
                "يلزم تأكيد صريح بأنك تملك النطاق أو لديك تفويض مكتوب لتقييمه"
            )
        if source_type == "local-readonly" and authorization_confirmed:
            raise ValueError("التحليل المحلي لا يستخدم تأكيد تفويض شبكة")
        import ipaddress
        import re

        clean_id = self._clean_text(session_id, "معرّف الجلسة", 32)
        clean_source = self._clean_text(Path(source_name).name, "اسم المصدر", 200)
        digest = (sha256 or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("بصمة SHA-256 غير صالحة")
        if not isinstance(assets, list) or not assets or len(assets) > 256:
            raise ValueError("يجب أن يحتوي الاستيراد على أصل واحد على الأقل وبحد أقصى 256 أصلاً")
        if not isinstance(services, list) or len(services) > 5000:
            raise ValueError("عدد الخدمات يتجاوز الحد المسموح (5000)")
        if isinstance(skipped_host_count, bool) or not isinstance(skipped_host_count, int) or skipped_host_count < 0:
            raise ValueError("عدد الأجهزة المستبعدة غير صالح")

        def optional_text(value: Any, field: str, maximum: int) -> str | None:
            if value is None or value == "":
                return None
            if not isinstance(value, str):
                raise ValueError(f"{field}: يجب أن تكون القيمة نصاً")
            clean = value.strip()
            if len(clean) > maximum:
                raise ValueError(f"{field}: تجاوز الحد الأقصى ({maximum} حرفاً)")
            if any(ord(ch) < 32 for ch in clean):
                raise ValueError(f"{field}: يحتوي محارف تحكم غير مسموحة")
            return clean or None

        normalized_assets: dict[str, dict[str, Any]] = {}
        for item in assets:
            if not isinstance(item, dict):
                raise ValueError("بنية الأصل المستورد غير صالحة")
            try:
                ip_value = str(ipaddress.ip_address(item.get("ip", "")))
            except ValueError as exc:
                raise ValueError("يحتوي الاستيراد على عنوان IP غير صالح") from exc
            mac = optional_text(item.get("mac"), "MAC", 17)
            if mac and not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                raise ValueError("عنوان MAC غير صالح")
            state = optional_text(item.get("state", "up"), "حالة الأصل", 20) or "unknown"
            if state not in {"up", "down", "unknown"}:
                raise ValueError("حالة الأصل غير مدعومة")
            normalized_assets[ip_value] = {
                "ip": ip_value,
                "hostname": optional_text(item.get("hostname"), "اسم المضيف", 253),
                "mac": mac.lower() if mac else None,
                "vendor": optional_text(item.get("vendor"), "الشركة المصنّعة", 120),
                "state": state,
            }
        if len(normalized_assets) != len(assets):
            # Multiple rows for the same address are ambiguous; reject rather than silently overwrite.
            raise ValueError("يتكرر عنوان IP داخل قائمة الأصول")

        normalized_services: list[dict[str, Any]] = []
        seen_services: set[tuple[str, str, int]] = set()
        allowed_states = {
            "open", "closed", "filtered", "open|filtered", "unfiltered",
            "unknown", "listening", "bound",
        }
        for item in services:
            if not isinstance(item, dict):
                raise ValueError("بنية الخدمة المستوردة غير صالحة")
            try:
                ip_value = str(ipaddress.ip_address(item.get("ip", "")))
            except ValueError as exc:
                raise ValueError("تحتوي خدمة مستوردة على عنوان IP غير صالح") from exc
            if ip_value not in normalized_assets:
                raise ValueError("الخدمة مرتبطة بأصل غير موجود في ملف الاستيراد")
            protocol = str(item.get("protocol", "")).lower()
            if protocol not in {"tcp", "udp"}:
                raise ValueError("بروتوكول الخدمة يجب أن يكون TCP أو UDP")
            port = item.get("port")
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("رقم منفذ الخدمة غير صالح")
            state = optional_text(item.get("state", "unknown"), "حالة المنفذ", 24) or "unknown"
            if state not in allowed_states:
                raise ValueError("حالة المنفذ غير مدعومة")
            key = (ip_value, protocol, port)
            if key in seen_services:
                raise ValueError("تتكرر خدمة على نفس الأصل والبروتوكول والمنفذ")
            seen_services.add(key)
            normalized_services.append({
                "ip": ip_value,
                "protocol": protocol,
                "port": port,
                "state": state,
                "name": optional_text(item.get("name"), "اسم الخدمة", 120),
                "product": optional_text(item.get("product"), "المنتج", 160),
                "version": optional_text(item.get("version"), "الإصدار", 120),
                "extra_info": optional_text(item.get("extra_info"), "معلومات إضافية", 500),
            })

        now = _now()
        try:
            with self._connect() as connection:
                session = connection.execute(
                    "SELECT status FROM sessions WHERE id=?", (clean_id,)
                ).fetchone()
                if session is None:
                    raise StoreError("الجلسة المطلوبة غير موجودة")
                if session["status"] != "open":
                    raise StoreError("لا يمكن استيراد بيانات إلى جلسة مغلقة")

                duplicate = connection.execute(
                    "SELECT id, asset_count, service_count, skipped_host_count, "
                    "authorization_confirmed, authorization_recorded_at, source_type "
                    "FROM imports WHERE session_id=? AND sha256=?",
                    (clean_id, digest),
                ).fetchone()
                if duplicate:
                    return {
                        "duplicate": True,
                        "import_id": int(duplicate["id"]),
                        "asset_count": int(duplicate["asset_count"]),
                        "service_count": int(duplicate["service_count"]),
                        "skipped_host_count": int(duplicate["skipped_host_count"]),
                        "authorization_confirmed": bool(duplicate["authorization_confirmed"]),
                        "authorization_recorded_at": duplicate["authorization_recorded_at"],
                        "source_type": duplicate["source_type"],
                        "source_name": clean_source,
                    }

                cursor = connection.execute(
                    "INSERT INTO imports(session_id, source_name, source_type, sha256, imported_at, "
                    "asset_count, service_count, "
                    "skipped_host_count, authorization_confirmed, authorization_recorded_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (clean_id, clean_source, source_type, digest, now,
                     len(normalized_assets), len(normalized_services), skipped_host_count,
                     1 if source_type == "file" else 0, now if source_type == "file" else None),
                )
                import_id = int(cursor.lastrowid)
                asset_ids: dict[str, int] = {}
                for ip_value, item in normalized_assets.items():
                    existing = connection.execute(
                        "SELECT id, first_seen FROM assets WHERE session_id=? AND ip=?",
                        (clean_id, ip_value),
                    ).fetchone()
                    if existing:
                        asset_id = int(existing["id"])
                        connection.execute(
                            "UPDATE assets SET hostname=COALESCE(?, hostname), "
                            "mac=COALESCE(?, mac), vendor=COALESCE(?, vendor), "
                            "state=?, source_import_id=?, last_seen=? WHERE id=?",
                            (item["hostname"], item["mac"], item["vendor"], item["state"],
                             import_id, now, asset_id),
                        )
                    else:
                        asset_cursor = connection.execute(
                            "INSERT INTO assets(session_id, ip, hostname, mac, vendor, state, "
                            "source_import_id, first_seen, last_seen) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (clean_id, ip_value, item["hostname"], item["mac"],
                             item["vendor"], item["state"], import_id, now, now),
                        )
                        asset_id = int(asset_cursor.lastrowid)
                    asset_ids[ip_value] = asset_id

                for item in normalized_services:
                    asset_id = asset_ids[item["ip"]]
                    existing = connection.execute(
                        "SELECT id FROM services WHERE asset_id=? AND protocol=? AND port=?",
                        (asset_id, item["protocol"], item["port"]),
                    ).fetchone()
                    if existing:
                        connection.execute(
                            "UPDATE services SET state=?, name=COALESCE(?, name), "
                            "product=COALESCE(?, product), version=COALESCE(?, version), "
                            "extra_info=COALESCE(?, extra_info), source_import_id=?, last_seen=? "
                            "WHERE id=?",
                            (item["state"], item["name"], item["product"], item["version"],
                             item["extra_info"], import_id, now, int(existing["id"])),
                        )
                    else:
                        connection.execute(
                            "INSERT INTO services(asset_id, protocol, port, state, name, "
                            "product, version, extra_info, source_import_id, first_seen, last_seen) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (asset_id, item["protocol"], item["port"], item["state"],
                             item["name"], item["product"], item["version"],
                             item["extra_info"], import_id, now, now),
                        )
                connection.execute(
                    "UPDATE sessions SET updated_at=? WHERE id=?", (now, clean_id)
                )
            return {
                "duplicate": False,
                "import_id": import_id,
                "asset_count": len(normalized_assets),
                "service_count": len(normalized_services),
                "skipped_host_count": skipped_host_count,
                "authorization_confirmed": source_type == "file",
                "authorization_recorded_at": now if source_type == "file" else None,
                "source_type": source_type,
                "source_name": clean_source,
            }
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"تعارض في بيانات الأصول والخدمات: {exc}") from exc
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر حفظ الاستيراد: {exc}") from exc

    def list_assets(self, session_id: str) -> list[dict[str, Any]]:
        clean_id = self._clean_text(session_id, "معرّف الجلسة", 32)
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT a.id, a.session_id, a.ip, a.hostname, a.mac, a.vendor, "
                    "a.state, a.first_seen, a.last_seen, i.source_name, i.source_type, "
                    "(SELECT COUNT(*) FROM services s WHERE s.asset_id=a.id) AS service_count "
                    "FROM assets a JOIN imports i ON i.id=a.source_import_id "
                    "WHERE a.session_id=? ORDER BY a.ip",
                    (clean_id,),
                ).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر قراءة سجل الأصول: {exc}") from exc

    def list_services(self, session_id: str) -> list[dict[str, Any]]:
        clean_id = self._clean_text(session_id, "معرّف الجلسة", 32)
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT s.id, a.ip, a.hostname, s.protocol, s.port, s.state, "
                    "s.name, s.product, s.version, s.extra_info, s.first_seen, "
                    "s.last_seen, i.source_name, i.source_type "
                    "FROM services s JOIN assets a ON a.id=s.asset_id "
                    "JOIN imports i ON i.id=s.source_import_id "
                    "WHERE a.session_id=? ORDER BY a.ip, s.protocol, s.port",
                    (clean_id,),
                ).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر قراءة سجل الخدمات: {exc}") from exc

    def list_imports(self, session_id: str) -> list[dict[str, Any]]:
        clean_id = self._clean_text(session_id, "معرّف الجلسة", 32)
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT id, source_name, source_type, sha256, imported_at, asset_count, "
                    "service_count, skipped_host_count, authorization_confirmed, "
                    "authorization_recorded_at FROM imports "
                    "WHERE session_id=? ORDER BY imported_at DESC",
                    (clean_id,),
                ).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise StoreError(f"تعذر قراءة سجل الاستيرادات: {exc}") from exc

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
