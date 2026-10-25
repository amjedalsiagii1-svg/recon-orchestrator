"""Default credential testing — HTTP Basic Auth only (safe).

Safety:
  - Only tests HTTP Basic Auth (401 with WWW-Authenticate: Basic)
  - Never tests form login (to avoid CAPTCHA, lockouts, alerts)
  - Stops immediately on first match
  - Hard limit: 15 attempts per host
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, asdict
from typing import Any

import httpx


# Curated list — most common in real-world routers/IoT
DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", ""),
    ("root", "toor"),
    ("root", "admin"),
    ("root", "password"),
    ("user", "user"),
    ("guest", "guest"),
    ("cisco", "cisco"),
    ("support", "support"),
]

MAX_ATTEMPTS = 15


@dataclass
class CredTestResult:
    url: str
    auth_realm: str | None = None
    testable: bool = False
    matched: tuple[str, str] | None = None
    attempts: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "auth_realm": self.auth_realm,
            "testable": self.testable,
            "matched": {"user": self.matched[0], "pass": self.matched[1]}
                       if self.matched else None,
            "attempts": self.attempts,
            "error": self.error,
        }


async def _check_basic_auth(url: str, timeout: float) -> tuple[bool, str | None]:
    """Returns (testable, auth_realm)."""
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=False,
        ) as c:
            r = await c.get(url)
            if r.status_code != 401:
                return False, None
            auth = r.headers.get("www-authenticate", "").lower()
            if not auth.startswith("basic"):
                return False, None
            realm = ""
            if "realm=" in auth:
                realm = auth.split("realm=", 1)[1].strip('"').strip()
            return True, realm
    except Exception:
        return False, None


async def test_default_creds(
    target: str, port: int, path: str = "/", timeout: float = 3.0,
) -> CredTestResult:
    """Test default creds against an HTTP Basic Auth endpoint."""
    url = f"http://{target}:{port}{path}"
    result = CredTestResult(url=url)

    testable, realm = await _check_basic_auth(url, timeout)
    result.auth_realm = realm
    result.testable = testable
    if not testable:
        return result

    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=False,
    ) as c:
        for user, pwd in DEFAULT_CREDS[:MAX_ATTEMPTS]:
            result.attempts += 1
            try:
                r = await c.get(url, auth=(user, pwd))
                if r.status_code in (200, 301, 302, 303):
                    result.matched = (user, pwd)
                    return result
            except Exception:
                continue
    return result
