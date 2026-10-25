"""Safe directory & path brute-force — read-only, parallel, capped."""
from __future__ import annotations

import asyncio
import hashlib
import secrets
from dataclasses import dataclass, field, asdict
from typing import Any

import httpx


# Curated list — high-signal paths only (~100), no dictionary spam
PATHS: list[str] = [
    # Admin panels
    "/admin/", "/admin/login", "/admin.php", "/administrator/",
    "/login", "/login.php", "/wp-admin/", "/wp-login.php",
    "/cgi-bin/", "/manager/html", "/console/",
    # Config leaks
    "/.env", "/.env.local", "/.env.backup", "/config.php", "/config.php.bak",
    "/config.json", "/config.yml", "/settings.xml", "/web.config",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    # Git / SVN
    "/.git/HEAD", "/.git/config", "/.git/logs/HEAD",
    "/.svn/entries", "/.hg/",
    # Backup / temp
    "/backup/", "/backup.zip", "/backup.tar.gz", "/dump.sql",
    "/database.sql", "/data.sql",
    "/index.php.bak", "/index.php~", "/index.php.swp",
    # Server info
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/test.php", "/apache-default/",
    # Actuator / Spring
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/heapdump", "/actuator/mappings",
    # API / Swagger
    "/api", "/api/v1", "/swagger", "/swagger-ui/", "/swagger-ui.html",
    "/v2/api-docs", "/openapi.json", "/graphql", "/graphiql",
    # Common CMS
    "/wp-content/", "/wp-json/", "/xmlrpc.php",
    "/joomla/", "/administrator/index.php",
    "/drupal/", "/user/login", "/modules/",
    # Misc
    "/.well-known/security.txt", "/.DS_Store", "/.htaccess",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/WEB-INF/web.xml", "/META-INF/",
    "/health", "/healthz", "/status", "/metrics",
    "/debug", "/trace", "/test", "/tmp", "/logs", "/log/",
    "/download/", "/uploads/", "/files/", "/static/", "/assets/",
]

MAX_CONCURRENT = 10
TIMEOUT = 3.0




@dataclass
class Baseline:
    """Fingerprint of a random 404 (or catch-all 200/301) response."""
    status: int = 0
    length: int = 0
    hash: str | None = None
    content_type: str | None = None
    redirect_location: str | None = None
    is_catchall: bool = False


async def _get_baseline(client: httpx.AsyncClient, base: str) -> Baseline:
    """Fetch random non-existent path to fingerprint server catch-all behavior."""
    rand_path = "/__xyz_nonexistent_" + secrets.token_hex(8) + "__"
    try:
        r = await client.get(base + rand_path)
        content_hash = hashlib.md5(r.content).hexdigest() if r.status_code == 200 else None
        loc = r.headers.get("location", "")
        # Catch-all includes: 200 (fake page), 301/302/303/307/308 (redirect-everything)
        return Baseline(
            status=r.status_code,
            length=len(r.content),
            hash=content_hash,
            content_type=r.headers.get("content-type", "").split(";")[0],
            redirect_location=loc,
            is_catchall=(r.status_code in (200, 301, 302, 303, 307, 308)),
        )
    except Exception:
        return Baseline()


def _is_baseline_hit(
    r: httpx.Response, baseline: Baseline,
    requested_path: str = "", base_url: str = "",
) -> bool:
    """True if response matches baseline catch-all pattern (false positive).

    Handles 3 common catch-all behaviors:
      A) 200 fake page (identical body hash or size)
      B) 3xx to fixed host (redirect to same external host for all paths)
      C) 3xx echo pattern (server redirects /foo → host/foo)
    """
    if not baseline.is_catchall:
        return False
    if r.status_code != baseline.status:
        return False

    # ── Case B/C: 3xx catch-all ──
    if baseline.redirect_location:
        r_loc = r.headers.get("location", "")
        if not r_loc:
            return False

        try:
            from urllib.parse import urlparse
            r_p = urlparse(r_loc)
            b_p = urlparse(baseline.redirect_location)
            req_host = (urlparse(base_url).hostname or "") if base_url else ""

            # Rule 1: exact same redirect target
            if r_loc == baseline.redirect_location:
                return True

            # Rule 2: ECHO pattern — server rewrites /X → host/X
            req_norm = requested_path if requested_path.startswith("/") else "/" + requested_path
            if r_p.path == req_norm:
                return True

            # Rule 3: redirect goes to a DIFFERENT host than requested,
            # but the same host as baseline → catch-all redirect server
            r_host = (r_p.hostname or "").lower()
            b_host = (b_p.hostname or "").lower()
            req_host_l = (req_host or "").lower()
            if r_host and b_host and r_host == b_host and r_host != req_host_l:
                return True

            # Rule 4: both redirect to same host root "/"
            if (r_p.netloc == b_p.netloc
                and r_p.path in ("", "/")
                and b_p.path in ("", "/")):
                return True
        except Exception:
            pass
        return False

    # ── Case A: 200 catch-all (fake page) ──
    if baseline.hash and hashlib.md5(r.content).hexdigest() == baseline.hash:
        return True
    if baseline.length > 0 and abs(len(r.content) - baseline.length) < 30:
        return True
    return False

# Expected content signatures for high-value paths (rejects HTML when text expected)
_CONTENT_EXPECTATIONS = {
    "/.env": {"content_types": ["text/plain", "application/octet-stream", ""],
              "must_contain_any": ["=", "KEY", "PASSWORD", "SECRET"],
              "must_not_contain": ["<html", "<!doctype", "<head", "<body"]},
    "/.git/HEAD": {"content_types": ["text/plain", "application/octet-stream", ""],
                   "must_contain_any": ["ref:", "commit", "branch"],
                   "must_not_contain": ["<html", "<!doctype", "<body"]},
    "/.git/config": {"content_types": ["text/plain", "application/octet-stream", ""],
                     "must_contain_any": ["[core]", "[remote", "repositoryformatversion"],
                     "must_not_contain": ["<html", "<!doctype", "<body"]},
    "/backup.zip": {"content_types": ["application/zip", "application/octet-stream"],
                    "must_contain_any": [], "must_not_contain": ["<html", "<!doctype"]},
    "/dump.sql": {"content_types": ["text/plain", "application/octet-stream", ""],
                  "must_contain_any": ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "--"],
                  "must_not_contain": ["<html", "<!doctype", "<body"]},
    "/actuator/env": {"content_types": ["application/json", "application/vnd.spring-boot.actuator.v3+json"],
                      "must_contain_any": ["{", "propertySources", "activeProfiles"],
                      "must_not_contain": ["<html", "<!doctype"]},
    "/phpinfo.php": {"content_types": ["text/html"],
                     "must_contain_any": ["PHP Version", "phpinfo()", "PHP Credits"],
                     "must_not_contain": []},
    "/server-status": {"content_types": ["text/html"],
                       "must_contain_any": ["Apache Server Status", "Server Version"],
                       "must_not_contain": []},
}


def _content_sanity_ok(path: str, body: bytes, content_type: str) -> bool:
    """Reject hits whose content doesn't match what the file type should look like."""
    rule = _CONTENT_EXPECTATIONS.get(path.lower())
    if not rule:
        return True  # no rule → accept
    ct_lower = content_type.lower()
    if rule["content_types"] and not any(exp in ct_lower for exp in rule["content_types"] if exp):
        return False
    body_lower = body[:4000].lower()
    must_contain = rule.get("must_contain_any") or []
    if must_contain and not any(sig.lower().encode() in body_lower for sig in must_contain):
        return False
    must_not = rule.get("must_not_contain") or []
    if any(sig.lower().encode() in body_lower for sig in must_not):
        return False
    return True


@dataclass
class DirHit:
    path: str
    status: int
    length: int = 0
    content_type: str | None = None
    is_redirect: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def _probe_path(
    client: httpx.AsyncClient, base: str, path: str, sem: asyncio.Semaphore,
    baseline: Baseline,
) -> DirHit | None:
    async with sem:
        try:
            r = await client.get(base + path)
            if r.status_code not in (200, 301, 302, 401, 403):
                return None
            # Filter 1: redirects to "/" (custom 404 rewrite)
            loc = r.headers.get("location", "")
            if r.status_code in (301, 302) and loc in ("/", ""):
                return None
            # Filter 2: identical to baseline (catch-all) → FALSE POSITIVE
            if _is_baseline_hit(r, baseline, requested_path=path, base_url=base):
                return None
            # Filter 3: content-type sanity for known sensitive files
            ct = r.headers.get("content-type", "").split(";")[0]
            if r.status_code == 200 and not _content_sanity_ok(path, r.content, ct):
                return None
            # Filter 4: 200 + empty body + trailing slash → likely fake
            if r.status_code == 200 and len(r.content) < 30 and path.endswith("/"):
                if "html" in ct.lower() and b"Index of" not in r.content[:500]:
                    return None
            return DirHit(
                path=path,
                status=r.status_code,
                length=len(r.content),
                content_type=ct,
                is_redirect=r.status_code in (301, 302),
            )
        except Exception:
            return None


async def brute_force(
    target: str, port: int, base_path: str = "/", timeout: float = TIMEOUT,
) -> list[DirHit]:
    """Parallel brute-force, capped. Returns only confirmed hits.

    Pre-step: fetch a random nonexistent path to fingerprint the server.
    If it returns 200 (catch-all), only hits with matching hash/length
    are rejected. Otherwise all 200s are presumed real.
    """
    base = f"http://{target}:{port}{base_path.rstrip('/')}"
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    hits: list[DirHit] = []
    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=False,
    ) as client:
        baseline = await _get_baseline(client, base)
        if baseline.is_catchall:
            print(f"[i] Server returns {baseline.status} for any path "
                  f"(len={baseline.length}). Filtering matches.")
        tasks = [_probe_path(client, base, p, sem, baseline) for p in PATHS]
        for r in await asyncio.gather(*tasks):
            if r:
                hits.append(r)
    return hits


# High-value paths (must be flagged HIGH/CRITICAL if found)
CRITICAL_PATHS = {
    "/.env", "/.env.local", "/.env.backup",
    "/.git/HEAD", "/.git/config",
    "/backup.zip", "/backup.tar.gz", "/dump.sql", "/database.sql",
    "/actuator/env", "/actuator/heapdump",
}
HIGH_PATHS = {
    "/phpinfo.php", "/info.php",
    "/config.php", "/config.php.bak", "/config.json",
    "/WEB-INF/web.xml",
    "/server-status", "/server-info",
    "/admin/", "/admin/login", "/wp-login.php",
    "/swagger-ui.html", "/v2/api-docs",
}
