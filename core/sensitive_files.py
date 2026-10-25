"""Classify discovered paths as vulnerabilities."""
from __future__ import annotations

from typing import Any

from core.dir_bruteforce import CRITICAL_PATHS, HIGH_PATHS, DirHit


# Match a path → (severity, title, description, remediation)
_PATTERNS: list[tuple[str, str, str, str, str]] = [
    # (substring, severity, title, desc, fix)
    (".env", "critical",
     "Exposed .env file",
     "Environment file with credentials, API keys, database passwords.",
     "Remove from web root, restrict access, rotate all exposed secrets."),
    (".git/", "critical",
     "Git repository exposed",
     "Full source code + commit history readable. May contain secrets.",
     "Disable .git/ in web root via server config."),
    (".svn/", "high",
     "Subversion repository exposed",
     "Source code and history exposed.",
     "Block .svn/ in web server config."),
    ("backup.zip", "critical",
     "Backup archive exposed",
     "Full backup archive downloadable — likely contains config + DB.",
     "Remove backup from web root; store off-server."),
    ("dump.sql", "critical",
     "SQL dump exposed",
     "Database dump downloadable — full data breach.",
     "Remove from web root; use secure storage."),
    ("database.sql", "critical",
     "Database dump exposed", "Database dump downloadable.",
     "Remove from web root."),
    ("phpinfo.php", "high",
     "phpinfo() exposed",
     "Full PHP configuration, paths, server info disclosed.",
     "Remove phpinfo.php; disable in production."),
    ("info.php", "high", "phpinfo() exposed",
     "Full PHP configuration disclosed.", "Remove file."),
    ("actuator/env", "critical",
     "Spring Boot /actuator/env exposed",
     "Environment variables including secrets may be readable.",
     "Restrict actuator endpoints; enable auth."),
    ("actuator/heapdump", "critical",
     "Spring Boot /actuator/heapdump exposed",
     "Full JVM heap downloadable — memory contains secrets.",
     "Restrict actuator; enable auth."),
    ("server-status", "high",
     "Apache /server-status exposed",
     "Active HTTP requests and internal IPs disclosed.",
     "Require auth for /server-status."),
    ("server-info", "high",
     "Apache /server-info exposed",
     "Server configuration disclosed.", "Require auth."),
    ("config.php", "high",
     "PHP config file exposed",
     "Configuration file readable — may contain DB credentials.",
     "Move outside web root."),
    ("web.config", "high",
     "Web.config exposed",
     "IIS configuration disclosed.",
     "Restrict web.config access."),
    ("WEB-INF/web.xml", "high",
     "WEB-INF/web.xml exposed",
     "Java web app descriptor readable.",
     "Block WEB-INF/ in web server config."),
    ("swagger-ui", "medium",
     "Swagger UI exposed",
     "API documentation reachable — full endpoint map.",
     "Restrict to internal networks."),
    ("/admin/", "medium",
     "Admin panel found",
     "Administrative interface is publicly reachable.",
     "Restrict by IP or require strong auth."),
    ("/admin/login", "medium",
     "Admin login page found",
     "Admin login form accessible.",
     "Restrict by IP or require strong auth."),
    ("wp-login.php", "medium",
     "WordPress login exposed",
     "WordPress admin login publicly reachable.",
     "Restrict by IP; add 2FA; use security plugin."),
    ("swagger", "medium",
     "Swagger docs exposed", "API docs reachable.", "Restrict."),
    ("robots.txt", "info",
     "robots.txt present", "May reveal hidden paths.",
     "Review robots.txt for sensitive paths."),
    ("/.htaccess", "high",
     ".htaccess exposed",
     "Apache config file readable — may reveal rewrite rules.",
     "Block .htaccess from serving."),
    (".DS_Store", "low",
     ".DS_Store exposed",
     "macOS metadata — may reveal directory structure.",
     "Block .DS_Store in web server."),
]


def classify(hit: DirHit, base_url: str) -> dict[str, Any] | None:
    """Classify a DirHit into a vuln record."""
    p = hit.path.lower()

    # 401 / 403 → just info (endpoint exists but protected)
    if hit.status in (401, 403):
        return {
            "id": f"PATH-{p.strip('/').replace('/', '-')[:30]}",
            "severity": "info",
            "title": f"Endpoint exists: {hit.path}",
            "description": f"HTTP {hit.status} — protected but visible.",
            "remediation": "Ensure proper access control on this path.",
            "url": base_url + hit.path,
        }

    # 200 → check known patterns
    for substring, severity, title, desc, fix in _PATTERNS:
        if substring in p:
            return {
                "id": f"PATH-{p.strip('/').replace('/', '-').replace('.', '_')[:30]}",
                "severity": severity,
                "title": title,
                "description": desc,
                "remediation": fix,
                "url": base_url + hit.path,
            }

    # Generic discovery (200, but not in pattern list) → low
    if hit.status == 200:
        return {
            "id": f"PATH-{p.strip('/').replace('/', '-').replace('.', '_')[:30]}",
            "severity": "low",
            "title": f"Path reachable: {hit.path}",
            "description": f"HTTP 200 — {hit.length} bytes.",
            "remediation": "Review whether this path should be public.",
            "url": base_url + hit.path,
        }
    return None
