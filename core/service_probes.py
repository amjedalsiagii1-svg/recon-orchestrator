"""Service-specific probes — HTTP, HTTPS, SSH, FTP, SMTP, generic TCP.

All probes are READ-ONLY and safe:
  - HTTP GET / (no exploitation, no auth submission)
  - TLS handshake + cert inspection
  - TCP banner grab (SSH, FTP, SMTP)
No packets trigger exploits or config changes.
"""
from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass, field, asdict
from typing import Any

import httpx


_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

HTTP_PORTS = (80, 8000, 8080, 8888, 3000, 5000, 9000)
HTTPS_PORTS = (443, 8443)


@dataclass
class ProbeResult:
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    banner: str | None = None
    http_title: str | None = None
    http_server: str | None = None
    http_powered_by: str | None = None
    http_status: int | None = None
    http_redirect: str | None = None
    http_auth_realm: str | None = None
    http_cookies: list[dict] = field(default_factory=list)
    http_missing_headers: list[str] = field(default_factory=list)
    tls_version: str | None = None
    tls_subject: str | None = None
    tls_issuer: str | None = None
    tls_sans: list[str] = field(default_factory=list)
    tls_not_after: str | None = None
    tls_self_signed: bool = False
    ssh_version: str | None = None
    ftp_welcome: str | None = None
    smtp_banner: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _extract_cn(name_tuples) -> str | None:
    if not name_tuples:
        return None
    for rdn in name_tuples:
        for k, v in rdn:
            if k == "commonName":
                return v
    return None


async def _probe_http(target: str, port: int, timeout: float, tls: bool) -> ProbeResult:
    scheme = "https" if tls else "http"
    url = f"{scheme}://{target}:{port}/"
    result = ProbeResult(
        port=port, protocol="tcp",
        service="https" if tls else "http",
    )
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True, max_redirects=3,
        ) as client:
            r = await client.get(url)
            h = {k.lower(): v for k, v in r.headers.items()}
            result.http_status = r.status_code
            result.http_server = h.get("server")
            result.http_powered_by = h.get("x-powered-by")
            result.http_redirect = h.get("location")  # final redirect target
            result.http_auth_realm = h.get("www-authenticate")

            # title
            try:
                text = r.text[:4000]
                m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                if m:
                    result.http_title = re.sub(r"\s+", " ", m.group(1)).strip()[:150]
            except Exception:
                pass

            # cookies
            for ch in r.headers.get_list("set-cookie"):
                parts = [p.strip() for p in ch.split(";") if p.strip()]
                if not parts:
                    continue
                name = parts[0].split("=", 1)[0]
                info = {
                    "name": name,
                    "secure": any("secure" in p.lower() for p in parts[1:]),
                    "httponly": any("httponly" in p.lower() for p in parts[1:]),
                    "samesite": next(
                        (p.split("=", 1)[1] for p in parts[1:]
                         if p.lower().startswith("samesite")),
                        None,
                    ),
                }
                result.http_cookies.append(info)

            # missing security headers
            result.http_missing_headers = [x for x in _SECURITY_HEADERS if x not in h]

            # TLS (separate connection to read cert)
            if tls:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port, ssl=ctx, server_hostname=target),
                        timeout=timeout,
                    )
                    try:
                        ssl_obj = writer.get_extra_info("ssl_object")
                        if ssl_obj:
                            cert = ssl_obj.getpeercert() or {}
                            result.tls_version = ssl_obj.version()
                            result.tls_subject = _extract_cn(cert.get("subject", ()))
                            result.tls_issuer = _extract_cn(cert.get("issuer", ()))
                            result.tls_sans = [
                                v for k, v in cert.get("subjectAltName", ()) if k == "DNS"
                            ]
                            result.tls_not_after = cert.get("notAfter")
                            result.tls_self_signed = (
                                cert.get("subject") == cert.get("issuer")
                                and cert.get("subject") is not None
                            )
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                except Exception:
                    pass
    except httpx.TimeoutException:
        result.error = "timeout"
    except Exception as e:
        result.error = str(e)[:120]
    return result


async def _probe_tcp(target: str, port: int, timeout: float, service: str) -> ProbeResult:
    result = ProbeResult(port=port, protocol="tcp", service=service)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout,
        )
        try:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                if data:
                    banner = data.decode(errors="replace").strip()[:250]
                    result.banner = banner
            except asyncio.TimeoutError:
                pass

            if result.banner:
                if result.banner.startswith("SSH-"):
                    result.ssh_version = result.banner
                elif result.banner.startswith("220") and port == 21:
                    result.ftp_welcome = result.banner
                elif result.banner.startswith("220") and port in (25, 587):
                    result.smtp_banner = result.banner
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except asyncio.TimeoutError:
        result.error = "timeout"
    except Exception as e:
        result.error = str(e)[:120]
    return result


async def probe_port(target: str, port: int, service: str, timeout: float = 3.0) -> ProbeResult:
    """Dispatch based on port/service."""
    if port in HTTPS_PORTS or service in ("https", "ssl", "http-ssl"):
        return await _probe_http(target, port, timeout, tls=True)
    if port in HTTP_PORTS or service in ("http", "http-alt", "http-proxy"):
        return await _probe_http(target, port, timeout, tls=False)
    if port == 22 or service == "ssh":
        return await _probe_tcp(target, port, timeout, "ssh")
    if port == 21 or service == "ftp":
        return await _probe_tcp(target, port, timeout, "ftp")
    if port in (25, 587) or service == "smtp":
        return await _probe_tcp(target, port, timeout, "smtp")
    # generic banner grab
    return await _probe_tcp(target, port, timeout, service)


async def probe_ports_parallel(
    target: str, ports: list[dict], timeout: float = 3.0,
) -> list[ProbeResult]:
    """Probe all ports in parallel (non-blocking)."""
    if not ports:
        return []
    tasks = [
        probe_port(target, int(p["port"]), p.get("service", "unknown"), timeout)
        for p in ports if p.get("port")
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[ProbeResult] = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            p = ports[i]
            out.append(ProbeResult(
                port=int(p["port"]), service=p.get("service", "unknown"),
                error=str(r)[:120],
            ))
        else:
            out.append(r)
    return out
