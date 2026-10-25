"""Phase 1 — Network type detection.

Detects:
  - Captive portal (HTTP 302 vs expected 204)
  - MITM / TLS interception (cert issuer sanity)
  - Hotspot (Android tethering common subnets)
  - Network classification: home_router / commercial / hotspot / unknown

Pure stdlib + httpx. No nmcli/iw/capdet needed. Termux-friendly.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import httpx


# ---------- data types ----------

@dataclass
class NetworkInfo:
    local_ips: list[str] = field(default_factory=list)
    default_gateway: str | None = None
    default_iface: str | None = None
    subnet_hint: str | None = None


@dataclass
class CaptiveCheck:
    status: int | None = None
    redirected: bool = False
    location: str | None = None
    error: str | None = None


@dataclass
class TLSCheck:
    connected: bool = False
    issuer_cn: str | None = None
    subject_cn: str | None = None
    is_suspicious: bool = False
    error: str | None = None


@dataclass
class Classification:
    type: str = "unknown"   # home_router | commercial | hotspot | unknown
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)


@dataclass
class Phase1Result:
    network: NetworkInfo
    captive: CaptiveCheck
    tls: TLSCheck
    dns_ok: bool
    classification: Classification
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": asdict(self.network),
            "captive": asdict(self.captive),
            "tls": asdict(self.tls),
            "dns_ok": self.dns_ok,
            "classification": asdict(self.classification),
            "extra": self.extra,
        }


# ---------- helpers ----------

def _read_proc_route() -> tuple[str | None, str | None]:
    """Try multiple methods to find default gateway + iface (Termux-friendly)."""
    import re
    import subprocess

    # Method 1: `ip route show default`
    for cmd in (["ip", "route", "show", "default"], ["ip", "-4", "route"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+) dev (\S+)", r.stdout)
            if m:
                return m.group(1), m.group(2)
        except Exception:
            pass

    # Method 2: Termux getprop (Android-specific)
    for prop in ("dhcp.wlan0.gateway", "dhcp.eth0.gateway", "net.dns1"):
        try:
            r = subprocess.run(["getprop", prop], capture_output=True, text=True, timeout=1)
            val = r.stdout.strip()
            if val and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", val):
                return val, None
        except Exception:
            pass

    # Method 3: /proc/net/route (Linux classic)
    route = Path("/proc/net/route")
    if route.exists():
        try:
            lines = route.read_text(encoding="utf-8").splitlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 3:
                    continue
                iface, dest_hex, gw_hex = parts[0], parts[1], parts[2]
                if dest_hex != "00000000":
                    continue
                try:
                    gw_int = int(gw_hex, 16)
                    gw = ".".join(str((gw_int >> sh) & 0xFF) for sh in (0, 8, 16, 24))
                    if gw != "0.0.0.0":
                        return gw, iface
                except Exception:
                    continue
        except Exception:
            pass

    # Method 4: derive .1 from local IP (best-effort guess)
    ips = _local_ips()
    if ips:
        try:
            parts = ips[0].split(".")
            if len(parts) == 4:
                return ".".join(parts[:3] + ["1"]), None
        except Exception:
            pass
    return None, None


def _local_ips() -> list[str]:
    """Get local non-loopback IPv4/IPv6 addresses (best-effort)."""
    ips: list[str] = []
    try:
        # primary trick: UDP socket to public IP never sends packets
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        try:
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip.startswith("127.") or ip == "::1":
                continue
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _guess_subnet(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return f"{addr}/24"
        return f"{addr}/64"
    except Exception:
        return None


def _detect_iface() -> str | None:
    """Get interface name using network_classifier (better fallbacks)."""
    try:
        from core.network_classifier import _read_interface
        return _read_interface()
    except Exception:
        # Fallback to old method
        _, iface = _read_proc_route()
        return iface


def gather_network_info() -> NetworkInfo:
    gw, iface = _read_proc_route()
    if not iface:
        iface = _detect_iface()
    ips = _local_ips()
    return NetworkInfo(
        local_ips=ips,
        default_gateway=gw,
        default_iface=iface,
        subnet_hint=_guess_subnet(ips[0]) if ips else None,
    )


# ---------- probes ----------

_CAPTIVE_URL = "http://connectivitycheck.gstatic.com/generate_204"
_DNS_HOST = "example.com"
_TLS_HOST = "www.google.com"
_TLS_PORT = 443


async def check_captive_portal(timeout: float = 3.0) -> CaptiveCheck:
    """Hit the Android/iOS captive-portal probe. Expected: HTTP 204."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as c:
            r = await c.get(_CAPTIVE_URL)
            return CaptiveCheck(
                status=r.status_code,
                redirected=(300 <= r.status_code < 400),
                location=r.headers.get("location"),
            )
    except httpx.TimeoutException:
        return CaptiveCheck(error="timeout")
    except Exception as e:
        return CaptiveCheck(error=str(e))


async def check_dns(timeout: float = 2.0) -> bool:
    """Try resolving multiple hostnames via getaddrinfo with a hard timeout."""
    def _resolve_one(host: str) -> bool:
        try:
            socket.getaddrinfo(host, 80)
            return True
        except Exception:
            return False

    for host in ("one.one.one.one", "example.com", "google.com", "cloudflare.com"):
        try:
            ok = await asyncio.wait_for(asyncio.to_thread(_resolve_one, host), timeout=timeout)
            if ok:
                return True
        except (asyncio.TimeoutError, Exception):
            continue
    return False


_TRUSTED_ISSUER_HINTS = (
    "let's encrypt",
    "digicert",
    "globalsign",
    "google trust services",
    "gts ca",
    "amazon",
    "cloudflare",
    "sectigo",
    "comodo",
    "entrust",
    "godaddy",
    "microsoft",
    "apple",
    "isrg",
    # Google Trust Services short codes (real issuer CNs on live certs)
    "we1", "we2", "we3", "we4", "wr1", "wr2", "wr3",
    # Let's Encrypt short codes
    "r3", "r4", "r10", "r11", "e1", "e2", "e5", "e6",
)


def _issuer_cn(cert: dict) -> str:
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return ""


async def check_tls(timeout: float = 3.0) -> TLSCheck:
    """Connect to a known host and inspect cert issuer."""
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(_TLS_HOST, _TLS_PORT, ssl=ctx, server_hostname=_TLS_HOST),
            timeout=timeout,
        )
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert() if ssl_obj else {}
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        issuer = _issuer_cn(cert or {})
        subject = ""
        for rdn in (cert or {}).get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    subject = value
        suspicious = True
        low = (issuer or "").lower()
        for hint in _TRUSTED_ISSUER_HINTS:
            if hint in low or low == hint:
                suspicious = False
                break
        return TLSCheck(
            connected=True,
            issuer_cn=issuer,
            subject_cn=subject,
            is_suspicious=suspicious,
        )
    except asyncio.TimeoutError:
        return TLSCheck(error="timeout")
    except ssl.SSLError as e:
        return TLSCheck(error=f"tls: {e}")
    except Exception as e:
        return TLSCheck(error=str(e))


# ---------- classification ----------

_ANDROID_HOTSPOT_PREFIXES = ("192.168.43.", "192.168.42.", "192.168.44.")

# Common home-router LAN prefixes (Huawei, Xiaomi, TP-Link, ASUS, D-Link, Netgear...)
_HOME_ROUTER_PREFIXES = (
    "192.168.0.",   # D-Link, TP-Link, Netgear
    "192.168.1.",   # TP-Link, ASUS, Netgear, generic
    "192.168.2.",   # Belkin, some ZTE
    "192.168.3.",   # Huawei (many models)
    "192.168.8.",   # Huawei (Nova, mobile routers, AX3)
    "192.168.31.",  # Xiaomi
    "192.168.50.",  # ASUS default
    "192.168.68.",  # some Mesh systems
    "10.0.0.",      # Netgear, some ISPs
    "10.0.1.",      # common extended
)


def classify(
    net: NetworkInfo,
    captive: CaptiveCheck,
    tls: TLSCheck,
    dns_ok: bool,
) -> Classification:
    reasons: list[str] = []
    score_hotspot = 0
    score_commercial = 0
    score_home = 0

    gw = net.default_gateway or ""
    local_ip = net.local_ips[0] if net.local_ips else ""

    # Hotspot signals
    if any(local_ip.startswith(p) for p in _ANDROID_HOTSPOT_PREFIXES):
        score_hotspot += 3
        reasons.append(f"local IP {local_ip} matches Android hotspot subnet")
    if gw.startswith("192.168.43."):
        score_hotspot += 2
        reasons.append(f"gateway {gw} matches Android hotspot pattern")

    # Commercial / captive signals (only strong signals count)
    if captive.redirected:
        score_commercial += 3
        reasons.append(f"HTTP {captive.status} redirect to {captive.location}")
    if captive.status not in (None, 204) and not captive.error:
        score_commercial += 2
        reasons.append(f"captive probe returned {captive.status} instead of 204")
    # DNS failure alone is weak — only count if TLS also failed/suspicious
    if not dns_ok and (tls.is_suspicious or not tls.connected):
        score_commercial += 2
        reasons.append("DNS failed AND TLS suspicious/failed")
    if tls.is_suspicious:
        score_commercial += 2
        reasons.append(f"TLS issuer not in trusted list: {tls.issuer_cn or 'unknown'}")

    # Home signals (strong when local IP matches known LAN range)
    for pref in _HOME_ROUTER_PREFIXES:
        if local_ip.startswith(pref):
            score_home += 3
            reasons.append(f"local IP {local_ip} in home LAN prefix {pref}x")
            break
    if gw and gw in ("192.168.1.1", "192.168.0.1", "192.168.1.254",
                     "10.0.0.1", "192.168.0.254", "192.168.3.1", "192.168.8.1"):
        score_home += 2
        reasons.append(f"common home-router gateway {gw}")
    if captive.status == 204 and not tls.is_suspicious:
        score_home += 1
        reasons.append("captive probe returned 204 and TLS is clean")

    # Hard override: active TLS interception trumps everything else
    if tls.connected and tls.is_suspicious:
        return Classification(
            type="commercial",
            confidence=1.0,
            reasons=[f"TLS issuer '{tls.issuer_cn}' not in trusted CAs — possible MITM"]
                    + reasons,
        )

    scores = {
        "hotspot": score_hotspot,
        "commercial": score_commercial,
        "home_router": score_home,
    }
    best_type, best_score = max(scores.items(), key=lambda kv: kv[1])
    total = sum(scores.values())

    if best_score <= 0:
        return Classification(type="unknown", confidence=0.0, reasons=["no signals"])

    confidence = round(best_score / total, 2) if total else 0.0
    return Classification(type=best_type, confidence=confidence, reasons=reasons)


# ---------- main API ----------

async def detect(timeout: float = 3.0) -> Phase1Result:
    """Run all probes and produce a Phase1Result."""
    net = gather_network_info()
    captive, tls = await asyncio.gather(
        check_captive_portal(timeout=timeout),
        check_tls(timeout=timeout),
    )
    dns_ok = await check_dns()
    cls = classify(net, captive, tls, dns_ok)
    return Phase1Result(
        network=net,
        captive=captive,
        tls=tls,
        dns_ok=dns_ok,
        classification=cls,
    )


def detect_sync(timeout: float = 3.0) -> dict[str, Any]:
    """Synchronous wrapper for CLI/testing."""
    return asyncio.run(detect(timeout=timeout)).to_dict()


# ============================================================================
# Extended network classification (all types) — Phase A enhancement
# ============================================================================
from core.network_classifier import classify as _classify_network, NetworkProfile


def classify_network() -> NetworkProfile:
    """Return rich network profile: type, brand, safety, warnings."""
    return _classify_network()


def classify_network_dict() -> dict:
    return _classify_network().to_dict()
