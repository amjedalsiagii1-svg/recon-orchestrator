"""Phase 2 — Network discovery (Termux-friendly, no root)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from core.scope import Scope, ScopeError
from integrations.nmap_runner import ping_sweep
from integrations.lan_discovery import lan_discover_all, classify_service_device


# ---------- data types ----------

@dataclass
class Device:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    device_type: str = "unknown"
    is_gateway: bool = False
    in_arp_cache: bool = False
    source: str = "nmap"           # nmap | mdns | ssdp | netbios | arp
    services: list[str] = field(default_factory=list)   # mDNS/SSDP services
    server: str | None = None       # SSDP Server header
    location: str | None = None     # SSDP Location URL

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveryResult:
    subnet: str
    devices: list[Device] = field(default_factory=list)
    scan_method: str = "none"
    duration_seconds: float = 0.0
    gateway: str | None = None
    raw_nmap: str = ""
    error: str | None = None
    broadcast_devices: int = 0    # devices found ONLY via broadcast
    methods_used: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subnet": self.subnet,
            "devices": [d.to_dict() for d in self.devices],
            "scan_method": self.scan_method,
            "duration_seconds": self.duration_seconds,
            "gateway": self.gateway,
            "error": self.error,
            "broadcast_devices": self.broadcast_devices,
            "methods_used": self.methods_used,
        }


# ---------- ARP cache ----------

def read_arp_cache() -> dict[str, str]:
    """Read /proc/net/arp -> {ip: mac}. Skips incomplete/invalid entries."""
    p = Path("/proc/net/arp")
    result: dict[str, str] = {}
    if not p.exists():
        return result
    try:
        lines = p.read_text(encoding="utf-8").splitlines()[1:]
    except Exception:
        return result
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, hwtype, flags, mac = parts[0], parts[1], parts[2], parts[3]
        if mac in ("00:00:00:00:00:00", "00:00:00:00:00:00".lower()):
            continue
        if not (len(mac) == 17 and mac.count(":") == 5):
            continue
        result[ip] = mac.lower()
    return result


# ---------- classification ----------

_PRINTER_HINTS = ("printer", "hp-", "canon", "epson", "brother", "xerox", "ricoh")
_CAMERA_HINTS = ("camera", "ipcam", "hikvision", "dahua", "reolink", "axis-", "foscam")
_MOBILE_HOSTNAME_HINTS = ("iphone", "android", "galaxy", "pixel", "ipad", "oneplus", "redmi")
_ROUTER_HOSTNAME_HINTS = ("router", "gateway", "modem", "openwrt", "dd-wrt", "pfsense")

_MOBILE_VENDOR_HINTS = (
    "apple", "samsung", "xiaomi", "huawei", "honor", "oneplus",
    "oppo", "vivo", "realme", "motorola", "nokia", "sony mobile",
)
_ROUTER_VENDOR_HINTS = (
    "tp-link", "asus", "netgear", "d-link", "ubiquiti", "cisco",
    "mikrotik", "zyxel", "linksys", "tenda", "mercury",
)
_IOT_VENDOR_HINTS = (
    "espressif", "tuya", "shelly", "raspberry", "sonoff", "texas instruments",
)


def classify_device(
    ip: str,
    gateway: str | None,
    hostname: str | None,
    vendor: str | None,
    mac: str | None = None,
) -> str:
    if gateway and ip == gateway:
        return "router"
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    if any(k in h for k in _PRINTER_HINTS):
        return "printer"
    if any(k in h for k in _CAMERA_HINTS):
        return "camera"
    if any(k in h for k in _MOBILE_HOSTNAME_HINTS):
        return "mobile"
    if any(k in h for k in _ROUTER_HOSTNAME_HINTS):
        return "router"
    if any(k in v for k in _MOBILE_VENDOR_HINTS):
        return "mobile"
    if any(k in v for k in _ROUTER_VENDOR_HINTS):
        return "router"
    if any(k in v for k in _IOT_VENDOR_HINTS):
        return "iot"
    return "unknown"


# ---------- main ----------

async def discover(
    subnet: str,
    scope: Scope | None = None,
    gateway: str | None = None,
    timeout: int = 90,
    use_broadcast: bool = True,
    broadcast_timeout: float = 4.0,
) -> DiscoveryResult:
    """Full discovery: nmap + ARP cache + optional mDNS/SSDP/NetBIOS.

    nmap runs in parallel with broadcast protocols — total time
    is max(nmap_time, broadcast_timeout) instead of sum.
    """
    import asyncio
    start = time.monotonic()

    if scope is not None:
        try:
            scope.require_allowed(subnet)
        except ScopeError as e:
            return DiscoveryResult(
                subnet=subnet, scan_method="blocked",
                duration_seconds=0.0, error=str(e),
            )

    # Run nmap and broadcast discovery in parallel
    if use_broadcast:
        nmap_task = asyncio.create_task(ping_sweep(subnet, timeout=timeout))
        broadcast_task = asyncio.create_task(
            lan_discover_all(timeout=broadcast_timeout)
        )
        try:
            (hosts, raw), broadcast_results = await asyncio.gather(
                nmap_task, broadcast_task, return_exceptions=False,
            )
        except Exception:
            # If broadcast fails, retry nmap alone
            try:
                hosts, raw = await ping_sweep(subnet, timeout=timeout)
            except Exception:
                hosts, raw = [], "failed"
            broadcast_results = []
    else:
        hosts, raw = await ping_sweep(subnet, timeout=timeout)
        broadcast_results = []

    if not hosts and raw in ("timeout", "nmap not found") and not broadcast_results:
        return DiscoveryResult(
            subnet=subnet, scan_method="failed",
            duration_seconds=round(time.monotonic() - start, 2),
            error=raw,
        )

    arp = read_arp_cache()

    # Index nmap devices by IP
    devices_by_ip: dict[str, Device] = {}
    for h in hosts:
        mac = h.mac or arp.get(h.ip)
        dt = classify_device(h.ip, gateway, h.hostname, h.vendor, mac)
        devices_by_ip[h.ip] = Device(
            ip=h.ip,
            mac=mac,
            vendor=h.vendor,
            hostname=h.hostname,
            device_type=dt,
            is_gateway=(h.ip == gateway),
            in_arp_cache=(h.ip in arp),
            source="nmap",
        )

    # ARP-only hosts (nmap missed them)
    for ip, mac in arp.items():
        if ip in devices_by_ip:
            continue
        devices_by_ip[ip] = Device(
            ip=ip,
            mac=mac,
            vendor=None,
            hostname=None,
            device_type=classify_device(ip, gateway, None, None, mac),
            is_gateway=(ip == gateway),
            in_arp_cache=True,
            source="arp",
        )

    # Merge broadcast results (mDNS/SSDP/NetBIOS)
    broadcast_only = 0
    methods_used = set()
    if hosts:
        methods_used.add("nmap")
    if arp:
        methods_used.add("arp")
    for b in broadcast_results:
        try:
            if getattr(b, "source", None):
                methods_used.add(b.source)
            ip = b.ip
            existing = devices_by_ip.get(ip)
            # Only count if IP belongs to our subnet
            if not _same_subnet(ip, subnet):
                continue
            if existing is None:
                # New device — only via broadcast
                dtype = classify_service_device(b) if callable(classify_service_device) else "unknown"
                if dtype == "unknown":
                    dtype = classify_device(ip, gateway, b.hostname, None)
                devices_by_ip[ip] = Device(
                    ip=ip,
                    mac=arp.get(ip),
                    vendor=None,
                    hostname=b.hostname,
                    device_type=dtype,
                    is_gateway=(ip == gateway),
                    in_arp_cache=(ip in arp),
                    source=b.source,
                    services=[b.service] if getattr(b, "service", None) else [],
                    server=getattr(b, "server", None),
                    location=getattr(b, "location", None),
                )
                broadcast_only += 1
            else:
                # Enrich existing device
                if not existing.hostname and b.hostname:
                    existing.hostname = b.hostname
                if existing.device_type == "unknown":
                    dt = classify_service_device(b) if callable(classify_service_device) else "unknown"
                    if dt != "unknown":
                        existing.device_type = dt
                if getattr(b, "service", None) and b.service not in existing.services:
                    existing.services.append(b.service)
                if getattr(b, "server", None) and not existing.server:
                    existing.server = b.server
                if getattr(b, "location", None) and not existing.location:
                    existing.location = b.location
                if existing.source == "nmap" and b.source != "nmap":
                    existing.source = f"nmap+{b.source}"
        except Exception:
            continue

    devices = list(devices_by_ip.values())

    def _ip_key(d: Device) -> tuple[int, ...]:
        try:
            return tuple(int(x) for x in d.ip.split("."))
        except Exception:
            return (999, 999, 999, 999)

    devices.sort(key=_ip_key)

    method_str = "+".join(sorted(methods_used)) or "nmap_sn+arp_cache"

    return DiscoveryResult(
        subnet=subnet,
        devices=devices,
        scan_method=method_str,
        duration_seconds=round(time.monotonic() - start, 2),
        gateway=gateway,
        raw_nmap=raw[:4000],
        broadcast_devices=broadcast_only,
        methods_used=sorted(methods_used),
    )


def _same_subnet(ip: str, subnet: str) -> bool:
    """Quick check: is ip within subnet? (accepts /24 by default)."""
    try:
        import ipaddress
        net = ipaddress.ip_network(subnet, strict=False)
        return ipaddress.ip_address(ip) in net
    except Exception:
        # Fallback: compare first 3 octets
        try:
            return ip.rsplit(".", 1)[0] == subnet.rsplit(".", 2)[0]
        except Exception:
            return True
