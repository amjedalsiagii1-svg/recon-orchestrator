"""Comprehensive network type detection for all common scenarios.

Types: home_router, mobile_hotspot, mobile_tethering, card_adapter,
       ethernet, corporate, public_wifi, vpn, mobile_data.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from core.mac_oui import is_locally_administered, lookup_vendor


@dataclass
class NetworkProfile:
    type: str
    type_ar: str
    confidence: float
    iface: str | None = None
    gateway: str | None = None
    gateway_mac: str | None = None
    gateway_vendor: str | None = None
    local_ips: list[str] = field(default_factory=list)
    subnet: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    dns_suffix: str | None = None
    captive: bool = False
    reasons: list[str] = field(default_factory=list)
    characteristics: dict[str, Any] = field(default_factory=dict)
    is_safe_to_scan: bool = True
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Interface name patterns → category
_IFACE_CATEGORIES = {
    "wlan": "wifi",
    "wlp": "wifi",
    "ath": "wifi",
    "eth": "ethernet",
    "enp": "ethernet",
    "eno": "ethernet",
    "enx": "ethernet_usb",
    "usb": "ethernet_usb",
    "rndis": "usb_tether",
    "rmnet": "mobile_data",
    "ccmni": "mobile_data",
    "pdp": "mobile_data",
    "wwan": "mobile_data",
    "tun": "vpn",
    "tap": "vpn",
    "ppp": "vpn_ppp",
}

# IP range → network type hints
_ANDROID_HOTSPOT_PREFIXES = ("192.168.43.", "192.168.44.")
_IPHONE_HOTSPOT_PREFIXES = ("172.20.10.",)
_USB_TETHER_PREFIXES = ("192.168.42.",)
_HOME_ROUTER_PREFIXES = (
    "192.168.0.", "192.168.1.", "192.168.2.", "192.168.3.",
    "192.168.8.", "192.168.31.", "192.168.50.", "192.168.68.",
    "10.0.0.", "10.0.1.",
)

# Arabic type names + short descriptions
_TYPE_NAMES_AR = {
    "home_router": "راوتر منزلي",
    "mobile_hotspot": "بث جوال",
    "mobile_tethering": "اتصال بجوالي (USB)",
    "card_adapter": "شبكة كروت (WiFi USB)",
    "ethernet": "شبكة إيثرنت سلكية",
    "corporate": "شبكة مؤسسة/عمل",
    "public_wifi": "شبكة عامة (مقهى/مطار/فندق)",
    "vpn": "شبكة VPN",
    "mobile_data": "بيانات جوال مباشرة",
    "unknown": "شبكة غير معروفة",
}

_TYPE_DESCRIPTIONS_AR = {
    "home_router": "شبكة منزلية بإدارة راوتر شخصي. الفحص آمن عادة إذا كانت شبكتك.",
    "mobile_hotspot": "أنت على نقطة اتصال جوال (شخص آخر). لا تفحص أجهزته.",
    "mobile_tethering": "أنت متصل بجوالك عبر USB. الشبكة تحت سيطرتك.",
    "card_adapter": "شبكة كروت WiFi خارجية (USB adapter) أو كرت شبكة.",
    "ethernet": "شبكة سلكية عبر كابل إيثرنت.",
    "corporate": "شبكة شركة/مؤسسة. قد يكون فحصها مخالفًا لسياسة الشركة.",
    "public_wifi": "شبكة عامة (مقهى، مطار). لا تفحص أجهزة الآخرين.",
    "vpn": "أنت خلف VPN. تأكد من النطاق الذي تريد فحصه.",
    "mobile_data": "متصل ببيانات الجوال مباشرة. لا تفحص شبكة المزود.",
    "unknown": "نوع الشبكة غير واضح. تحقق يدويًا قبل الفحص.",
}


def _read_interface() -> str | None:
    """Get primary network interface name (multiple fallbacks)."""
    import subprocess

    # Method 1: ip route show default
    try:
        r = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=2,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass

    # Method 2: /proc/net/route (Linux classic)
    try:
        path = Path("/proc/net/route")
        if path.exists():
            for line in path.read_text().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except Exception:
        pass

    # Method 3: ip -o link show up (skip lo)
    try:
        r = subprocess.run(
            ["ip", "-o", "link", "show", "up"],
            capture_output=True, text=True, timeout=2,
        )
        for line in r.stdout.splitlines():
            m = re.match(r"\d+:\s+([^:@\s]+)", line)
            if m and m.group(1) != "lo":
                return m.group(1)
    except Exception:
        pass

    # Method 4: /sys/class/net/
    try:
        net_dir = Path("/sys/class/net")
        if net_dir.exists():
            for entry in net_dir.iterdir():
                if entry.name == "lo":
                    continue
                state_file = entry / "operstate"
                if state_file.exists() and state_file.read_text().strip() == "up":
                    return entry.name
    except Exception:
        pass

    # Method 5: Termux getprop
    try:
        for prop in ("wifi.interface", "ro.wifi.interface"):
            r = subprocess.run(["getprop", prop], capture_output=True, text=True, timeout=1)
            val = r.stdout.strip()
            if val:
                return val
    except Exception:
        pass

    return None


def _iface_category(iface: str | None) -> str | None:
    if not iface:
        return None
    iface_l = iface.lower()
    for prefix, cat in _IFACE_CATEGORIES.items():
        if iface_l.startswith(prefix):
            return cat
    return None


def _local_ips() -> list[str]:
    ips: list[str] = []
    try:
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
            if ip not in ips and ":" not in ip:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _gateway() -> str | None:
    try:
        import subprocess
        r = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=2,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    for prop in ("dhcp.wlan0.gateway", "dhcp.eth0.gateway"):
        try:
            import subprocess
            r = subprocess.run(["getprop", prop], capture_output=True, text=True, timeout=1)
            val = r.stdout.strip()
            if val and val.count(".") == 3:
                return val
        except Exception:
            pass
    ips = _local_ips()
    if ips:
        try:
            parts = ips[0].split(".")
            return ".".join(parts[:3] + ["1"])
        except Exception:
            pass
    return None


def _gateway_mac(gateway: str | None) -> str | None:
    if not gateway:
        return None
    try:
        p = Path("/proc/net/arp")
        if not p.exists():
            return None
        for line in p.read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == gateway:
                mac = parts[3].lower()
                if mac.count(":") == 5 and mac != "00:00:00:00:00:00":
                    return mac
    except Exception:
        pass
    return None


def _dns_servers() -> list[str]:
    servers: list[str] = []
    try:
        p = Path("/etc/resolv.conf")
        if p.exists():
            for line in p.read_text().splitlines():
                if line.startswith("nameserver"):
                    servers.append(line.split()[1])
    except Exception:
        pass
    if not servers:
        try:
            import subprocess
            r = subprocess.run(
                ["getprop", "net.dns1"], capture_output=True, text=True, timeout=1,
            )
            val = r.stdout.strip()
            if val and val.count(".") == 3:
                servers.append(val)
        except Exception:
            pass
    return servers


def _subnet(local_ips: list[str]) -> str | None:
    if not local_ips:
        return None
    try:
        ip = ipaddress.ip_address(local_ips[0])
        return f"{ip}/24" if isinstance(ip, ipaddress.IPv4Address) else f"{ip}/64"
    except Exception:
        return None


def _detect_brand_from_ip_range(ip: str) -> str | None:
    if ip.startswith("192.168.8."):
        return "Huawei"
    if ip.startswith("192.168.31."):
        return "Xiaomi"
    if ip.startswith("192.168.50."):
        return "ASUS"
    return None


def classify() -> NetworkProfile:
    """Detect network type. Returns rich NetworkProfile."""
    iface = _read_interface()
    gw = _gateway()
    gw_mac = _gateway_mac(gw)
    gw_vendor = lookup_vendor(gw_mac)
    local_ips = _local_ips()
    dns = _dns_servers()
    subnet = _subnet(local_ips)
    iface_cat = _iface_category(iface)
    reasons: list[str] = []
    warnings: list[str] = []
    characteristics: dict[str, Any] = {}

    primary_ip = local_ips[0] if local_ips else None

    # ---------- VPN check (strongest signal) ----------
    if iface_cat in ("vpn", "vpn_ppp"):
        return NetworkProfile(
            type="vpn",
            type_ar=_TYPE_NAMES_AR["vpn"],
            confidence=0.95,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=[f"واجهة {iface} هي VPN (tun/tap/ppp)"],
            characteristics=characteristics,
            is_safe_to_scan=False,
            warnings=[
                "أنت خلف VPN. الفحص سيرى عنوان VPN وليس شبكتك الحقيقية.",
                "تأكد من نطاق scope.txt قبل الفحص.",
            ],
        )

    # ---------- Mobile data check ----------
    if iface_cat == "mobile_data":
        return NetworkProfile(
            type="mobile_data",
            type_ar=_TYPE_NAMES_AR["mobile_data"],
            confidence=0.95,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=[f"واجهة {iface} هي بيانات جوال (rmnet/ccmni)"],
            characteristics=characteristics,
            is_safe_to_scan=False,
            warnings=[
                "أنت على بيانات جوال مباشرة.",
                "الفحص سيتوجه لشبكة مزود الخدمة — غير مصرّح.",
                "لا تفحص أي IP خارج جهازك.",
            ],
        )

    # ---------- USB tethering ----------
    if iface_cat == "usb_tether" or (
        primary_ip and any(primary_ip.startswith(p) for p in _USB_TETHER_PREFIXES)
        and iface_cat in ("ethernet_usb", "usb_tether")
    ):
        return NetworkProfile(
            type="mobile_tethering",
            type_ar=_TYPE_NAMES_AR["mobile_tethering"],
            confidence=0.85,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=["واجهة rndis/USB + IP في نطاق tethering"],
            characteristics=characteristics,
            is_safe_to_scan=True,
        )

    # ---------- Android hotspot ----------
    if primary_ip and any(primary_ip.startswith(p) for p in _ANDROID_HOTSPOT_PREFIXES):
        return NetworkProfile(
            type="mobile_hotspot",
            type_ar=_TYPE_NAMES_AR["mobile_hotspot"],
            confidence=0.95,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=[f"IP {primary_ip} في نطاق بث جوال Android"],
            characteristics=characteristics,
            is_safe_to_scan=False,
            warnings=[
                "هذه نقطة اتصال جوال (شخص آخر).",
                "قد لا تملك إذنًا بفحص أجهزة الآخرين.",
                "اطلب إذنًا كتابيًا قبل أي فحص.",
            ],
        )

    # ---------- iPhone hotspot ----------
    if primary_ip and any(primary_ip.startswith(p) for p in _IPHONE_HOTSPOT_PREFIXES):
        return NetworkProfile(
            type="mobile_hotspot",
            type_ar="بث جوال (iPhone)",
            confidence=0.95,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=[f"IP {primary_ip} في نطاق iPhone hotspot"],
            characteristics=characteristics,
            is_safe_to_scan=False,
            warnings=[
                "نقطة اتصال iPhone (شخص آخر).",
                "اطلب إذنًا قبل الفحص.",
            ],
        )

    # ---------- Home router ----------
    if primary_ip and any(primary_ip.startswith(p) for p in _HOME_ROUTER_PREFIXES):
        brand = gw_vendor or _detect_brand_from_ip_range(primary_ip)
        reasons.append(f"IP {primary_ip} في نطاق راوتر منزلي شائع")
        if brand:
            reasons.append(f"ماركة الراوتر: {brand}")
            characteristics["brand"] = brand
        if iface_cat == "ethernet_usb":
            return NetworkProfile(
                type="card_adapter",
                type_ar=_TYPE_NAMES_AR["card_adapter"],
                confidence=0.8,
                iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
                local_ips=local_ips, subnet=subnet, dns_servers=dns,
                reasons=reasons + ["الواجهة USB Ethernet (كرت شبكة)"],
                characteristics=characteristics,
                is_safe_to_scan=True,
            )
        return NetworkProfile(
            type="home_router",
            type_ar=_TYPE_NAMES_AR["home_router"],
            confidence=0.9 if brand else 0.75,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=reasons,
            characteristics=characteristics,
            is_safe_to_scan=True,
        )

    # ---------- Corporate (10.x, 172.16-31.x) ----------
    if primary_ip and (
        primary_ip.startswith("10.")
        or any(primary_ip.startswith(f"172.{n}.") for n in range(16, 32))
    ):
        return NetworkProfile(
            type="corporate",
            type_ar=_TYPE_NAMES_AR["corporate"],
            confidence=0.85,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=[f"IP {primary_ip} في نطاق شبكة مؤسسة"],
            characteristics=characteristics,
            is_safe_to_scan=False,
            warnings=[
                "شبكة مؤسسة/عمل.",
                "الفحص قد يخالف سياسة الشركة.",
                "اطلب إذنًا كتابيًا من قسم الأمن السيبراني.",
            ],
        )

    # ---------- Ethernet ----------
    if iface_cat == "ethernet":
        return NetworkProfile(
            type="ethernet",
            type_ar=_TYPE_NAMES_AR["ethernet"],
            confidence=0.8,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=[f"واجهة سلكية {iface}"],
            characteristics=characteristics,
            is_safe_to_scan=True,
        )

    # ---------- Card adapter (USB WiFi) ----------
    if iface_cat in ("wifi",) and iface and not iface.startswith("wlan0"):
        return NetworkProfile(
            type="card_adapter",
            type_ar=_TYPE_NAMES_AR["card_adapter"],
            confidence=0.7,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=[f"واجهة WiFi إضافية {iface}"],
            characteristics=characteristics,
            is_safe_to_scan=True,
        )

    # ---------- WiFi default (public or unknown) ----------
    if iface_cat == "wifi":
        return NetworkProfile(
            type="public_wifi",
            type_ar=_TYPE_NAMES_AR["public_wifi"],
            confidence=0.5,
            iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
            local_ips=local_ips, subnet=subnet, dns_servers=dns,
            reasons=[f"WiFi {iface} بنطاق غير منزلي معروف"],
            characteristics=characteristics,
            is_safe_to_scan=False,
            warnings=[
                "شبكة WiFi بنطاق غير معروف.",
                "قد تكون شبكة عامة — لا تفحص أجهزة الآخرين.",
                "تحقق من إذنك قبل أي فحص.",
            ],
        )

    # ---------- Fallback ----------
    return NetworkProfile(
        type="unknown",
        type_ar=_TYPE_NAMES_AR["unknown"],
        confidence=0.3,
        iface=iface, gateway=gw, gateway_mac=gw_mac, gateway_vendor=gw_vendor,
        local_ips=local_ips, subnet=subnet, dns_servers=dns,
        reasons=["لا توجد إشارات كافية"],
        characteristics=characteristics,
        is_safe_to_scan=False,
        warnings=["نوع الشبكة غير واضح. تحقق يدويًا قبل أي فحص."],
    )
