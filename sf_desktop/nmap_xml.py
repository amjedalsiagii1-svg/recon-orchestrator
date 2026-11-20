"""Strict offline importer for existing Nmap XML result files.

This module never invokes Nmap or opens network connections. It parses an
existing local XML file, accepts only literal IPs inside the configured
ScopePolicy, and applies conservative file/record limits.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sf_desktop.scope_guard import ScopePolicy

MAX_XML_BYTES = 5 * 1024 * 1024
MAX_HOSTS = 256
MAX_SERVICES = 5000
MAX_WARNINGS = 30
_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class NmapImportError(ValueError):
    """Raised when an XML file is malformed or violates importer limits."""


@dataclass(frozen=True)
class ImportedAsset:
    ip: str
    hostname: str | None
    mac: str | None
    vendor: str | None
    state: str


@dataclass(frozen=True)
class ImportedService:
    ip: str
    protocol: str
    port: int
    state: str
    name: str | None
    product: str | None
    version: str | None
    extra_info: str | None


@dataclass(frozen=True)
class ParsedNmapImport:
    source_name: str
    sha256: str
    assets: tuple[ImportedAsset, ...]
    services: tuple[ImportedService, ...]
    skipped_host_count: int
    warnings: tuple[str, ...]

    def asset_dicts(self) -> list[dict[str, Any]]:
        return [asdict(item) for item in self.assets]

    def service_dicts(self) -> list[dict[str, Any]]:
        return [asdict(item) for item in self.services]


def _safe_attr(value: str | None, maximum: int) -> str | None:
    if value is None:
        return None
    clean = value.strip()
    if not clean:
        return None
    if len(clean) > maximum or any(ord(ch) < 32 for ch in clean):
        return None
    return clean


def parse_nmap_xml(
    raw: bytes,
    *,
    source_name: str,
    scope: ScopePolicy,
) -> ParsedNmapImport:
    """Parse a bounded Nmap XML export and keep only in-scope local IP data."""
    if not isinstance(raw, bytes):
        raise NmapImportError("يجب قراءة الملف على هيئة bytes")
    if not raw:
        raise NmapImportError("ملف XML فارغ")
    if len(raw) > MAX_XML_BYTES:
        raise NmapImportError(f"حجم الملف يتجاوز الحد ({MAX_XML_BYTES // (1024 * 1024)} MB)")
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise NmapImportError("محتوى DTD أو ENTITY غير مسموح في ملف الاستيراد")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise NmapImportError(f"بنية XML غير صالحة: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapImportError("الملف ليس تصديراً معروفاً بصيغة Nmap XML")

    host_nodes = root.findall("./host")
    if len(host_nodes) > MAX_HOSTS:
        raise NmapImportError(f"عدد الأجهزة يتجاوز الحد ({MAX_HOSTS})")

    assets: list[ImportedAsset] = []
    services: list[ImportedService] = []
    skipped = 0
    warnings: list[str] = []
    seen_asset_ips: set[str] = set()
    seen_service_keys: set[tuple[str, str, int]] = set()

    for host in host_nodes:
        host_state = host.find("./status")
        state = (host_state.get("state", "unknown") if host_state is not None else "unknown")
        if state != "up":
            skipped += 1
            continue

        in_scope_ips: list[str] = []
        for address_node in host.findall("./address"):
            addr_type = address_node.get("addrtype", "")
            if addr_type not in {"ipv4", "ipv6"}:
                continue
            raw_ip = address_node.get("addr", "")
            try:
                ip_value = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                continue
            check = scope.authorize_target(ip_value)
            if check.allowed and ip_value not in in_scope_ips:
                in_scope_ips.append(ip_value)

        if not in_scope_ips:
            skipped += 1
            if len(warnings) < MAX_WARNINGS:
                warnings.append("تم استبعاد جهاز لا يملك عنوان IP ضمن النطاق المحلي المصرح.")
            continue

        hostname_node = host.find("./hostnames/hostname")
        hostname = _safe_attr(
            hostname_node.get("name") if hostname_node is not None else None, 253
        )
        mac = None
        vendor = None
        for address_node in host.findall("./address"):
            if address_node.get("addrtype") == "mac":
                candidate = address_node.get("addr", "")
                if _MAC_RE.fullmatch(candidate):
                    mac = candidate.lower()
                    vendor = _safe_attr(address_node.get("vendor"), 120)
                    break

        for ip_value in in_scope_ips:
            if ip_value not in seen_asset_ips:
                assets.append(ImportedAsset(
                    ip=ip_value,
                    hostname=hostname,
                    mac=mac,
                    vendor=vendor,
                    state="up",
                ))
                seen_asset_ips.add(ip_value)

        for port_node in host.findall("./ports/port"):
            protocol = (port_node.get("protocol") or "").lower()
            if protocol not in {"tcp", "udp"}:
                continue
            try:
                port_number = int(port_node.get("portid", "0"))
            except ValueError:
                continue
            if not 1 <= port_number <= 65535:
                continue
            state_node = port_node.find("./state")
            port_state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            if port_state not in {"open", "closed", "filtered", "open|filtered", "unfiltered"}:
                port_state = "unknown"
            service_node = port_node.find("./service")
            attrs = service_node.attrib if service_node is not None else {}
            for ip_value in in_scope_ips:
                key = (ip_value, protocol, port_number)
                if key in seen_service_keys:
                    continue
                seen_service_keys.add(key)
                services.append(ImportedService(
                    ip=ip_value,
                    protocol=protocol,
                    port=port_number,
                    state=port_state,
                    name=_safe_attr(attrs.get("name"), 120),
                    product=_safe_attr(attrs.get("product"), 160),
                    version=_safe_attr(attrs.get("version"), 120),
                    extra_info=_safe_attr(attrs.get("extrainfo"), 500),
                ))
                if len(services) > MAX_SERVICES:
                    raise NmapImportError(f"عدد الخدمات يتجاوز الحد ({MAX_SERVICES})")

    if not assets:
        raise NmapImportError(
            "لم يتم العثور على أجهزة ضمن النطاق الحالي. راجع ملف config/scope.txt وتأكد من صلاحية الملف."
        )

    safe_name = Path(source_name).name[:200] or "nmap-import.xml"
    return ParsedNmapImport(
        source_name=safe_name,
        sha256=hashlib.sha256(raw).hexdigest(),
        assets=tuple(assets),
        services=tuple(services),
        skipped_host_count=skipped,
        warnings=tuple(warnings),
    )


def parse_nmap_xml_file(path: str | Path, *, scope: ScopePolicy) -> ParsedNmapImport:
    """Read a local, regular, non-symlink XML file without executing it."""
    candidate = Path(path)
    try:
        if candidate.is_symlink() or not candidate.is_file():
            raise NmapImportError("يجب اختيار ملف محلي عادي، وليس رابطاً رمزياً أو مجلداً")
        size = candidate.stat().st_size
        if size > MAX_XML_BYTES:
            raise NmapImportError(f"حجم الملف يتجاوز الحد ({MAX_XML_BYTES // (1024 * 1024)} MB)")
        raw = candidate.read_bytes()
    except OSError as exc:
        raise NmapImportError(f"تعذر قراءة الملف: {exc}") from exc
    return parse_nmap_xml(raw, source_name=candidate.name, scope=scope)
