"""One-click, read-only diagnostics of the current Kali device only.

This module never discovers neighboring hosts, sends packets, resolves DNS,
uses elevated privileges, or invokes a shell. It reads local interface/route
metadata and local listening sockets using a tiny fixed command allowlist.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

MAX_COMMAND_OUTPUT = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class LocalAuditSnapshot:
    collected_at: str
    hostname: str
    interfaces: tuple[dict[str, Any], ...]
    assets: tuple[dict[str, Any], ...]
    services: tuple[dict[str, Any], ...]
    default_gateway: str | None
    default_interface: str | None
    dns_servers: tuple[str, ...]
    warnings: tuple[str, ...]

    def canonical_json(self) -> str:
        return json.dumps(
            asdict(self), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )


def run_readonly_command(program: str, arguments: Sequence[str]) -> str:
    """Run only a fixed read-only local command, with no shell and a short timeout."""
    allowed = {
        ("ip", ("-j", "address", "show")),
        ("ip", ("-j", "route", "show", "default")),
        ("ss", ("-H", "-lntu")),
    }
    normalized = (program, tuple(arguments))
    if normalized not in allowed:
        raise ValueError("محاولة تشغيل أمر غير موجود في قائمة التشخيص المحلي")
    executable = shutil.which(program)
    if not executable:
        raise FileNotFoundError(f"الأداة المحلية غير موجودة: {program}")
    completed = subprocess.run(
        [executable, *arguments],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=COMMAND_TIMEOUT_SECONDS,
        env={"PATH": str(Path(executable).parent), "LC_ALL": "C", "LANG": "C"},
        close_fds=True,
    )
    output = completed.stdout or ""
    if len(output.encode("utf-8", errors="replace")) > MAX_COMMAND_OUTPUT:
        raise ValueError(f"خرج الأمر {program} تجاوز الحد المسموح")
    if completed.returncode != 0:
        message = (completed.stderr or "").strip()[:300]
        raise RuntimeError(message or f"انتهى الأمر {program} برمز {completed.returncode}")
    return output


def _is_local_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        not address.is_loopback
        and not address.is_unspecified
        and not address.is_multicast
        and (address.is_private or address.is_link_local)
    )


def _safe_text(value: Any, maximum: int = 253) -> str | None:
    if not isinstance(value, str):
        return None
    clean = value.strip()
    if not clean or len(clean) > maximum or any(ord(ch) < 32 for ch in clean):
        return None
    return clean


def parse_ip_address_json(raw: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"خرج ip address ليس JSON صالحاً: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("خرج ip address يجب أن يكون قائمة")
    interfaces: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    seen_ips: set[str] = set()

    for node in data[:128]:
        if not isinstance(node, dict):
            continue
        ifname = _safe_text(node.get("ifname"), 32)
        if not ifname:
            continue
        mac = _safe_text(node.get("address"), 17)
        if mac and not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
            mac = None
        operstate = _safe_text(node.get("operstate"), 20) or "UNKNOWN"
        addresses: list[str] = []
        address_info = node.get("addr_info", [])
        if not isinstance(address_info, list):
            address_info = []
        for info in address_info[:64]:
            if not isinstance(info, dict):
                continue
            local = info.get("local")
            if not isinstance(local, str):
                continue
            try:
                normalized = str(ipaddress.ip_address(local))
            except ValueError:
                continue
            if _is_local_address(normalized):
                addresses.append(normalized)
                if normalized not in seen_ips:
                    assets.append({
                        "ip": normalized,
                        "hostname": None,
                        "mac": mac.lower() if mac else None,
                        "vendor": None,
                        "state": "up" if operstate == "UP" else "unknown",
                    })
                    seen_ips.add(normalized)
        interfaces.append({
            "name": ifname,
            "state": operstate,
            "mac": mac.lower() if mac else None,
            "addresses": addresses,
        })
    return interfaces, assets


def parse_default_route_json(raw: str) -> tuple[str | None, str | None]:
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None, None
    if not isinstance(data, list):
        return None, None
    for route in data[:128]:
        if not isinstance(route, dict) or route.get("dst", "default") != "default":
            continue
        gateway = route.get("gateway")
        device = route.get("dev")
        try:
            if gateway:
                gateway = str(ipaddress.ip_address(gateway))
        except ValueError:
            gateway = None
        return gateway, _safe_text(device, 32)
    return None, None


def parse_local_listeners(raw: str, asset_ip: str) -> list[dict[str, Any]]:
    """Parse ss -H -lntu. Process arguments are intentionally never retained."""
    try:
        normalized_asset_ip = str(ipaddress.ip_address(asset_ip))
    except ValueError as exc:
        raise ValueError("عنوان الأصل المحلي غير صالح") from exc

    output: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for line in raw.splitlines()[:2000]:
        columns = line.split()
        if len(columns) < 5:
            continue
        protocol = columns[0].lower()
        if protocol not in {"tcp", "udp"}:
            continue
        state_token = columns[1].upper()
        state = "listening" if protocol == "tcp" and state_token == "LISTEN" else (
            "bound" if protocol == "udp" and state_token in {"UNCONN", "ESTAB"} else None
        )
        if state is None:
            continue
        local = columns[4]
        if local.startswith("[") and "]:" in local:
            host_part, port_part = local.rsplit(":", 1)
            host_part = host_part[1:-1]
        elif ":" in local:
            host_part, port_part = local.rsplit(":", 1)
        else:
            continue
        try:
            port = int(port_part)
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue
        key = (protocol, port)
        if key in seen:
            continue
        seen.add(key)
        output.append({
            "ip": normalized_asset_ip,
            "protocol": protocol,
            "port": port,
            "state": state,
            "name": "مستمع TCP محلي" if protocol == "tcp" else "منفذ UDP محلي مرتبط",
            "product": None,
            "version": None,
            "extra_info": f"عنوان الربط المحلي: {host_part}",
        })
    return output


def read_dns_servers(path: str | Path = "/etc/resolv.conf") -> tuple[str, ...]:
    servers: list[str] = []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ()
    for line in lines[:256]:
        columns = line.split("#", 1)[0].split()
        if len(columns) < 2 or columns[0] != "nameserver":
            continue
        try:
            value = str(ipaddress.ip_address(columns[1]))
        except ValueError:
            continue
        if value not in servers:
            servers.append(value)
        if len(servers) >= 8:
            break
    return tuple(servers)


def collect_local_snapshot(
    command_runner: Callable[[str, Sequence[str]], str] = run_readonly_command,
    resolv_conf_path: str | Path = "/etc/resolv.conf",
) -> LocalAuditSnapshot:
    """Collect a concise read-only snapshot of this computer and its sockets."""
    warnings: list[str] = []
    try:
        address_output = command_runner("ip", ("-j", "address", "show"))
        interfaces, assets = parse_ip_address_json(address_output)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        interfaces, assets = [], []
        warnings.append(f"تعذر قراءة واجهات الشبكة: {exc}")

    if not assets:
        # Loopback is a truthful fallback for an offline or minimal environment.
        assets = [{
            "ip": "127.0.0.1",
            "hostname": socket.gethostname()[:253],
            "mac": None,
            "vendor": None,
            "state": "up",
        }]

    hostname = socket.gethostname()[:253] or "unknown"
    for asset in assets:
        asset["hostname"] = hostname

    try:
        route_output = command_runner("ip", ("-j", "route", "show", "default"))
        gateway, default_interface = parse_default_route_json(route_output)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        gateway, default_interface = None, None
        warnings.append(f"تعذر قراءة المسار الافتراضي: {exc}")

    try:
        listener_output = command_runner("ss", ("-H", "-lntu"))
        services = parse_local_listeners(listener_output, assets[0]["ip"])
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        services = []
        warnings.append(f"تعذر قراءة منافذ الاستماع المحلية: {exc}")

    dns = read_dns_servers(resolv_conf_path)
    if not dns:
        warnings.append("لم يتم العثور على خوادم DNS في ملف الإعداد المحلي.")

    return LocalAuditSnapshot(
        collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        hostname=hostname,
        interfaces=tuple(interfaces),
        assets=tuple(assets),
        services=tuple(services),
        default_gateway=gateway,
        default_interface=default_interface,
        dns_servers=dns,
        warnings=tuple(warnings),
    )
