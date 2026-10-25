"""Phase 3 — Target selection with mandatory scope re-verification."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from core.scope import Scope


@dataclass
class Target:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    device_type: str = "unknown"
    is_gateway: bool = False
    in_scope: bool = True
    recommended_next: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_RECOMMENDATIONS: dict[str, list[str]] = {
    "router": [
        "P4 quick scan: admin ports 80, 443, 22, 23, 8080",
        "Check default creds on admin panel (admin/admin, root/root)",
        "Look for firmware version disclosure",
        "P5: try known router CVEs (searchsploit by vendor)",
    ],
    "camera": [
        "Port 554 (RTSP) — test anonymous access (rtsp://ip:554/)",
        "Web UI on 80/8080/8000 — try default creds",
        "P5: match against vendor CVEs (Hikvision, Dahua, Reolink)",
    ],
    "printer": [
        "Ports 515 (LPD), 631 (IPP), 9100 (raw) — often unauthenticated",
        "Web admin on 80/443 — try default creds",
        "PS/PJL may allow NVRAM read/write",
    ],
    "mobile": [
        "Limited attack surface — typically sandboxed (iOS/Android)",
        "Only useful to detect accidental open dev services",
        "Not a recommended target unless authorized explicitly",
    ],
    "iot": [
        "Often ships with hardcoded creds",
        "Check MQTT (1883/8883), CoAP (5683), web admin",
        "P5: search for vendor-specific CVEs",
    ],
    "unknown": [
        "P4 comprehensive scan to fingerprint services",
        "If root available: P4 with -O for OS fingerprint",
    ],
}


def select_target(
    ip: str,
    devices: list[dict[str, Any]],
    scope: Scope,
) -> Target:
    """Build a Target, re-verifying scope. Raises ScopeError if not allowed."""
    ip = (ip or "").strip()
    if not ip:
        raise ValueError("empty target")

    # MANDATORY final scope check — cannot be bypassed
    scope.require_allowed(ip)

    device: dict[str, Any] | None = None
    for d in devices:
        if d.get("ip") == ip:
            device = d
            break

    t = Target(
        ip=ip,
        mac=(device or {}).get("mac"),
        vendor=(device or {}).get("vendor"),
        hostname=(device or {}).get("hostname"),
        device_type=(device or {}).get("device_type", "unknown"),
        is_gateway=bool((device or {}).get("is_gateway", False)),
        in_scope=True,
    )
    t.recommended_next = list(_RECOMMENDATIONS.get(t.device_type, _RECOMMENDATIONS["unknown"]))
    return t
