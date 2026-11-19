"""Strict, offline-only scope policy for SF.

Only literal private, loopback, or link-local IP addresses are accepted.
Hostnames and public IP ranges are rejected. This module does not resolve DNS
or perform any network operation.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

MAX_SCOPE_ADDRESSES = 256


@dataclass(frozen=True)
class ScopeCheck:
    allowed: bool
    reason: str
    normalized: str | None = None


def _is_local_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
    ) and not address.is_global


def validate_scope_entry(value: str, max_addresses: int = MAX_SCOPE_ADDRESSES) -> ScopeCheck:
    """Check a configured IP or CIDR without DNS or network access."""
    candidate = (value or "").strip()
    if not candidate:
        return ScopeCheck(False, "إدخال فارغ")
    if "%" in candidate:
        return ScopeCheck(False, "عناوين IPv6 ذات النطاق النصي غير مدعومة")

    try:
        if "/" in candidate:
            network = ipaddress.ip_network(candidate, strict=True)
        else:
            address = ipaddress.ip_address(candidate)
            network = ipaddress.ip_network(
                f"{address}/{address.max_prefixlen}", strict=True
            )
    except ValueError:
        return ScopeCheck(False, "يُسمح بعنوان IP أو CIDR فقط؛ أسماء المضيفين مرفوضة")

    if network.num_addresses > max_addresses:
        return ScopeCheck(
            False,
            f"النطاق أكبر من الحد المحلي المسموح ({max_addresses} عنواناً)",
            str(network),
        )

    first = network.network_address
    last = network.broadcast_address
    if not _is_local_address(first) or not _is_local_address(last):
        return ScopeCheck(
            False,
            "النطاق يجب أن يكون خاصاً أو محلياً أو link-local",
            str(network),
        )

    return ScopeCheck(True, "نطاق محلي محدود بصيغة صحيحة", str(network))


@dataclass(frozen=True)
class ScopePolicy:
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    rejected: tuple[tuple[str, str], ...]

    @classmethod
    def from_values(cls, values: Iterable[str]) -> "ScopePolicy":
        accepted: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        rejected: list[tuple[str, str]] = []
        seen: set[str] = set()

        for value in values:
            check = validate_scope_entry(value)
            if not check.allowed or not check.normalized:
                rejected.append((value, check.reason))
                continue
            if check.normalized in seen:
                continue
            seen.add(check.normalized)
            accepted.append(ipaddress.ip_network(check.normalized, strict=True))

        return cls(tuple(accepted), tuple(rejected))

    def authorize_target(self, target: str) -> ScopeCheck:
        """Authorize one literal IP address, never a hostname or CIDR."""
        candidate = (target or "").strip()
        if not candidate or "%" in candidate:
            return ScopeCheck(False, "أدخل عنوان IP حرفياً")
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return ScopeCheck(False, "يجب أن يكون الهدف عنوان IP حرفياً؛ DNS غير مسموح")

        if not _is_local_address(address):
            return ScopeCheck(False, "الأهداف العامة أو غير المحلية مرفوضة")

        for network in self.networks:
            if address.version == network.version and address in network:
                return ScopeCheck(True, "العنوان داخل نطاق SF المصرح محلياً", str(address))
        return ScopeCheck(False, "العنوان غير موجود داخل أي نطاق مقبول")

    def authorize_network(self, candidate: str) -> ScopeCheck:
        """Allow only a bounded local CIDR fully contained in the policy."""
        check = validate_scope_entry(candidate)
        if not check.allowed or not check.normalized:
            return check
        requested = ipaddress.ip_network(check.normalized, strict=True)
        for allowed in self.networks:
            if requested.version == allowed.version and requested.subnet_of(allowed):
                return ScopeCheck(True, "الشبكة فرعية بالكامل من نطاق SF", str(requested))
        return ScopeCheck(False, "الشبكة المطلوبة أوسع من النطاق المصرح أو خارجه", str(requested))
