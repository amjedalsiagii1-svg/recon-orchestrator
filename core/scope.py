"""Scope Guard — prevents scanning outside authorized targets."""
from __future__ import annotations

import ipaddress
from pathlib import Path


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope."""


class Scope:
    """Authorized-target guard backed by a plain-text scope file.

    Accepted entries (one per line):
      - IPv4 address (e.g. 10.0.0.5) -> treated as /32
      - IPv6 address -> treated as /128
      - CIDR block (e.g. 192.168.1.0/24)
      - Hostname (exact, case-insensitive match)

    Lines starting with '#' and blank lines are ignored.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        if path is None:
            path = Path(__file__).resolve().parent.parent / "config" / "scope.txt"
        self.path = Path(path)
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._hostnames: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            raise ScopeError(f"scope file not found: {self.path}")
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            self._add_entry(line)

    def _add_entry(self, entry: str) -> None:
        try:
            if "/" in entry:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
                return
            ip = ipaddress.ip_address(entry)
            if isinstance(ip, ipaddress.IPv4Address):
                self._networks.append(ipaddress.IPv4Network(f"{ip}/32", strict=False))
            else:
                self._networks.append(ipaddress.IPv6Network(f"{ip}/128", strict=False))
            return
        except ValueError:
            pass
        self._hostnames.add(entry.lower())

    def is_allowed(self, target: str) -> bool:
        """Accept either a single IP/hostname or a CIDR network.

        A CIDR is allowed ONLY if it is fully contained within an
        authorized network (subnet_of). This prevents scanning
        broader ranges than intended.
        """
        if not target:
            return False
        t = target.strip().lower()
        if t in self._hostnames:
            return True

        # CIDR path
        if "/" in t:
            try:
                target_net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                return False
            for net in self._networks:
                if not isinstance(target_net, type(net)):
                    continue
                try:
                    if target_net.subnet_of(net):
                        return True
                except (AttributeError, TypeError):
                    # subnet_of exists in 3.7+; fallback for old versions
                    if target_net.network_address in net and target_net.prefixlen >= net.prefixlen:
                        return True
            return False

        # Single-IP path
        try:
            ip = ipaddress.ip_address(t)
        except ValueError:
            return False
        for net in self._networks:
            if isinstance(ip, ipaddress.IPv4Address) and isinstance(net, ipaddress.IPv4Network):
                if ip in net:
                    return True
            elif isinstance(ip, ipaddress.IPv6Address) and isinstance(net, ipaddress.IPv6Network):
                if ip in net:
                    return True
        return False

    def require_allowed(self, target: str) -> None:
        if not self.is_allowed(target):
            raise ScopeError(
                f"target '{target}' is NOT authorized (scope: {self.path})"
            )

    def __repr__(self) -> str:
        return (
            f"Scope({self.path.name}: "
            f"{len(self._networks)} networks, {len(self._hostnames)} hostnames)"
        )
