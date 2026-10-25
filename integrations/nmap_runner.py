"""Async wrapper around nmap for host discovery."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass


@dataclass
class NmapHost:
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    status: str = "up"


async def ping_sweep(subnet: str, timeout: int = 90) -> tuple[list[NmapHost], str]:
    """Run nmap -sn <subnet>. Returns (hosts, raw_output). No root required."""
    cmd = [
        "nmap", "-sn", "-T4",
        "--max-retries", "1",
        "--host-timeout", "15s",
        "--initial-rtt-timeout", "500ms",
        subnet,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return [], "nmap not found"
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return [], "timeout"
    raw = (stdout or b"").decode(errors="replace")
    err = (stderr or b"").decode(errors="replace")
    hosts = _parse_nmap_sn(raw)
    return hosts, raw if raw else err


def _parse_nmap_sn(output: str) -> list[NmapHost]:
    """Parse nmap -sn human-readable output."""
    hosts: list[NmapHost] = []
    current: NmapHost | None = None
    for line in output.splitlines():
        # Two formats:
        #   "Nmap scan report for 192.168.1.1"
        #   "Nmap scan report for router.local (192.168.1.1)"
        m = re.match(
            r"Nmap scan report for (?:([^\s(]+)\s*\()?(\d{1,3}(?:\.\d{1,3}){3})\)?",
            line,
        )
        if m:
            current = NmapHost(ip=m.group(2), hostname=m.group(1))
            hosts.append(current)
            continue
        if current is None:
            continue
        if "Host is up" in line:
            current.status = "up"
        m2 = re.search(
            r"MAC Address: ([0-9A-Fa-f:]{17})\s*(?:\(([^)]+)\))?", line
        )
        if m2:
            current.mac = m2.group(1).lower()
            current.vendor = m2.group(2)
    return hosts


# ============================================================================
# Port scanning (Phase 4)
# ============================================================================
import xml.etree.ElementTree as _ET


@dataclass
class PortFinding:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


def _parse_nmap_xml(xml_text: str) -> tuple[list[PortFinding], str | None]:
    """Parse nmap XML output. Returns (findings, os_guess)."""
    findings: list[PortFinding] = []
    os_guess: str | None = None
    try:
        root = _ET.fromstring(xml_text)
    except _ET.ParseError:
        return [], None
    for host in root.findall("host"):
        if os_guess is None:
            osmatch = host.find("os/osmatch")
            if osmatch is not None:
                os_guess = osmatch.get("name")
        for port_el in host.findall("ports/port"):
            try:
                portid = int(port_el.get("portid", "0"))
            except (TypeError, ValueError):
                continue
            protocol = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            state = (state_el.get("state", "unknown")
                     if state_el is not None else "unknown")
            svc_el = port_el.find("service")
            svc = prod = ver = None
            if svc_el is not None:
                svc = svc_el.get("name")
                prod = svc_el.get("product")
                ver = svc_el.get("version")
            findings.append(PortFinding(
                port=portid, protocol=protocol, state=state,
                service=svc, product=prod, version=ver,
            ))
    return findings, os_guess


async def scan_ports_xml(
    target: str,
    extra_args: list[str],
    timeout: int = 600,
) -> tuple[list[PortFinding], str | None, str]:
    """Run nmap -oX - <extra_args> <target>. Returns (findings, os_guess, raw)."""
    cmd = ["nmap", "-oX", "-"] + list(extra_args) + [target]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return [], None, "nmap not found"
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return [], None, "timeout"
    raw = (stdout or b"").decode(errors="replace")
    err = (stderr or b"").decode(errors="replace")

    xml_start = raw.find("<?xml")
    if xml_start < 0:
        xml_start = raw.find("<nmaprun")
    if xml_start < 0:
        return [], None, raw or err

    findings, os_guess = _parse_nmap_xml(raw[xml_start:])
    return findings, os_guess, raw
