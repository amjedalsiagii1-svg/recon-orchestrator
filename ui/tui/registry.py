"""Phase Registry - Extensible list of phases for TUI"""
from dataclasses import dataclass
from typing import Callable, Any


@dataclass
class PhaseSpec:
    number: str
    key: str
    arabic: str
    english: str
    description: str
    runner: Callable
    has_input: bool = False
    input_placeholder: str = ""


def get_phases():
    """Return all registered phases. Add new phase here."""
    from ui.tui.runners import (
        run_p1, run_p2, run_p3, run_p4, run_p5,
        run_p6, run_p7, run_p8,
    )
    return [
        PhaseSpec("1", "network", "كشف نوع الشبكة", "Network Type",
                  "Detect captive portal, MITM, hotspot", run_p1),
        PhaseSpec("2", "discovery", "اكتشاف الأجهزة", "Discovery",
                  "ARP/NDP scan, OS fingerprint", run_p2),
        PhaseSpec("3", "target", "اختيار الهدف", "Target Selection",
                  "Choose target from discovered", run_p3,
                  has_input=True, input_placeholder="192.168.8.1"),
        PhaseSpec("4", "ports", "فحص المنافذ", "Port Scan",
                  "Quick/stealth/UDP/full profiles", run_p4),
        PhaseSpec("5", "vulns", "فحص الثغرات", "Vulnerability Scan",
                  "Nuclei/Nikto/Searchsploit", run_p5),
        PhaseSpec("6", "exploit", "الاستغلال الآمن", "Safe Exploitation",
                  "Review plans (dry-run only)", run_p6),
        PhaseSpec("7", "report", "توليد التقرير", "Reporting",
                  "HTML report with commands", run_p7),
        PhaseSpec("8", "webscan", "فحص الويب", "Web Scan",
                  "8 tools: WhatWeb/Nikto/Gobuster/etc", run_p8),
    ]
