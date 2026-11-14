"""Phase Registry - Extensible with icons and Arabic"""
from dataclasses import dataclass
from typing import Callable


@dataclass
class PhaseSpec:
    number: str
    key: str
    icon: str
    arabic: str
    english: str
    description_ar: str
    runner: Callable
    has_input: bool = False
    input_placeholder: str = ""


def get_phases():
    from ui.tui.runners import (
        run_p1, run_p2, run_p3, run_p4, run_p5,
        run_p6, run_p7, run_p8,
    )
    return [
        PhaseSpec("1", "network", "🌐", "كشف الشبكة", "Network Type",
                  "اكتشاف نوع الشبكة (منزلي، مؤسسي، فندقي، صناعي...)", run_p1),
        PhaseSpec("2", "discovery", "📡", "اكتشاف الأجهزة", "Discovery",
                  "اكتشاف الأجهزة المتصلة (ARP + Nmap + OS fingerprint)", run_p2),
        PhaseSpec("3", "target", "🎯", "اختيار الهدف", "Target Selection",
                  "تحديد الهدف من الأجهزة المكتشفة", run_p3,
                  has_input=True, input_placeholder="192.168.8.1"),
        PhaseSpec("4", "ports", "🔍", "فحص المنافذ", "Port Scan",
                  "فحص المنافذ المفتوحة والخدمات (Quick profile)", run_p4),
        PhaseSpec("5", "vulns", "⚠️", "فحص الثغرات", "Vulnerability Scan",
                  "اكتشاف الثغرات (Nuclei + Searchsploit)", run_p5),
        PhaseSpec("6", "exploit", "💥", "خطط الاستغلال", "Safe Exploitation",
                  "مراجعة خطط الاستغلال (Dry-run فقط)", run_p6),
        PhaseSpec("7", "report", "📄", "توليد التقرير", "Reporting",
                  "إنشاء تقرير HTML عربي مع الأوامر", run_p7),
        PhaseSpec("8", "webscan", "🌍", "فحص الويب", "Web Scan",
                  "8 أدوات: WhatWeb/Nikto/Gobuster/WPScan...", run_p8),
    ]
