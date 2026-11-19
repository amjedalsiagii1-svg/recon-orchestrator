"""Deterministic, explainable defensive guidance for SF.

Recommendations are advisory, tied to stored evidence, and never executed.
The command catalog is limited to local, read-only Linux diagnostics.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SEVERITY_LABELS = {
    "critical": "حرج",
    "high": "مرتفع",
    "medium": "متوسط",
    "low": "منخفض",
    "info": "معلوماتي",
    "unspecified": "غير محدد",
}


@dataclass(frozen=True)
class SafeCommand:
    id: str
    title: str
    command: str
    purpose: str
    expected: str
    prerequisites: str
    impact: str = "قراءة محلية فقط؛ لا يغيّر إعدادات النظام ولا يتصل بهدف بعيد."


SAFE_COMMANDS: tuple[SafeCommand, ...] = (
    SafeCommand(
        "interfaces", "عرض واجهات وعناوين الجهاز",
        "ip -br address",
        "يعرض واجهات الشبكة المحلية وعناوين IP وحالة الواجهة باختصار.",
        "أسماء الواجهات وحالتها والعناوين المرتبطة بها؛ قد لا يظهر عنوان عند فصل الواجهة.",
        "أداة ip ضمن iproute2؛ لا يحتاج عادةً إلى root.",
    ),
    SafeCommand(
        "routes", "عرض جدول التوجيه المحلي",
        "ip route",
        "يعرض مسارات IPv4 المحلية والمسار الافتراضي إن وجد.",
        "قد يظهر سطر يبدأ بـ default يوضح البوابة والواجهة الافتراضية.",
        "أداة ip ضمن iproute2؛ لا يحتاج عادةً إلى root.",
    ),
    SafeCommand(
        "listeners", "مراجعة الخدمات التي تستمع محلياً",
        "ss -lntup",
        "يعرض مقابس TCP وUDP التي تستمع على الجهاز، مع معلومات العمليات عندما تسمح الصلاحيات.",
        "قائمة بالمنافذ المحلية وحالات الاستماع؛ غياب بعض أسماء العمليات قد يكون بسبب الصلاحيات.",
        "أداة ss؛ بعض تفاصيل العمليات قد تحتاج صلاحيات إضافية.",
    ),
    SafeCommand(
        "failed-units", "التحقق من وحدات systemd المتعثرة",
        "systemctl --failed",
        "يعرض وحدات systemd التي دخلت حالة فشل.",
        "قائمة الوحدات الفاشلة، أو رسالة تفيد بعدم وجود وحدات فاشلة.",
        "نظام يستخدم systemd؛ لا يغيّر حالة الخدمات.",
    ),
    SafeCommand(
        "updates", "عرض الحزم القابلة للتحديث",
        "apt list --upgradable",
        "يعرض الحزم التي يرى فهرس APT المحلي أنها قابلة للتحديث.",
        "قائمة الحزم وإصداراتها المتاحة وفق آخر فهرس محلي؛ لا ينفذ التحديث.",
        "APT؛ النتائج تعتمد على حداثة فهارس الحزم المحلية.",
    ),
    SafeCommand(
        "firewall", "قراءة حالة جدار UFW",
        "sudo ufw status verbose",
        "يعرض حالة UFW والقواعد الفعالة دون تغييرها.",
        "Status: active أو inactive، مع القواعد المعرّفة إن وجدت.",
        "يتطلب UFW وقد يطلب كلمة مرور sudo؛ الأمر للقراءة فقط.",
    ),
    SafeCommand(
        "network-manager", "عرض حالة أجهزة NetworkManager",
        "nmcli device status",
        "يعرض أجهزة الشبكة وحالة إدارتها والاتصال المرتبط بها.",
        "جدول للأجهزة والحالة والاتصال؛ قد لا تتوفر الأداة في كل تثبيت.",
        "NetworkManager وnmcli؛ لا يحتاج عادةً إلى root.",
    ),
)


_RECOMMENDATION_RULES: dict[str, dict[str, str]] = {
    "asset": {
        "title": "تأكيد ملكية الأصل ونطاقه",
        "reason": "سجل الأصل وحده لا يثبت ملكيته أو أنه ضمن التفويض.",
        "action": "وثّق المالك والغرض ومصدر المعلومة، ثم أبقِ الأصل خارج أي تقييم حتى يتم تأكيد التفويض.",
        "priority": "متوسط",
    },
    "service": {
        "title": "مراجعة الحاجة إلى الخدمة",
        "reason": "وجود خدمة أو منفذ لا يعني وجود ثغرة؛ يجب فهم سبب تشغيله ومَن يحتاج إليه.",
        "action": "تحقق من مالك الخدمة والغرض منها، وقارن إعداد الاستماع بالاحتياج الفعلي. عطّل الخدمة فقط عبر إجراء تغيير معتمد وبعد فهم أثره.",
        "priority": "متوسط",
    },
    "configuration": {
        "title": "مقارنة الإعداد بخط أساس موثوق",
        "reason": "ملاحظة الإعداد تحتاج إلى سياق وإصدار ومرجع قبل تصنيفها كمشكلة.",
        "action": "سجّل المنتج والإصدار والإعداد الفعلي، ثم قارنه بتوصيات المورّد أو معيار تقوية مناسب، ووثّق طريقة التحقق.",
        "priority": "متوسط",
    },
    "finding": {
        "title": "التحقق من الملاحظة قبل اعتمادها",
        "reason": "تسمية السجل كملاحظة أمنية لا تجعلها ثغرة مؤكدة تلقائياً.",
        "action": "راجع الدليل المباشر، والمنتج والإصدار المتأثرين، وقابلية الانطباق، ومصدر المطابقة. لا تعتمد التصنيف قبل اكتمال هذه العناصر.",
        "priority": "مرتفع",
    },
    "note": {
        "title": "استكمال السياق ومصدر المعلومة",
        "reason": "الملاحظات غير المكتملة قد تؤدي إلى استنتاجات غير دقيقة.",
        "action": "أضف وقت الملاحظة ومصدرها والبيئة التي تخصها، وافصل بين الحقيقة المرصودة والافتراض.",
        "priority": "منخفض",
    },
}

_SEVERITY_PRIORITY = {
    "critical": "عاجل للمراجعة",
    "high": "أولوية مراجعة عالية",
    "medium": "أولوية مراجعة متوسطة",
    "low": "أولوية مراجعة منخفضة",
    "info": "معلوماتي",
}


def severity_counts(evidence: list[dict[str, Any]]) -> dict[str, int]:
    """Count only explicitly stored severity labels; never infer severity."""
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unspecified")}
    for item in evidence:
        payload = item.get("payload") or {}
        severity = str(payload.get("severity", "unspecified")).strip().lower()
        if severity not in counts:
            severity = "unspecified"
        counts[severity] += 1
    return counts


def recommendations_for_evidence(
    evidence: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Produce transparent remediation workflow advice from evidence category."""
    recommendations: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in evidence:
        category = str(item.get("category", "note")).strip().lower()
        rule = _RECOMMENDATION_RULES.get(category, _RECOMMENDATION_RULES["note"])
        if category not in seen:
            recommendations.append({
                "category": category,
                **rule,
            })
            seen.add(category)

        payload = item.get("payload") or {}
        severity = str(payload.get("severity", "")).strip().lower()
        if category == "finding" and severity in _SEVERITY_PRIORITY:
            recommendations.append({
                "category": category,
                "title": _SEVERITY_PRIORITY[severity],
                "reason": f"درجة الخطورة المسجلة: {SEVERITY_LABELS[severity]}؛ يجب التحقق من الدليل ومستوى الثقة.",
                "action": "رتّب المراجعة وفق أثر الأصل وقابلية الانطباق، ثم وثّق الإصلاح والتحقق اللاحق.",
                "priority": _SEVERITY_PRIORITY[severity],
            })
    return recommendations


def commands_for_report() -> tuple[SafeCommand, ...]:
    """Return the fixed local read-only command catalog."""
    return SAFE_COMMANDS
