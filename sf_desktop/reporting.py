"""Safe standalone HTML report generation for SF local sessions.

Only data already stored in a selected local session is rendered. All values
are escaped; no remote assets, scripts, or executable user content are added.
A session report has a stable filename and is atomically replaced on refresh.
"""
from __future__ import annotations

import html
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sf_desktop.environment import PROJECT_ROOT
from sf_desktop.storage import SFStore, StoreError
from sf_desktop.advisor import commands_for_report, recommendations_for_evidence, severity_counts

REPORT_VERSION = "0.1"
MAX_REPORT_EVIDENCE = 5000


class ReportError(RuntimeError):
    """Raised when a standalone report cannot be safely written."""


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else "—"), quote=True)


def _render(session: dict[str, str], evidence: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for index, item in enumerate(evidence, start=1):
        confidence = float(item.get("confidence", 0.0))
        confidence_label = f"{confidence * 100:.0f}%"
        payload = json.dumps(
            item.get("payload", {}),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td>{_e(item.get('category'))}</td>"
            f"<td>{_e(item.get('title'))}</td>"
            f"<td>{_e(item.get('detail'))}</td>"
            f"<td>{_e(item.get('source'))}</td>"
            f"<td>{_e(item.get('observed_at'))}</td>"
            f"<td><span class='confidence'>{_e(confidence_label)}</span></td>"
            "</tr>"
            "<tr class='payload-row'><td colspan='7'>"
            "<details><summary>تفاصيل منظمة إضافية</summary>"
            f"<pre>{_e(payload)}</pre>"
            "</details></td></tr>"
        )

    evidence_body = "".join(rows) if rows else (
        "<tr><td colspan='7' class='empty'>"
        "لا توجد أدلة مسجلة في هذه الجلسة حتى الآن. "
        "هذا التقرير يوثق حالة الجلسة ولا يمثل نتيجة فحص."
        "</td></tr>"
    )
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    status = "جلسة مفتوحة" if session.get("status") == "open" else "جلسة مغلقة"
    severity = severity_counts(evidence)
    severity_labels = {
        "critical": "حرج",
        "high": "مرتفع",
        "medium": "متوسط",
        "low": "منخفض",
        "info": "معلوماتي",
        "unspecified": "غير محدد",
    }
    severity_cards = "".join(
        f"<div class='metric'><span class='muted'>{_e(severity_labels[key])}</span>"
        f"<strong>{severity[key]}</strong></div>"
        for key in ("critical", "high", "medium", "low", "info", "unspecified")
        if severity[key]
    ) or "<p class='muted'>لا توجد درجات خطورة مسجلة.</p>"

    recommendations = recommendations_for_evidence(evidence)
    recommendation_rows = "".join(
        "<tr>"
        f"<td>{_e(item['priority'])}</td>"
        f"<td>{_e(item['title'])}</td>"
        f"<td>{_e(item['reason'])}</td>"
        f"<td>{_e(item['action'])}</td>"
        "</tr>"
        for item in recommendations
    ) or "<tr><td colspan='4' class='empty'>تظهر التوصيات بعد تسجيل أدلة أو ملاحظات.</td></tr>"

    command_rows = "".join(
        "<tr>"
        f"<td>{_e(command.title)}</td>"
        f"<td><code>{_e(command.command)}</code></td>"
        f"<td>{_e(command.purpose)}</td>"
        f"<td>{_e(command.expected)}</td>"
        f"<td>{_e(command.prerequisites)}<br>{_e(command.impact)}</td>"
        "</tr>"
        for command in commands_for_report()
    )


    return f"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
 content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>تقرير SF — {_e(session.get('name'))}</title>
<style>
:root {{ color-scheme: dark; --bg:#0b1220; --panel:#111d2e; --line:#293b53;
  --text:#e7eef7; --muted:#9aacc2; --accent:#72ddca; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:34px; background:var(--bg); color:var(--text);
  font-family:"Noto Sans Arabic","Noto Sans",sans-serif; line-height:1.8; }}
main {{ max-width:1200px; margin:auto; }}
header,.panel {{ background:var(--panel); border:1px solid var(--line);
  border-radius:16px; padding:24px; margin-bottom:18px; }}
.brand {{ color:var(--accent); font-size:15px; font-weight:800; letter-spacing:2px; }}
h1 {{ margin:8px 0; font-size:30px; }}
h2 {{ margin:0 0 14px; font-size:19px; }}
.muted {{ color:var(--muted); }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; }}
.metric {{ background:#0c1727; border:1px solid var(--line); border-radius:12px;
  padding:14px; }}
.metric strong {{ display:block; color:var(--accent); font-size:19px; overflow-wrap:anywhere; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th,td {{ text-align:right; vertical-align:top; padding:12px; border-bottom:1px solid var(--line);
  overflow-wrap:anywhere; }}
th {{ color:var(--accent); background:#0c1727; }}
.empty {{ text-align:center; color:var(--muted); padding:28px; }}
.confidence {{ color:var(--accent); font-weight:800; }}
.payload-row td {{ padding-top:0; }}
summary {{ cursor:pointer; color:var(--muted); }}
pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#09111e;
  border-radius:8px; padding:12px; direction:ltr; text-align:left; }}
footer {{ color:var(--muted); text-align:center; font-size:12px; padding:18px; }}
@media print {{ body {{ background:#fff; color:#111; padding:10px; }}
  header,.panel {{ break-inside:avoid; background:#fff; color:#111; border-color:#bbb; }}
  th,td {{ border-color:#ccc; }} .metric {{ background:#f5f7fa; color:#111; }} }}
</style>
</head>
<body>
<main>
<header>
  <div class="brand">SF · SECURITY ASSESSMENT</div>
  <h1>تقرير جلسة التقييم</h1>
  <div class="muted">تقرير مستقل بصيغة HTML — لا يحتوي على موارد خارجية أو شيفرات تشغيلية</div>
</header>
<section class="panel">
  <h2>ملخص الجلسة</h2>
  <div class="grid">
    <div class="metric"><span class="muted">اسم الجلسة</span><strong>{_e(session.get('name'))}</strong></div>
    <div class="metric"><span class="muted">معرّف الجلسة</span><strong>{_e(session.get('id'))}</strong></div>
    <div class="metric"><span class="muted">الحالة</span><strong>{_e(status)}</strong></div>
    <div class="metric"><span class="muted">عدد الأدلة المسجلة</span><strong>{len(evidence)}</strong></div>
  </div>
  <p class="muted">تاريخ الإنشاء: {_e(session.get('created_at'))}</p>
  <p class="muted">آخر تحديث: {_e(session.get('updated_at'))}</p>
  <p class="muted">وقت إنشاء التقرير: {_e(created)}</p>
</section>
<section class="panel">
  <h2>ملخص درجات الخطورة المدخلة</h2>
  <p class="muted">يعرض هذا الملخص القيم المسجلة صراحةً في الأدلة، ولا ينشئ تصنيفاً تلقائياً.</p>
  <div class="grid">{severity_cards}</div>
</section>
<section class="panel">
  <h2>الأدلة والملاحظات المسجلة</h2>
  <p class="muted">يعرض هذا القسم السجلات الموجودة في قاعدة بيانات SF لهذه الجلسة فقط.
  مستوى الثقة المنقول هو القيمة المسجلة، وليس حكماً مستقلاً من التقرير.</p>
  <table>
    <thead><tr><th>#</th><th>الفئة</th><th>العنوان</th><th>التفاصيل</th>
      <th>المصدر</th><th>وقت التسجيل</th><th>الثقة</th></tr></thead>
    <tbody>{evidence_body}</tbody>
  </table>
</section>
<section class="panel">
  <h2>توصيات المراجعة والمعالجة</h2>
  <p class="muted">توصيات إرشادية مبنية على فئة السجل ودرجته المدخلة. راجع الدليل والسياق قبل اتخاذ إجراء.</p>
  <table>
    <thead><tr><th>الأولوية</th><th>التوصية</th><th>سببها</th><th>الخطوة المقترحة</th></tr></thead>
    <tbody>{recommendation_rows}</tbody>
  </table>
</section>
<section class="panel">
  <h2>أوامر تحقق محلية آمنة</h2>
  <p class="muted">الأوامر أدناه استعلامية على جهاز Kali المحلي. لا تنفذ فحصاً على هدف بعيد ولا تغيّر إعدادات النظام. اقرأ المتطلبات والنتيجة المتوقعة قبل تشغيل أي أمر يدوياً.</p>
  <table>
    <thead><tr><th>الغرض</th><th>الأمر</th><th>وظيفته</th><th>النتيجة المتوقعة</th><th>المتطلبات والأثر</th></tr></thead>
    <tbody>{command_rows}</tbody>
  </table>
</section>
<section class="panel">
  <h2>حدود التقرير</h2>
  <ul>
    <li>هذا التقرير يعكس البيانات المحفوظة في الجلسة وقت إنشائه فقط.</li>
    <li>غياب الأدلة لا يعني أن النظام أو الشبكة خاليان من المشكلات.</li>
    <li>لا تُعرض نتائج فحص لم تُنفذ، ولا تُستنتج ثغرات من بيانات غير موجودة.</li>
    <li>يجب مراجعة الأدلة ومصدرها قبل اتخاذ قرارات أمنية أو تشغيلية.</li>
  </ul>
</section>
<footer>SF Report v{REPORT_VERSION} · Generated { _e(created) }</footer>
</main>
</body>
</html>
"""


def generate_session_report(
    store: SFStore,
    session_id: str,
    output_dir: str | Path | None = None,
) -> Path:
    """Create or atomically refresh the single HTML report for one session."""
    try:
        session = store.get_session(session_id)
        if session is None:
            raise ReportError("الجلسة المطلوبة غير موجودة")
        evidence = store.list_evidence(session_id)
    except StoreError as exc:
        raise ReportError(str(exc)) from exc

    if len(evidence) > MAX_REPORT_EVIDENCE:
        raise ReportError(
            f"عدد الأدلة يتجاوز الحد الآمن للتقرير ({MAX_REPORT_EVIDENCE})"
        )

    destination = Path(output_dir) if output_dir is not None else (
        PROJECT_ROOT / "reports" / "output"
    )
    reports_parent = destination.parent
    try:
        if reports_parent.is_symlink() or destination.is_symlink():
            raise ReportError("مسار التقرير يحتوي على رابط رمزي غير مسموح")
        destination.mkdir(parents=True, exist_ok=True)
        if not destination.is_dir() or destination.is_symlink():
            raise ReportError("مجلد مخرجات التقرير غير صالح")
    except OSError as exc:
        raise ReportError(f"تعذر تجهيز مجلد التقرير: {exc}") from exc

    filename = f"SF-{session['id']}.html"
    final_path = destination / filename
    if final_path.is_symlink():
        raise ReportError("رفض الكتابة فوق ملف تقرير مرتبط برابط رمزي")

    temporary_path: Path | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{session['id']}-",
            suffix=".tmp",
            dir=destination,
            text=True,
        )
        temporary_path = Path(temp_name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(_render(session, evidence))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, final_path)
        temporary_path = None
        if os.name == "posix":
            final_path.chmod(0o600)
        return final_path
    except (OSError, ValueError) as exc:
        raise ReportError(f"تعذر إنشاء تقرير HTML: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
