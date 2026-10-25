"""HTML report generator with filename control + Downloads copy."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.exploit_db import get_all_cves, get_exploit
from core.session import Session


PHASE_ORDER = ("p1", "p2", "p3", "p4", "p5", "p6", "p7")

ACCESS_ORDER = {"none": 0, "info": 1, "user": 2, "www-data": 2,
                "admin": 3, "admin_panel": 3, "root": 4, "system": 4}




def _safe_network_profile() -> dict:
    try:
        from core.network_classifier import classify
        return classify().to_dict()
    except Exception:
        return {}

async def collect_session_data(session: Session) -> dict[str, Any]:
    row = await session.get()
    events = await session.list_events()
    phases: dict[str, Any] = {}
    for p in PHASE_ORDER:
        d = await session.get_phase_data(p)
        if d:
            phases[p] = d
    return {"session": row or {}, "phases": phases, "events": events}


def _enrich_vuln(v: dict[str, Any]) -> dict[str, Any]:
    """Attach exploit_details (incl. execution guide) to a vuln dict."""
    ve = dict(v)
    cve = v.get("id")
    entry = get_exploit(cve) if cve else None
    if not entry:
        ve["exploit"] = None
        return ve
    ag = entry.get("access_gained") or {}
    ex = entry.get("explanation") or {}
    eg = entry.get("execution_guide") or {}
    ve["exploit"] = {
        "module": entry["module"],
        "tool": entry["tool"],
        "skill": entry.get("skill_required", "unknown"),
        "access_level": ag.get("level", "unknown"),
        "access_user": ag.get("user"),
        "access_process": ag.get("process"),
        "persistence": ag.get("persistence"),
        "capabilities": list(ag.get("capabilities", [])),
        "limitations": list(ag.get("limitations", [])),
        "methods": list(entry.get("methods", [])),
        "post_exploit": list(entry.get("post_exploit", [])),
        "requirements": list(entry.get("requirements", [])),
        "rollback": list(entry.get("rollback", [])),
        "impact": entry.get("impact", ""),
        "risk_note": entry.get("risk_note", ""),
        "ethical": entry.get("ethical", ""),
        # NEW:
        "simple_explanation": ex.get("simple", ""),
        "how_it_works": list(ex.get("how_it_works", [])),
        "attack_vector": ex.get("attack_vector", ""),
        "prerequisites": list(eg.get("prerequisites", [])),
        "steps": list(eg.get("steps", [])),
        "verification": list(eg.get("verification", [])),
        "cleanup": list(eg.get("cleanup", [])),
        "warnings": list(eg.get("warnings", [])),
    }
    return ve


def build_context(data: dict[str, Any]) -> dict[str, Any]:
    phases = data["phases"]
    p1 = phases.get("p1") or {}
    p2 = phases.get("p2") or {}
    p3 = phases.get("p3") or {}
    p4 = phases.get("p4") or {}
    p5 = phases.get("p5") or {}

    raw_vulns = p5.get("vulns") or []
    ports = p4.get("ports") or []
    devices = p2.get("devices") or []

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in raw_vulns:
        s = (v.get("severity") or "info").lower()
        sev[s] = sev.get(s, 0) + 1

    vulns = [_enrich_vuln(v) for v in raw_vulns]

    # Exploitation potential summary
    exploit_vulns = [v for v in vulns if v.get("exploit")]
    max_access = "none"
    total_methods = 0
    total_post = 0
    for v in exploit_vulns:
        e = v["exploit"]
        total_methods += len(e["methods"])
        total_post += len(e["post_exploit"])
        lvl = e["access_level"]
        if ACCESS_ORDER.get(lvl, 0) > ACCESS_ORDER.get(max_access, 0):
            max_access = lvl

    # Remediation sorted critical -> info
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    remediation = sorted(
        [
            {
                "cve": v.get("id"),
                "severity": (v.get("severity") or "info").lower(),
                "remediation": v.get("remediation") or "No specific remediation recorded.",
                "cvss": v.get("cvss") or 0,
            }
            for v in vulns
        ],
        key=lambda r: (order.get(r["severity"], 9), -(r["cvss"] or 0)),
    )

    target = p3.get("ip") or p5.get("target") or "unknown"

    return {
        "session_id": (data["session"].get("id") or "unknown"),
        "target": target,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "network": p1.get("network") or {},
        "classification": p1.get("classification") or {},
        "devices": devices,
        "ports": ports,
        "vulns": vulns,
        "severity": sev,
        "events": data["events"],
        "remediation": remediation,
        "exploit_vulns_count": len(exploit_vulns),
        "max_access": max_access,
        "total_methods": total_methods,
        "total_post": total_post,
        "all_cves": get_all_cves(),
        "network_profile": _safe_network_profile(),
    }


def render_report(
    data: dict[str, Any],
    template_dir: Path,
    output_path: Path,
) -> Path:
    template_dir = Path(template_dir)
    tpl = template_dir / "summary.html.j2"
    if not tpl.exists():
        raise FileNotFoundError(f"template not found: {tpl}")

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("summary.html.j2")
    html = template.render(**build_context(data))

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


async def generate(
    session: Session,
    out_dir: str | Path = "reports/output",
    template_dir: str | Path = "reports/templates",
    filename: str | None = None,
) -> Path:
    data = await collect_session_data(session)
    fname = filename or f"recon-{session.id or 'unknown'}.html"
    return render_report(data, Path(template_dir), Path(out_dir) / fname)
