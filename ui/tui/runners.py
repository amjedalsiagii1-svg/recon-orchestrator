"""Phase Runners - Wrap existing phase logic for TUI"""
import io
import os
import contextlib
from typing import Any


def _capture(fn, *args, **kwargs):
    """Run fn while capturing stdout; return (result, output_text)."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            result = fn(*args, **kwargs)
        return result, buf.getvalue()
    except Exception as e:
        return None, f"[ERROR] {type(e).__name__}: {e}"


def run_p1(state: dict, **kw):
    from phases.p1_network_type import detect
    result, out = _capture(detect)
    if result:
        ntype = getattr(result, "network_type", None) or getattr(result, "classification", None)
        if ntype:
            state["network_type"] = str(ntype)
    return {"result": result, "output": out, "ok": result is not None}


def run_p2(state: dict, **kw):
    from phases.p2_discovery import scan
    from core.scope import Scope
    scope = state.get("scope") or Scope.from_file("config/scope.txt")
    devices, out = _capture(scan, scope)
    state["devices"] = devices or []
    return {"result": devices, "output": out, "ok": bool(devices)}


def run_p3(state: dict, target: str = "", **kw):
    if not target:
        return {"result": None, "output": "No target provided", "ok": False}
    state["target"] = target
    return {"result": target, "output": f"Target set: {target}", "ok": True}


def run_p4(state: dict, **kw):
    from phases.p4_port_scan import scan
    target = state.get("target")
    if not target:
        return {"result": None, "output": "Set target first (Phase 3)", "ok": False}
    result, out = _capture(scan, target, "quick")
    state["scan_result"] = result
    return {"result": result, "output": out, "ok": result is not None}


def run_p5(state: dict, **kw):
    from phases.p5_vuln_scan import scan
    target = state.get("target")
    if not target:
        return {"result": None, "output": "Set target first", "ok": False}
    ports = getattr(state.get("scan_result"), "ports", [])
    result, out = _capture(scan, target, ports)
    state["vulns"] = result
    return {"result": result, "output": out, "ok": bool(result)}


def run_p6(state: dict, **kw):
    vulns = state.get("vulns")
    if not vulns:
        return {"result": None, "output": "Run Phase 5 first", "ok": False}
    plans = []
    try:
        for v in vulns:
            plans.append({
                "cve": getattr(v, "cve", "?"),
                "cvss": getattr(v, "cvss", 0),
                "port": getattr(v, "port", "?"),
            })
    except Exception as e:
        return {"result": None, "output": f"Error: {e}", "ok": False}
    return {"result": plans, "output": f"{len(plans)} plan(s). Use CLI for interaction.", "ok": True}


def run_p7(state: dict, **kw):
    from phases.p7_report import generate
    from core.session import Session
    try:
        session = state.get("session")
        if not session:
            return {"result": None, "output": "No session", "ok": False}
        result, out = _capture(generate, session)
        return {"result": result, "output": out, "ok": True}
    except Exception as e:
        return {"result": None, "output": f"Error: {e}", "ok": False}


def run_p8(state: dict, **kw):
    import subprocess
    target = state.get("target")
    if not target:
        return {"result": None, "output": "Set target first", "ok": False}
    try:
        r = subprocess.run(
            ["bash", "kali/webscan.sh", target],
            capture_output=True, text=True, timeout=600,
        )
        return {"result": True, "output": r.stdout + r.stderr, "ok": r.returncode == 0}
    except subprocess.TimeoutExpired:
        return {"result": None, "output": "Timed out (10 min)", "ok": False}
    except Exception as e:
        return {"result": None, "output": f"Error: {e}", "ok": False}
