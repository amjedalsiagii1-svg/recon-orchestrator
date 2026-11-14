"""Phase Runners - Direct calls, output isolated by subprocess wrapper"""
def run_p1(state, **kw):
    from phases.p1_network_type import detect
    try:
        r = detect()
        ntype = str(getattr(r, "network_type", None) or getattr(r, "classification", "unknown"))
        state["network_type"] = ntype
        return {"ok": True, "result": r, "output": f"Type: {ntype}"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}


def run_p2(state, **kw):
    from phases.p2_discovery import scan
    from core.scope import Scope
    try:
        scope = Scope.from_file("config/scope.txt")
        devices = scan(scope) or []
        state["devices"] = devices
        return {"ok": bool(devices), "result": devices, "output": f"Found {len(devices)} device(s)"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}


def run_p3(state, target="", **kw):
    if not target:
        return {"ok": False, "result": None, "output": "Target required"}
    state["target"] = target
    return {"ok": True, "result": target, "output": f"Target: {target}"}


def run_p4(state, **kw):
    from phases.p4_port_scan import scan
    target = state.get("target")
    if not target:
        return {"ok": False, "result": None, "output": "Set target first"}
    try:
        r = scan(target, "quick")
        state["scan_result"] = r
        return {"ok": bool(r), "result": r, "output": f"Ports scanned"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}


def run_p5(state, **kw):
    from phases.p5_vuln_scan import scan
    target = state.get("target")
    if not target:
        return {"ok": False, "result": None, "output": "Set target first"}
    try:
        ports = getattr(state.get("scan_result"), "ports", [])
        r = scan(target, ports)
        state["vulns"] = r
        return {"ok": bool(r), "result": r, "output": f"{len(r or [])} vuln(s)"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}


def run_p6(state, **kw):
    vulns = state.get("vulns")
    if not vulns:
        return {"ok": False, "result": None, "output": "Run Phase 5 first"}
    plans = [{"cve": getattr(v, "cve", "?"), "cvss": getattr(v, "cvss", 0),
              "port": getattr(v, "port", "?")} for v in vulns]
    return {"ok": True, "result": plans, "output": f"{len(plans)} plan(s)"}


def run_p7(state, **kw):
    return {"ok": False, "result": None,
            "output": "Use CLI (bash run.sh → 7) for reports with session context"}


def run_p8(state, **kw):
    import subprocess
    target = state.get("target")
    if not target:
        return {"ok": False, "result": None, "output": "Set target first"}
    try:
        r = subprocess.run(["bash", "kali/webscan.sh", target],
                          capture_output=True, text=True, timeout=600)
        return {"ok": r.returncode == 0, "result": None, "output": r.stdout + r.stderr}
    except subprocess.TimeoutExpired:
        return {"ok": False, "result": None, "output": "Timed out (10 min)"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}
