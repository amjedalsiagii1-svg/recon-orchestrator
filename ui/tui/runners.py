"""Phase Runners - Auto-generated with async support"""
import asyncio
import inspect

def _run_async(func, *args, **kwargs):
    """Run async or sync function safely."""
    res = func(*args, **kwargs)
    if inspect.iscoroutine(res):
        try:
            # Try to get existing loop
            loop = asyncio.get_running_loop()
            # If in loop, create new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as ex:
                future = ex.submit(asyncio.run, res)
                return future.result(timeout=300)
        except RuntimeError:
            # No loop running - safe to use asyncio.run
            return asyncio.run(res)
    return res

def run_p1(state, **kw):
    from phases.p1_network_type import detect
    try:
        r = _run_async(detect)
        # Handle Phase1Result -> classification
        cls = getattr(r, "classification", None)
        if cls:
            ntype = str(getattr(cls, "type", "unknown"))
            conf = float(getattr(cls, "confidence", 0))
        else:
            ntype = str(getattr(r, "network_type", "unknown"))
            conf = float(getattr(r, "confidence", 0))
        state["network_type"] = ntype
        return {"ok": True, "result": {"network_type": ntype, "confidence": conf}, "output": f"Type: {ntype} (conf: {conf:.2f})"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}

def run_p2(state, **kw):
    from phases.p2_discovery import discover
    from core.scope import Scope
    try:
        scope = Scope.from_file("config/scope.txt")
        # Try calling with scope, or without
        try:
            devices = _run_async(discover, scope) or []
        except TypeError:
            devices = _run_async(discover) or []
        state["devices"] = devices
        return {"ok": bool(devices), "result": devices, "output": f"Found {len(devices)} device(s)"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}

def run_p3(state, target="", **kw):
    if not target: return {"ok": False, "result": None, "output": "Target required"}
    state["target"] = target
    return {"ok": True, "result": {"target": target}, "output": f"Target set: {target}"}

def run_p4(state, **kw):
    from phases.p4_port_scan import scan
    target = state.get("target") or "192.168.8.1"
    try:
        try:
            r = _run_async(scan, target, "quick")
        except TypeError:
            r = _run_async(scan, target)
        state["scan_result"] = r
        ports = getattr(r, "ports", []) if r else []
        return {"ok": r is not None, "result": r, "output": f"Scanned: {len(ports)} port(s) found"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}

def run_p5(state, **kw):
    from phases.p5_vuln_scan import scan
    target = state.get("target") or "192.168.8.1"
    try:
        ports = getattr(state.get("scan_result"), "ports", [])
        try:
            r = _run_async(scan, target, ports)
        except TypeError:
            r = _run_async(scan, target)
        state["vulns"] = r or []
        return {"ok": bool(r), "result": r, "output": f"{len(r or [])} vuln(s) found"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}

def run_p6(state, **kw):
    vulns = state.get("vulns")
    if not vulns: return {"ok": False, "result": None, "output": "Run Phase 5 first"}
    plans = [{"cve": getattr(v, "cve", "?"), "cvss": getattr(v, "cvss", 0), "port": getattr(v, "port", "?")} for v in vulns]
    return {"ok": True, "result": plans, "output": f"{len(plans)} plan(s)"}

def run_p7(state, **kw):
    return {"ok": False, "result": None, "output": "Use CLI for reports"}

def run_p8(state, **kw):
    import subprocess
    target = state.get("target") or "192.168.8.1"
    try:
        r = subprocess.run(["bash", "kali/webscan.sh", target], capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
        return {"ok": r.returncode == 0, "result": None, "output": r.stdout + r.stderr}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Error: {e}"}
