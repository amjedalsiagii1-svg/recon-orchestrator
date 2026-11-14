"""Run phases in isolated subprocess - robust, no stdin blocking"""
import subprocess
import json
import os
import sys

# Absolute path to project root
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_phase_isolated(phase_key, target=None):
    # Map key -> number
    key_to_n = {
        "network": "1", "discovery": "2", "target": "3",
        "ports": "4", "vulns": "5", "exploit": "6",
        "report": "7", "webscan": "8",
    }
    n = key_to_n.get(phase_key)
    if not n:
        return {"ok": False, "result": None, "output": f"Unknown phase: {phase_key}"}

    script = f'''
import sys, os
sys.path.insert(0, {_PROJECT_ROOT!r})
os.chdir({_PROJECT_ROOT!r})
try:
    from ui.tui.runners import run_p{n}
    state = {{"target": {target!r}}}
    result = run_p{n}(state)
    import json
    def clean(x, depth=0):
        if depth > 10: return "<max_depth>"
        if x is None or isinstance(x, (int, float, str, bool)): return x
        if isinstance(x, dict): return {{str(k): clean(v, depth+1) for k, v in x.items()}}
        if isinstance(x, (list, tuple)): return [clean(i, depth+1) for i in x]
        if hasattr(x, "__dict__"): return {{k: clean(v, depth+1) for k, v in vars(x).items()}}
        return str(x)
    print("__JSON_START__")
    print(json.dumps({{"ok": result.get("ok", False), "result": clean(result.get("result"))}}, default=str))
    print("__JSON_END__")
except Exception as e:
    import traceback
    traceback.print_exc()
    print("__JSON_START__")
    print(json.dumps({{"ok": False, "result": None, "error": str(e)}}))
    print("__JSON_END__")
'''

    try:
        r = subprocess.run(
            ["python3", "-c", script],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=_PROJECT_ROOT,
            stdin=subprocess.DEVNULL,   # ← الأهم: منع التعليق
        )
    except subprocess.TimeoutExpired as e:
        out = ""
        if e.stdout: out += e.stdout if isinstance(e.stdout, str) else e.stdout.decode("utf-8", "replace")
        if e.stderr: out += "\n" + (e.stderr if isinstance(e.stderr, str) else e.stderr.decode("utf-8", "replace"))
        return {"ok": False, "result": None, "output": f"TIMEOUT after 300s\n{out}"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Spawn error: {type(e).__name__}: {e}"}

    output = (r.stdout or "") + "\n" + (r.stderr or "")
    data = None
    in_json = False
    json_lines = []
    for line in output.splitlines():
        if line.strip() == "__JSON_START__":
            in_json = True
            continue
        if line.strip() == "__JSON_END__":
            break
        if in_json:
            json_lines.append(line)
    if json_lines:
        try:
            data = json.loads("\n".join(json_lines))
        except Exception:
            pass

    return {
        "ok": data.get("ok", False) if data else False,
        "result": data.get("result") if data else None,
        "output": output,
    }
