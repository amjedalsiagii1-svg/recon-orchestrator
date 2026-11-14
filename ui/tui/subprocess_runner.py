"""Run phases in isolated subprocess - zero stdout conflict with Textual"""
import subprocess
import json
import os


def run_phase_isolated(phase_key, target=None):
    n = phase_key[1:] if phase_key[0] == "p" else phase_key.replace("network", "1").replace("discovery", "2").replace("target", "3").replace("ports", "4").replace("vulns", "5").replace("exploit", "6").replace("report", "7").replace("webscan", "8")
    script = f'''
import sys
sys.path.insert(0, ".")
try:
    from ui.tui.runners import run_p{n}
    state = {{"target": {repr(target)}}}
    result = run_p{n}(state)
    import json
    def clean(x):
        if x is None: return None
        if hasattr(x, "__dict__"): return {{k: clean(v) for k, v in vars(x).items()}}
        if isinstance(x, (list, tuple)): return [clean(i) for i in x]
        if isinstance(x, dict): return {{str(k): clean(v) for k, v in x.items()}}
        if isinstance(x, (int, float, str, bool)): return x
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
            capture_output=True, text=True, timeout=600, cwd=os.getcwd(),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "result": None, "output": "Timed out"}
    except Exception as e:
        return {"ok": False, "result": None, "output": f"Spawn error: {e}"}

    output = r.stdout + "\n" + r.stderr
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
