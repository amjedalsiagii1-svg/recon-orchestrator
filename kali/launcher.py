"""Kali Edition launcher - Multi-strategy hook with diagnostics"""
import sys
import os
import inspect

_here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _here not in sys.path:
    sys.path.insert(0, _here)

os.environ.setdefault("RECON_ENV", "kali")
os.environ.setdefault("RECON_CONFIG_DIR", os.path.join(_here, "kali", "config"))


def _extract_network_type(result):
    if result is None:
        return None
    if isinstance(result, str):
        return result
    for attr in ("network_type", "classification", "type"):
        v = getattr(result, attr, None)
        if v:
            return v
    if isinstance(result, dict):
        for k in ("network_type", "classification", "type"):
            if k in result and result[k]:
                return result[k]
    if isinstance(result, tuple):
        for item in result:
            v = _extract_network_type(item)
            if v:
                return v
    return None


def _show_extended(result):
    try:
        network_type = _extract_network_type(result)
        if not network_type:
            if os.environ.get("KALI_DEBUG"):
                print(f"\033[93m[KALI DEBUG] result={type(result).__name__} attrs={[a for a in dir(result) if not a.startswith('_')][:8]}\033[0m")
            return
        import yaml
        from rich.console import Console
        from rich.panel import Panel
        config_dir = os.environ.get("RECON_CONFIG_DIR", "kali/config")
        yaml_path = os.path.join(config_dir, "network_types.yaml")
        if not os.path.exists(yaml_path):
            return
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f).get("network_types", {})
        info = data.get(str(network_type))
        if not info:
            return
        icon = info.get("icon", "🔍")
        ar = info.get("ar", network_type)
        desc = info.get("description", "")
        risk = info.get("risk", "unknown")
        recs = info.get("recommendations", [])
        det = info.get("detection", [])
        color = {"low": "green", "medium": "yellow", "high": "red",
                 "very_high": "bright_red", "critical": "bright_red"}.get(risk, "white")
        recs_txt = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(recs)) or "  (لا توجد)"
        det_txt = "\n".join(f"  • {d}" for d in det) or "  (لا توجد)"
        msg = (f"{icon} [bold]{ar}[/bold]\n\n[white]{desc}[/white]\n\n"
               f"[bold]المخاطر:[/bold] [{color}]{risk.upper()}[/{color}]\n\n"
               f"[bold yellow]⚠️ التوصيات الأمنية:[/bold yellow]\n{recs_txt}\n\n"
               f"[bold cyan]🔎 مؤشرات الكشف:[/bold cyan]\n{det_txt}")
        Console().print(Panel(msg, title=f"📡 Kali Edition — {icon} {ar}", border_style="cyan"))
    except Exception as e:
        if os.environ.get("KALI_DEBUG"):
            print(f"\033[91m[KALI ERROR] {e}\033[0m")


# STRATEGY 1: Hook p1_network_type
_hooked = False
try:
    import phases.p1_network_type as p1
    for fn_name in ('detect', 'run', 'classify', 'analyze', 'detect_network_type'):
        if hasattr(p1, fn_name) and callable(getattr(p1, fn_name)):
            _orig = getattr(p1, fn_name)
            _is_async = inspect.iscoroutinefunction(_orig)
            if _is_async:
                async def _wrapped(*a, __orig=_orig, **kw):
                    r = await __orig(*a, **kw)
                    _show_extended(r)
                    return r
            else:
                def _wrapped(*a, __orig=_orig, **kw):
                    r = __orig(*a, **kw)
                    _show_extended(r)
                    return r
            setattr(p1, fn_name, _wrapped)
            print(f"\033[92m✅ Kali Edition: hooked p1.{fn_name}\033[0m")
            _hooked = True
            break
    if not _hooked:
        funcs = [a for a in dir(p1) if not a.startswith('_') and callable(getattr(p1, a)) and not isinstance(getattr(p1, a), type)]
        print(f"\033[93m⚠ Kali Edition: p1 functions = {funcs}\033[0m")
except Exception as e:
    print(f"\033[91m⚠ Kali Edition: {e}\033[0m")

from ui.cli import main
sys.exit(main())
