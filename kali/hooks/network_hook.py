"""Network Extended Info Hook"""
import os
import re
from rich.console import Console
from rich.panel import Panel


def show_extended_panel(network_type):
    import yaml
    cfg = os.environ.get("RECON_CONFIG_DIR", os.path.join(os.path.dirname(__file__), "..", "config"))
    yaml_path = os.path.join(cfg, "network_types.yaml")
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
    recs_txt = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(recs)) or "  (none)"
    det_txt = "\n".join(f"  • {d}" for d in det) or "  (none)"
    msg = (f"{icon} [bold]{ar}[/bold]\n\n[white]{desc}[/white]\n\n"
           f"[bold]Risk:[/bold] [{color}]{risk.upper()}[/{color}]\n\n"
           f"[bold yellow]Recommendations:[/bold yellow]\n{recs_txt}\n\n"
           f"[bold cyan]Detection indicators:[/bold cyan]\n{det_txt}")
    Console().print(Panel(msg, title=f"Kali Edition - {icon} {ar}", border_style="cyan"))


def install_network_hook():
    import rich.console as rc
    _orig = rc.Console.print
    _seen = set()

    def _patched(self, *args, **kwargs):
        _orig(self, *args, **kwargs)
        try:
            for arg in args:
                txt = str(arg)
                m = re.search(r'(?:Type|النوع):\s*([a-z_]+)', txt)
                if m:
                    ntype = m.group(1)
                    if ntype not in _seen:
                        _seen.add(ntype)
                        show_extended_panel(ntype)
                        break
        except Exception:
            pass

    rc.Console.print = _patched
    return True
