"""Kali Edition launcher - All hooks defined first, then installed, then run."""
import sys
import os
import re

_here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _here not in sys.path:
    sys.path.insert(0, _here)

os.environ.setdefault("RECON_ENV", "kali")
os.environ.setdefault("RECON_CONFIG_DIR", os.path.join(_here, "kali", "config"))


# ============================================================
# HOOK 1: Extended Network Info Panel
# ============================================================
def _show_extended_panel(network_type):
    try:
        import yaml
        from rich.console import Console
        from rich.panel import Panel
        config_dir = os.environ.get("RECON_CONFIG_DIR", os.path.join(_here, "kali", "config"))
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
        recs_txt = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(recs)) or "  (none)"
        det_txt = "\n".join(f"  - {d}" for d in det) or "  (none)"
        msg = (f"{icon} [bold]{ar}[/bold]\n\n[white]{desc}[/white]\n\n"
               f"[bold]Risk:[/bold] [{color}]{risk.upper()}[/{color}]\n\n"
               f"[bold yellow]Recommendations:[/bold yellow]\n{recs_txt}\n\n"
               f"[bold cyan]Detection indicators:[/bold cyan]\n{det_txt}")
        Console().print(Panel(msg, title=f"Kali Edition - {icon} {ar}", border_style="cyan"))
    except Exception:
        pass


def _install_output_hook():
    try:
        import rich.console as rc
        _orig = rc.Console.print
        _seen = set()

        def _patched(self, *args, **kwargs):
            _orig(self, *args, **kwargs)
            try:
                for arg in args:
                    txt = str(arg)
                    m = re.search(r'(?:Type|\u0627\u0644\u0646\u0648\u0639):\s*([a-z_]+)', txt)
                    if m:
                        ntype = m.group(1)
                        if ntype not in _seen:
                            _seen.add(ntype)
                            _show_extended_panel(ntype)
                            break
            except Exception:
                pass

        rc.Console.print = _patched
        return True
    except Exception:
        return False


# ============================================================
# HOOK 2: Playbook Auto-Suggest (after port scan)
# ============================================================
def _install_playbook_hook():
    try:
        import rich.console as rc
        _orig = rc.Console.print
        state = {"ports": [], "target": None, "shown": False}

        def _extract_ports(txt):
            ports = []
            for m in re.finditer(r'\u2502\s*(\d{2,5})\s*\u2502\s*(tcp|udp)', txt):
                try:
                    ports.append(int(m.group(1)))
                except (ValueError, IndexError):
                    pass
            return ports

        def _extract_target(txt):
            m = re.search(r'(?:Target|\u0627\u0644\u0647\u062f\u0641)\s*[:/]?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', txt)
            if m:
                return m.group(1)
            return None

        def _patched(self, *args, **kwargs):
            _orig(self, *args, **kwargs)
            try:
                for arg in args:
                    txt = str(arg)
                    t = _extract_target(txt)
                    if t:
                        state["target"] = t
                        state["shown"] = False
                    ports = _extract_ports(txt)
                    if ports:
                        state["ports"] = ports
                        state["shown"] = False
                    if ("Risk Summary" in txt or "\u0645\u0644\u062e\u0635 \u0627\u0644\u062e\u0637\u0648\u0631\u0629" in txt) and state["ports"] and not state["shown"]:
                        state["shown"] = True
                        try:
                            from kali.playbook import build_playbook, display_playbook
                            target = state["target"] or "<target>"
                            pb = build_playbook(state["ports"], target)
                            if pb:
                                display_playbook(pb, target)
                        except Exception:
                            pass
            except Exception:
                pass

        rc.Console.print = _patched
        return True
    except Exception:
        return False


# ============================================================
# INSTALL HOOKS (order matters for chaining)
# ============================================================
_hooks_installed = []
if _install_playbook_hook():
    _hooks_installed.append("playbook")
if _install_output_hook():
    _hooks_installed.append("extended-info")

if _hooks_installed:
    print("\033[92m[OK] Kali Edition hooks: " + ", ".join(_hooks_installed) + "\033[0m")


# ============================================================
# RUN CLI
# ============================================================
from ui.cli import main
sys.exit(main())
