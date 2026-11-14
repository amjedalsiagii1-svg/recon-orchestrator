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
        state = {"ports": [], "target": None, "shown": False, "report_done": False}

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
                    
                    # Enrich HTML report when it's generated
                    if ("Report Ready" in txt or "\u0627\u0644\u062a\u0642\u0631\u064a\u0631 \u062c\u0627\u0647\u0632" in txt) and state["ports"] and not state["report_done"]:
                        import re as _re
                        path_match = _re.search(r'(reports/output/[\w\-\.]+\.html)', txt)
                        if path_match:
                            state["report_done"] = True
                            try:
                                from kali.report_enricher import enrich_report_file
                                target = state["target"] or "<target>"
                                enrich_report_file(path_match.group(1), state["ports"], target)
                            except Exception:
                                pass
            except Exception:
                pass

        rc.Console.print = _patched
        return True
    except Exception:
        return False




# ---- Auto-suggest Web Scan after P4 ----
def _suggest_webscan_hook():
    try:
        import rich.console as rc
        from rich.panel import Panel
        _orig = rc.Console.print
        state = {"ports": [], "target": None, "suggested": False}

        def _patched(self, *args, **kwargs):
            _orig(self, *args, **kwargs)
            try:
                for arg in args:
                    txt = str(arg)
                    import re as _re
                    m = _re.search(r'(?:Target|\u0627\u0644\u0647\u062f\u0641)\s*[:/]?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', txt)
                    if m:
                        state["target"] = m.group(1)
                    for pm in _re.finditer(r'\u2502\s*(\d{2,5})\s*\u2502\s*(tcp|udp)', txt):
                        try:
                            state["ports"].append(int(pm.group(1)))
                        except (ValueError, IndexError):
                            pass
                    if ("Risk Summary" in txt or "\u0645\u0644\u062e\u0635 \u0627\u0644\u062e\u0637\u0648\u0631\u0629" in txt) and not state["suggested"]:
                        http_ports = [p for p in state["ports"] if p in (80, 443, 8080, 8443, 3000, 5000, 8000, 9000)]
                        if http_ports and state["target"]:
                            state["suggested"] = True
                            msg = (
                                f"[bold yellow]\ud83c\udf10 WEB SERVICE DETECTED[/bold yellow]\n\n"
                                f"Target: [cyan]{state['target']}[/cyan]\n"
                                f"HTTP ports: [green]{', '.join(map(str, http_ports))}[/green]\n\n"
                                f"[bold]Run web scan now?[/bold]\n"
                                f"  [green]bash kali/webscan.sh {state['target']}[/green]\n\n"
                                f"[dim]Or with --fast for quick scan:[/dim]\n"
                                f"  [green]bash kali/webscan.sh {state['target']} --fast[/green]"
                            )
                            rc.Console().print(Panel(msg, title="\ud83d\udd0d Web Recon Available", border_style="yellow"))
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
if _suggest_webscan_hook():
    _hooks_installed.append("webscan-suggest")
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
