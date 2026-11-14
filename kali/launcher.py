"""Kali Edition launcher - Fixed hooks with proper Rich rendering"""
import sys
import os
import re

_here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _here not in sys.path:
    sys.path.insert(0, _here)

os.environ.setdefault("RECON_ENV", "kali")
os.environ.setdefault("RECON_CONFIG_DIR", os.path.join(_here, "kali", "config"))


# ============================================================
# Helper: Render Rich objects to plain text (ESSENTIAL!)
# ============================================================
def _render_arg_to_text(orig_print, console_self, arg):
    """Render any rich object to plain text via a captured console"""
    try:
        import io
        import rich.console as rc
        buf = io.StringIO()
        capture = rc.Console(
            record=True, width=300, file=buf,
            force_terminal=False, no_color=True, legacy_windows=False
        )
        orig_print(capture, arg)
        return capture.export_text()
    except Exception:
        try:
            return str(arg)
        except Exception:
            return ""


# ============================================================
# HOOK 1: Extended Network Info
# ============================================================
def _show_extended_panel(network_type):
    try:
        import yaml
        from rich.console import Console
        from rich.panel import Panel
        cfg = os.environ.get("RECON_CONFIG_DIR", os.path.join(_here, "kali", "config"))
        yaml_path = os.path.join(cfg, "network_types.yaml")
        if not os.path.exists(yaml_path):
            return
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f).get("network_types", {})
        info = data.get(str(network_type))
        if not info:
            return
        icon = info.get("icon", "*")
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
                    txt = _render_arg_to_text(_orig, self, arg)
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
# HOOK 2: Playbook + Report Enricher
# ============================================================
def _install_playbook_hook():
    try:
        import rich.console as rc
        _orig = rc.Console.print
        state = {"ports": [], "target": None, "shown": False, "report_done": False}

        def _extract_ports(txt):
            ports = set()
            # Match any vertical bar (light or heavy) followed by digits
            for m in re.finditer(r'[\u2502\u2503]\s*(\d{2,5})\s*[\u2502\u2503]\s*(tcp|udp)', txt, re.IGNORECASE):
                try:
                    ports.add(int(m.group(1)))
                except (ValueError, IndexError):
                    pass
            return sorted(ports)

        def _extract_target(txt):
            m = re.search(r'(?:Target|\u0627\u0644\u0647\u062f\u0641)\s*[:/]?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', txt)
            return m.group(1) if m else None

        def _patched(self, *args, **kwargs):
            _orig(self, *args, **kwargs)
            try:
                for arg in args:
                    txt = _render_arg_to_text(_orig, self, arg)
                    if not txt:
                        continue
                    # Extract target
                    t = _extract_target(txt)
                    if t:
                        state["target"] = t
                    # Extract ports
                    found = _extract_ports(txt)
                    if found:
                        for p in found:
                            if p not in state["ports"]:
                                state["ports"].append(p)
                        state["shown"] = False
                    # After Risk Summary -> show playbook
                    if ("Risk Summary" in txt or "\u0645\u0644\u062e\u0635 \u0627\u0644\u062e\u0637\u0648\u0631\u0629" in txt):
                        if state["ports"] and not state["shown"]:
                            state["shown"] = True
                            try:
                                from kali.playbook import build_playbook, display_playbook
                                target = state["target"] or "<target>"
                                pb = build_playbook(state["ports"], target)
                                if pb:
                                    display_playbook(pb, target)
                            except Exception:
                                pass
                    # After Report Ready -> enrich report
                    if ("Report Ready" in txt or "\u0627\u0644\u062a\u0642\u0631\u064a\u0631 \u062c\u0627\u0647\u0632" in txt):
                        if not state["report_done"]:
                            pm = re.search(r'(reports/output/[\w\-\.]+\.html)', txt)
                            if pm:
                                state["report_done"] = True
                                try:
                                    from kali.report_enricher import enrich_report_file
                                    target = state["target"] or "<target>"
                                    enrich_report_file(pm.group(1), state["ports"], target)
                                except Exception:
                                    pass
            except Exception:
                pass

        rc.Console.print = _patched
        return True
    except Exception:
        return False


# ============================================================
# HOOK 3: Web Scan Suggestion
# ============================================================
def _install_webscan_hook():
    try:
        import rich.console as rc
        from rich.panel import Panel
        _orig = rc.Console.print
        state = {"ports": [], "target": None, "suggested": False}

        def _extract_ports(txt):
            ports = set()
            for m in re.finditer(r'[\u2502\u2503]\s*(\d{2,5})\s*[\u2502\u2503]\s*(tcp|udp)', txt, re.IGNORECASE):
                try:
                    ports.add(int(m.group(1)))
                except (ValueError, IndexError):
                    pass
            return sorted(ports)

        def _extract_target(txt):
            m = re.search(r'(?:Target|\u0627\u0644\u0647\u062f\u0641)\s*[:/]?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', txt)
            return m.group(1) if m else None

        def _patched(self, *args, **kwargs):
            _orig(self, *args, **kwargs)
            try:
                for arg in args:
                    txt = _render_arg_to_text(_orig, self, arg)
                    if not txt:
                        continue
                    t = _extract_target(txt)
                    if t:
                        state["target"] = t
                    for p in _extract_ports(txt):
                        if p not in state["ports"]:
                            state["ports"].append(p)
                    if ("Risk Summary" in txt or "\u0645\u0644\u062e\u0635 \u0627\u0644\u062e\u0637\u0648\u0631\u0629" in txt):
                        http_ports = [p for p in state["ports"] if p in (80, 443, 8080, 8443, 3000, 5000, 8000, 9000)]
                        if http_ports and state["target"] and not state["suggested"]:
                            state["suggested"] = True
                            msg = (
                                f"[bold yellow]WEB SERVICE DETECTED[/bold yellow]\n\n"
                                f"Target: [cyan]{state['target']}[/cyan]\n"
                                f"HTTP ports: [green]{', '.join(map(str, http_ports))}[/green]\n\n"
                                f"[bold]Run web scan now?[/bold]\n"
                                f"  [green]bash kali/webscan.sh {state['target']}[/green]\n\n"
                                f"[dim]Quick scan:[/dim]\n"
                                f"  [green]bash kali/webscan.sh {state['target']} --fast[/green]"
                            )
                            rc.Console().print(Panel(msg, title="Web Recon Available", border_style="yellow"))
            except Exception:
                pass

        rc.Console.print = _patched
        return True
    except Exception:
        return False


# ============================================================
# INSTALL HOOKS (order: webscan first, then playbook, then extended-info)
# ============================================================
_hooks = []
if _install_webscan_hook():
    _hooks.append("webscan-suggest")
if _install_playbook_hook():
    _hooks.append("playbook")
if _install_output_hook():
    _hooks.append("extended-info")

if _hooks:
    print("\033[92m[OK] Kali Edition hooks: " + ", ".join(_hooks) + "\033[0m")

# ============================================================
# RUN CLI
# ============================================================
from ui.cli import main
sys.exit(main())
