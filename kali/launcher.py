"""Kali Edition launcher - Output interception strategy"""
import sys
import os
import re

_here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _here not in sys.path:
    sys.path.insert(0, _here)

os.environ.setdefault("RECON_ENV", "kali")
os.environ.setdefault("RECON_CONFIG_DIR", os.path.join(_here, "kali", "config"))


def _show_extended_panel(network_type):
    """عرض اللوحة العربية الموسعة"""
    try:
        import yaml
        from rich.console import Console
        from rich.panel import Panel
        config_dir = os.environ.get("RECON_CONFIG_DIR", os.path.join(_here, "kali", "config"))
        yaml_path = os.path.join(config_dir, "network_types.yaml")
        if not os.path.exists(yaml_path):
            if os.environ.get("KALI_DEBUG"):
                print(f"[KALI] yaml not found: {yaml_path}")
            return
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f).get("network_types", {})
        info = data.get(str(network_type))
        if not info:
            if os.environ.get("KALI_DEBUG"):
                print(f"[KALI] no info for: {network_type}")
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
            print(f"[KALI] show error: {e}")


def _install_output_hook():
    """Intercept Console.print and detect classification panel"""
    try:
        import rich.console as rc
        _orig_print = rc.Console.print
        _seen_types = set()

        def _render_to_text(console, obj):
            """Render rich object to plain text"""
            try:
                import io
                buf = io.StringIO()
                tmp_console = rc.Console(record=True, width=250, file=buf, force_terminal=False)
                _orig_print(tmp_console, obj)
                return tmp_console.export_text()
            except Exception:
                return str(obj)

        def _patched_print(self, *args, **kwargs):
            _orig_print(self, *args, **kwargs)
            try:
                for arg in args:
                    text = _render_to_text(self, arg)
                    # Look for network_type classification output
                    m = re.search(r'(?:Type|النوع):\s*([a-z_]+)', text)
                    if m:
                        ntype = m.group(1)
                        # Only show if it's a known extended type not yet shown
                        if ntype in _seen_types:
                            continue
                        _seen_types.add(ntype)
                        _show_extended_panel(ntype)
                        break
            except Exception as e:
                if os.environ.get("KALI_DEBUG"):
                    print(f"[KALI] print hook: {e}")

        rc.Console.print = _patched_print
        return True
    except Exception as e:
        if os.environ.get("KALI_DEBUG"):
            print(f"[KALI] hook install error: {e}")
        return False


# Install hook BEFORE importing ui.cli
if _install_playbook_hook():
    print("\033[92mPlaybook Hook installed\033[0m")
if _show_service_commands_hook():
    print("\033[92mCommands Hook installed\033[0m")
if _install_output_hook():
    print("\033[92m✅ Kali Edition: Output Interception Hook installed\033[0m")
else:
    print("\033[91m⚠️ Kali Edition: hook failed\033[0m")



# ---- Service Commands Hook ----
def _show_service_commands_hook():
    """After P4 port scan, show commands for detected services"""
    try:
        import os, yaml
        from rich.console import Console
        from rich.panel import Panel
        
        def _find_service_yaml(service_name):
            cmd_dir = os.path.join(_here, "kali", "plugins", "commands")
            if not os.path.exists(cmd_dir):
                return None
            fpath = os.path.join(cmd_dir, f"{service_name}.yaml")
            if os.path.exists(fpath):
                return fpath
            return None
        
        def _display_cmds(service_name):
            fpath = _find_service_yaml(service_name)
            if not fpath:
                return
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            cmds = data.get("commands", {})
            console = Console()
            output = ""
            for cat, clist in cmds.items():
                output += f"\n[bold yellow]{cat.replace('_',' ').title()}:[/bold yellow]\n"
                for c in clist[:3]:
                    output += f"  [green]{c}[/green]\n"
            console.print(Panel(output, title=f"Commands for {service_name}", border_style="green"))
        
        import rich.console as rc
        _orig = rc.Console.print
        _seen = set()
        
        def _patched(self, *args, **kwargs):
            _orig(self, *args, **kwargs)
            try:
                for arg in args:
                    text = str(arg)
                    # Detect service in port scan output
                    if "Port" in text and "Service" in text:
                        continue
                    for svc in ("ssh", "ftp", "http", "smb", "mysql", "rdp", "dns"):
                        if svc in text.lower() and svc not in _seen:
                            _seen.add(svc)
                            _display_cmds(svc)
                            break
            except Exception:
                pass
        
        rc.Console.print = _patched
        return True
    except Exception:
        return False



# ---- Playbook Auto-Hook after P4 ----
def _install_playbook_hook():
    """Intercept P4 port scan output and show playbook"""
    try:
        import re
        import rich.console as rc
        _orig = rc.Console.print
        _last_scan = {"target": None, "ports": [], "shown": False}

        def _extract_ports(text):
            """Extract port numbers from port scan table"""
            ports = []
            for m in re.finditer(r'│\s*(\d{2,5})\s*│\s*(tcp|udp)', text):
                try:
                    ports.append(int(m.group(1)))
                except (ValueError, IndexError):
                    pass
            return ports

        def _patched(self, *args, **kwargs):
            _orig(self, *args, **kwargs)
            try:
                for arg in args:
                    txt = str(arg)
                    # Look for port scan result table
                    if "Open Ports" in txt or "profile:" in txt:
                        ports = _extract_ports(txt)
                        if ports:
                            _last_scan["ports"] = ports
                            _last_scan["shown"] = False
                    # When "Risk Summary" appears (end of scan), show playbook
                    if "Risk Summary" in txt or "ملخص الخطورة" in txt:
                        if _last_scan["ports"] and not _last_scan["shown"]:
                            _last_scan["shown"] = True
                            try:
                                from kali.playbook import build_playbook, display_playbook, save_playbook
                                import os
                                target = None
                                # Try to get target from env or default
                                target = os.environ.get("RECON_TARGET", "<target>")
                                pb = build_playbook(_last_scan["ports"], target)
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

from ui.cli import main
sys.exit(main())
