"""Web Scan Suggestion Hook"""
import re
from rich.panel import Panel
from ._utils import render_arg_to_text


def install_webscan_hook():
    import rich.console as rc
    _orig = rc.Console.print
    state = {"ports": [], "target": None, "suggested": False}

    def _extract_ports(txt):
        ports = set()
        for m in re.finditer(r'[│┃]\s*(\d{2,5})\s*[│┃]\s*(tcp|udp)', txt, re.IGNORECASE):
            try:
                ports.add(int(m.group(1)))
            except (ValueError, IndexError):
                pass
        return sorted(ports)

    def _extract_target(txt):
        m = re.search(r'(?:Target|الهدف)\s*[:/]?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', txt)
        return m.group(1) if m else None

    def _patched(self, *args, **kwargs):
        _orig(self, *args, **kwargs)
        try:
            for arg in args:
                txt = render_arg_to_text(_orig, self, arg)
                if not txt:
                    continue
                t = _extract_target(txt)
                if t:
                    state["target"] = t
                for p in _extract_ports(txt):
                    if p not in state["ports"]:
                        state["ports"].append(p)
                if "Risk Summary" in txt or "ملخص الخطورة" in txt:
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
