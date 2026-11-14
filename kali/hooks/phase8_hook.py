"""Phase 8: Web Application Scan via Console.input hook"""
import re
from rich.panel import Panel


def install_phase8_hook():
    try:
        import rich.console as rc
        import subprocess
        from ._utils import render_arg_to_text

        _orig_input = rc.Console.input
        _orig_print = rc.Console.print
        _state = {"active": False, "menu_shown": False}

        def _is_phase8(txt):
            if not isinstance(txt, str):
                return False
            s = txt.strip()
            return s == "8" or s.startswith("8 ")

        def _run_scan(console, result):
            parts = result.strip().split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else ""
            _state["active"] = True
            try:
                if not target:
                    target = _orig_input(console, "Target IP: ")
                if target and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target.strip()):
                    target = target.strip()
                    console.print(Panel(
                        f"[bold cyan]🌐 Web Application Scan[/bold cyan]\n"
                        f"Target: [green]{target}[/green]\n"
                        f"[dim]Running 8 tools (3-10 min)...[/dim]",
                        border_style="cyan"
                    ))
                    try:
                        subprocess.run(["bash", "kali/webscan.sh", target], timeout=600)
                    except subprocess.TimeoutExpired:
                        console.print("[red]Web scan timed out[/red]")
                    except Exception as e:
                        console.print(f"[red]Web scan error: {e}[/red]")
                    console.print("\n[green]✓ Web scan complete.[/green]")
                else:
                    console.print("[red]Invalid target IP[/red]")
            finally:
                _state["active"] = False

        def _patched_input(self, *args, **kwargs):
            result = _orig_input(self, *args, **kwargs)
            if not _state["active"] and _is_phase8(result):
                _run_scan(self, result)
                return "r"
            return result

        def _patched_print(self, *args, **kwargs):
            _orig_print(self, *args, **kwargs)
            try:
                if _state["menu_shown"]:
                    return
                for arg in args:
                    txt = render_arg_to_text(_orig_print, self, arg)
                    if "1-7 run phase" in txt and "8 Web" not in txt:
                        _orig_print(self, "[cyan]8[/cyan] Web App Scan  [dim]| [cyan]8 <ip>[/cyan] for quick start[/dim]")
                        _state["menu_shown"] = True
                        break
            except Exception:
                pass

        rc.Console.input = _patched_input
        rc.Console.print = _patched_print
        return True
    except Exception:
        return False
