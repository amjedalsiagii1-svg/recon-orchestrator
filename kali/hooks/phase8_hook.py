"""Phase 8: Web Application Scan - Triple-layered input interception"""
import re
import subprocess
from rich.panel import Panel


def install_phase8_hook():
    try:
        import rich.console as rc
        import builtins

        _orig_console_input = rc.Console.input
        _orig_builtin_input = builtins.input
        _orig_print = rc.Console.print
        _state = {"active": False, "in_console": False}

        def _is_phase8(txt):
            if not isinstance(txt, str):
                return False
            s = txt.strip()
            return s == "8" or s.startswith("8 ")

        def _run_scan(console, result):
            parts = result.strip().split(maxsplit=1)
            target = parts[1].strip() if len(parts) > 1 else ""
            _state["active"] = True
            try:
                if not target:
                    try:
                        target = _orig_builtin_input("Target IP: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        console.print("[yellow]Cancelled[/yellow]")
                        return
                if target and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                    console.print(Panel(
                        f"[bold cyan]🌐 Web Application Scan[/bold cyan]\n"
                        f"Target: [green]{target}[/green]\n"
                        f"[dim]Running 8 tools (3-10 min)...[/dim]",
                        border_style="cyan"
                    ))
                    try:
                        subprocess.run(["bash", "kali/webscan.sh", target], timeout=600)
                    except subprocess.TimeoutExpired:
                        console.print("[red]Web scan timed out (10 min)[/red]")
                    except Exception as e:
                        console.print(f"[red]Error: {e}[/red]")
                    console.print("\n[green]✓ Web scan complete. Press Enter to continue.[/green]")
                    try:
                        _orig_builtin_input()
                    except (EOFError, KeyboardInterrupt):
                        pass
                else:
                    console.print(f"[red]Invalid target IP: {target}[/red]")
            finally:
                _state["active"] = False

        def _maybe_intercept(result, console=None):
            if _state["active"]:
                return None
            if not _is_phase8(result):
                return None
            if console is None:
                from rich.console import Console
                console = Console()
            _run_scan(console, result)
            return "r"

        # Layer 1: Console.input
        def _patched_console_input(self, *args, **kwargs):
            _state["in_console"] = True
            try:
                result = _orig_console_input(self, *args, **kwargs)
            finally:
                _state["in_console"] = False
            intercepted = _maybe_intercept(result, self)
            return intercepted if intercepted is not None else result

        # Layer 2: builtins.input (fallback for direct input() calls)
        def _patched_builtin_input(prompt=""):
            if _state["in_console"] or _state["active"]:
                return _orig_builtin_input(prompt)
            result = _orig_builtin_input(prompt)
            intercepted = _maybe_intercept(result, None)
            return intercepted if intercepted is not None else result

        # Layer 3: Add menu line on every menu display
        def _patched_print(self, *args, **kwargs):
            _orig_print(self, *args, **kwargs)
            try:
                for arg in args:
                    txt = str(arg)
                    if "1-7 run phase" in txt and "8 Web" not in txt:
                        _orig_print(self, "[cyan]8[/cyan] Web App Scan  [dim]| [cyan]8 <ip>[/cyan] for quick start[/dim]")
                        break
            except Exception:
                pass

        rc.Console.input = _patched_console_input
        rc.Console.print = _patched_print
        builtins.input = _patched_builtin_input
        return True
    except Exception:
        return False
