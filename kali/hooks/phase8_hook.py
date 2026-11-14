"""Phase 8: Web Application Scan - Menu Option 8"""
import subprocess
from rich.console import Console
from rich.prompt import Prompt


def install_phase8_hook():
    """Patch the CLI to accept option 8 for web scan."""
    try:
        import ui.cli as cli_module
        cli_class = None
        for name in dir(cli_module):
            obj = getattr(cli_module, name)
            if isinstance(obj, type) and hasattr(obj, "_main_loop"):
                cli_class = obj
                break
        if not cli_class:
            return False
        # Find the method that reads choice - try common names
        for method_name in ("_read_choice", "_ask_choice", "_prompt_choice", "_get_choice"):
            if hasattr(cli_class, method_name):
                _orig = getattr(cli_class, method_name)
                def _patched(self, *args, __orig=_orig, **kwargs):
                    result = __orig(self, *args, **kwargs)
                    if isinstance(result, str) and result.strip().startswith("8"):
                        parts = result.strip().split(maxsplit=1)
                        target = parts[1] if len(parts) > 1 else ""
                        c = getattr(self, "console", Console())
                        if not target:
                            try:
                                target = Prompt.ask("Target IP")
                            except Exception:
                                return "r"
                        if target:
                            c.print(f"\n[bold cyan]🌐 Web Application Scan on {target}[/bold cyan]\n")
                            try:
                                subprocess.run(["bash", "kali/webscan.sh", target], timeout=600)
                            except subprocess.TimeoutExpired:
                                c.print("[red]Web scan timed out[/red]")
                            c.print("\n[green]Web scan complete.[/green]")
                            try:
                                Prompt.ask("Press Enter to continue", default="")
                            except Exception:
                                pass
                        return "r"
                    return result
                setattr(cli_class, method_name, _patched)
                return True
        return False
    except Exception:
        return False
