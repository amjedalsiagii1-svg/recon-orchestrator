"""Kali Edition - Safe runtime patch. Does NOT modify ui/cli.py."""
import os

_PATCHED = False


def install() -> bool:
    """Install patch. Returns True on success, False on failure (silent)."""
    global _PATCHED
    if _PATCHED:
        return True
    try:
        import ui.cli as cli_module
        cli_class = _find_cli_class(cli_module)
        if not cli_class:
            return False
        if _patch_render(cli_class) or _patch_run_phase1(cli_class):
            _PATCHED = True
            return True
        return False
    except Exception:
        return False


def _find_cli_class(module):
    for name in ("CLI", "CLIApp", "ReconCLI", "App"):
        obj = getattr(module, name, None)
        if isinstance(obj, type) and hasattr(obj, "_run_phase1"):
            return obj
    for _, obj in vars(module).items():
        if isinstance(obj, type) and hasattr(obj, "_run_phase1"):
            return obj
    return None


def _patch_render(cli_class) -> bool:
    for method_name in ("_render_phase_result", "_show_result", "_render_result", "_display_result"):
        if hasattr(cli_class, method_name):
            original = getattr(cli_class, method_name)
            def wrapper(self, result, *args, **kwargs):
                out = original(self, result, *args, **kwargs)
                try:
                    if _has_network_type(result):
                        _show_extended(self, result)
                except Exception:
                    pass
                return out
            setattr(cli_class, method_name, wrapper)
            return True
    return False


def _patch_run_phase1(cli_class) -> bool:
    if not hasattr(cli_class, "_run_phase1"):
        return False
    original = cli_class._run_phase1
    import inspect
    if inspect.iscoroutinefunction(original):
        async def wrapper(self, *args, **kwargs):
            r = await original(self, *args, **kwargs)
            try:
                p1 = _find_p1_result(self)
                if p1:
                    _show_extended(self, p1)
            except Exception:
                pass
            return r
    else:
        def wrapper(self, *args, **kwargs):
            r = original(self, *args, **kwargs)
            try:
                p1 = _find_p1_result(self)
                if p1:
                    _show_extended(self, p1)
            except Exception:
                pass
            return r
    cli_class._run_phase1 = wrapper
    return True


def _find_p1_result(cli_instance):
    session = getattr(cli_instance, "session", None)
    if not session:
        return None
    for attr in ("p1", "p1_result", "network_result", "network_type_result", "classification"):
        r = getattr(session, attr, None)
        if _has_network_type(r):
            return r
    return None


def _has_network_type(result) -> bool:
    if result is None:
        return False
    if hasattr(result, "network_type"):
        return True
    if isinstance(result, dict) and "network_type" in result:
        return True
    return False


def _show_extended(cli_instance, result):
    import yaml
    from rich.panel import Panel

    network_type = (
        getattr(result, "network_type", None)
        or (result.get("network_type") if isinstance(result, dict) else None)
    )
    if not network_type:
        return

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
    ar_name = info.get("ar", network_type)
    desc = info.get("description", "")
    risk = info.get("risk", "unknown")
    recs = info.get("recommendations", [])
    det = info.get("detection", [])

    color = {"low": "green", "medium": "yellow", "high": "red",
             "very_high": "bright_red", "critical": "bright_red"}.get(risk, "white")

    recs_txt = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(recs)) or "  (لا توجد)"
    det_txt = "\n".join(f"  • {d}" for d in det) or "  (لا توجد)"

    msg = (
        f"{icon} [bold]{ar_name}[/bold]\n\n"
        f"[white]{desc}[/white]\n\n"
        f"[bold]المخاطر:[/bold] [{color}]{risk.upper()}[/{color}]\n\n"
        f"[bold yellow]⚠️ التوصيات:[/bold yellow]\n{recs_txt}\n\n"
        f"[bold cyan]🔎 الكشف:[/bold cyan]\n{det_txt}"
    )

    console = getattr(cli_instance, "console", None)
    if console is None:
        from rich.console import Console
        console = Console()

    console.print(Panel(msg, title=f"📡 Kali Edition — {icon} {ar_name}", border_style="cyan"))
