"""Welcome screen."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Center, Middle
from textual.screen import Screen
from textual.widgets import Static

from core.privilege import detect as detect_priv
from core.scope import Scope


class WelcomeScreen(Screen):
    """Welcome/banner screen."""

    BINDINGS = [
        ("enter", "continue", "Continue"),
        ("ctrl+j", "continue", "Continue"),
        ("ctrl+m", "continue", "Continue"),
        ("space", "continue", "Continue"),
        ("c", "continue", "Continue"),
        ("escape", "quit_app", "Quit"),
        ("q", "quit_app", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        try:
            scope_repr = repr(Scope())
        except Exception as e:
            scope_repr = f"[red]Scope error: {e}[/red]"
        priv = detect_priv()

        banner = (
            "[bold cyan]"
            "\u2566\u2550\u2557\u2554\u2550\u2557\u2554\u2550\u2557\u2554\u2550\u2557\u2554\u2557\u2554  "
            "\u2554\u2550\u2557\u2566\u2550\u2557\u2554\u2550\u2557\u2566 \u2566\u2554\u2550\u2557\u2554\u2550\u2557\u2566\u2566\u2557"
            "\u2566\u2550\u2557\u2554\u2550\u2557\u2566\u2566\u2557\u2554\u2550\u2557\u2566\u2550\u2557\n"
            "[/bold cyan]"
        )
        # Fallback ASCII banner (ASCII-safe across all terminals)
        banner = (
            "[bold cyan]"
            "  ___  ___ ___  ___  _  _     ___ ___ ___  _  _ ___ ___ ___ _____ ___ ___\n"
            " | _ \\| __/ __|/ _ \\| \\| |   / _ \\| _ \\ __| | | / __| __|_   _| _ \\ __|\n"
            " |   /| _| (__| (_) | .` |  | (_) |   / _|| |_| \\__ \\ _| | | |   / _` |\n"
            " |_|_\\|___\\___|\\___/|_|\\_|   \\___/|_|_\\___|\\___/|___/___| |_| |_|\\__|\n"
            "[/bold cyan]"
        )

        yield Middle(
            Center(
                Static(banner),
                Static("[bold]Recon Orchestrator[/bold]  v0.3.1"),
                Static(""),
                Static(f"[dim]Scope:[/dim] {scope_repr}"),
                Static(f"[dim]Privilege:[/dim] {priv.summary}"),
                Static(""),
                Static("[yellow]Press ENTER / SPACE / C to continue  •  ESC or Q to quit[/yellow]"),
                Static("[dim]Termux hint: if ENTER does nothing, press CTRL then J[/dim]"),
                Static(""),
                Static("[dim]\u26a0 Use ONLY on authorized networks. See config/scope.txt[/dim]"),
            )
        )

    def on_key(self, event) -> None:
        """Catch all 'continue' keys — Termux soft Enter sends \\n (ctrl+j)."""
        if event.key in ("enter", "ctrl+j", "ctrl+m", "space", "c"):
            event.prevent_default()
            event.stop()
            self.action_continue()
        elif event.key in ("escape", "q"):
            event.prevent_default()
            event.stop()
            self.action_quit_app()

    def action_continue(self) -> None:
        self.app.open_main()

    def action_quit_app(self) -> None:
        self.app.exit()
