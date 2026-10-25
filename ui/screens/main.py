"""Main screen with phases and live log."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Label, ListItem, ListView, Static

from core.logger import get_logger
from core.privilege import detect as detect_priv
from core.session import Session

from ui.widgets.log_panel import LogPanel


PHASES = [
    ("p1", "1. Network Type Detection"),
    ("p2", "2. Discovery"),
    ("p3", "3. Target Selection"),
    ("p4", "4. Port Scan"),
    ("p5", "5. Vulnerability Scan"),
    ("p6", "6. Safe Exploitation"),
    ("p7", "7. Reporting"),
]


class PhaseItem(ListItem):
    """One phase entry in the sidebar list."""

    def __init__(self, phase_id: str, label: str) -> None:
        self.phase_id = phase_id
        self.phase_label = label
        super().__init__(Label(label))


class MainScreen(Screen):
    """Main working screen."""

    BINDINGS = [
        ("q", "quit_app", "Quit"),
        ("escape", "quit_app", "Quit"),
        ("r", "refresh_status", "Refresh"),
        ("ctrl+j", "activate_selected", "Activate"),
        ("space", "activate_selected", "Activate"),
    ]

    def __init__(self, session: Session, demo: bool = False) -> None:
        super().__init__()
        self.session = session
        self.demo = demo
        self.log = get_logger("main")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Static("[bold cyan]Phases[/bold cyan]", id="phases_title")
                yield ListView(
                    *[PhaseItem(pid, label) for pid, label in PHASES],
                    id="phase_list",
                )
                yield Static("", id="hint")
            with Vertical(id="main_area"):
                yield Static("", id="status_bar")
                yield LogPanel(id="log")
        yield Footer()

    def on_mount(self) -> None:
        self._update_status()
        try:
            self.query_one("#hint", Static).update(
                "[dim]Termux: ↑/↓ to move • CTRL+J or SPACE to select • Q to quit[/dim]"
            )
        except Exception:
            pass
        self.log_line("info", f"Session: {self.session.id}")
        if self.demo:
            self.log_line("warn", "DEMO MODE - no real scans will run")
        self.log_line("info", "Ready. Select a phase from the list.")

    def _update_status(self) -> None:
        try:
            sb = self.query_one("#status_bar", Static)
            priv = detect_priv()
            sb.update(
                f"[bold]Target:[/bold] (unset)  |  "
                f"[bold]Session:[/bold] {self.session.id}  |  "
                f"[bold]Platform:[/bold] Termux  |  "
                f"[bold]Root:[/bold] {'yes' if priv.is_root else 'no'}  |  "
                f"[bold]Demo:[/bold] {'yes' if self.demo else 'no'}"
            )
        except Exception:
            pass

    def log_line(self, level: str, message: str) -> None:
        try:
            panel = self.query_one("#log", LogPanel)
            panel.log_line(level, message)
        except Exception:
            pass
        try:
            logger = getattr(self.log, level, self.log.info)
            logger(message)
        except Exception:
            pass

    def on_key(self, event) -> None:
        """Termux-safe key handler — soft Enter sends ctrl+j."""
        if event.key in ("q", "escape"):
            event.prevent_default()
            event.stop()
            self.action_quit_app()
        elif event.key == "r":
            event.prevent_default()
            event.stop()
            self.action_refresh_status()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if isinstance(item, PhaseItem):
            self.log_line("info", f"Selected: {item.phase_label}")
            if self.demo:
                self.log_line("warn", "Demo mode - phase not executed")
            else:
                self.log_line("warn", "Phase not implemented yet")

    def action_activate_selected(self) -> None:
        """Activate currently selected phase (Termux fallback for Enter)."""
        try:
            lv = self.query_one("#phase_list", ListView)
        except Exception:
            return
        idx = lv.index
        if idx is None or idx < 0:
            idx = 0
        try:
            lv.index = idx
        except Exception:
            pass
        item = PHASES[idx] if 0 <= idx < len(PHASES) else None
        if item:
            pid, label = item
            self.log_line("info", f"Selected: {label}")

            if self.demo:
                self.log_line("warn", "Demo mode - phase not executed")
            else:
                self.log_line("warn", "Phase not implemented yet")

    def action_quit_app(self) -> None:
        self.app.exit()

    def action_refresh_status(self) -> None:
        self._update_status()
        self.log_line("info", "Status refreshed")
