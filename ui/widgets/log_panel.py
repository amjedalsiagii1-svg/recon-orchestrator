"""Live log panel widget."""
from __future__ import annotations

from rich.text import Text
from textual.widgets import RichLog


_LEVEL_COLORS = {
    "debug": "dim",
    "info": "cyan",
    "warn": "yellow",
    "warning": "yellow",
    "error": "red",
    "critical": "bold red",
}


class LogPanel(RichLog):
    """RichLog with colored level labels."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.border_title = "Log"

    def log_line(self, level: str, message: str) -> None:
        color = _LEVEL_COLORS.get(level.lower(), "white")
        t = Text()
        t.append(f"[{level.upper():<5}]", style=f"bold {color}")
        t.append(" ")
        t.append(message)
        self.write(t)
