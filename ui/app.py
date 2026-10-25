"""Recon Orchestrator TUI — main application."""
from __future__ import annotations

import argparse

from textual.app import App

from core.logger import get_logger, setup_logging
from core.session import Session

from ui.screens.main import MainScreen
from ui.screens.welcome import WelcomeScreen


class ReconApp(App):
    """Main Textual application."""

    TITLE = "Recon Orchestrator"
    SUB_TITLE = "Security Operations Platform"

    CSS = """
    Screen { background: $surface; }
    #body { height: 1fr; }
    #sidebar { width: 34; border: solid $primary; padding: 1; }
    #main_area { width: 1fr; padding: 1; }
    #status_bar {
        height: 3; padding: 1;
        background: $primary-darken-2;
        color: $text;
        border: solid $primary;
    }
    #log { height: 1fr; border: solid $accent; padding: 1; }
    ListView { height: 1fr; }
    """

    def __init__(self, demo: bool = False) -> None:
        super().__init__()
        self.demo = demo
        self.session: Session | None = None

    async def on_mount(self) -> None:
        logger = get_logger("app")
        try:
            self.session = await Session.open("data/sessions.db")
            sid = await self.session.create("tui-session")
            setup_logging(session_id=sid)
            logger = get_logger("app")
            logger.info("session_created", session_id=sid)
        except Exception as e:
            logger.error("session_open_failed", error=str(e))
            self.session = None
        self.push_screen(WelcomeScreen())

    def open_main(self) -> None:
        if self.session is None:
            try:
                self.notify("Session failed to open", severity="error")
            except Exception:
                pass
            return
        try:
            self.switch_screen(MainScreen(self.session, demo=self.demo))
        except Exception as e:
            get_logger("app").error("open_main_failed", error=str(e))

    async def on_unmount(self) -> None:
        if self.session:
            try:
                await self.session.close()
            except Exception:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(prog="ui.app")
    parser.add_argument("--demo", action="store_true", help="Demo mode")
    args, _unknown = parser.parse_known_args()
    ReconApp(demo=args.demo).run()


if __name__ == "__main__":
    main()
