"""Recon Orchestrator - Professional TUI (Textual)"""
import asyncio
import os
import sys
from rich.console import Console

from textual import work
from textual.app import App, ComposeResult
from textual.widgets import (
    Header, Footer, TabbedContent, TabPane, DataTable, Button,
    Static, RichLog, Input, Label, LoadingIndicator,
)
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer

from ui.tui.registry import get_phases


class PhaseTab(Container):
    """A single phase tab: Run button + input (optional) + output log."""

    def __init__(self, spec, app_state):
        super().__init__(id=f"tab-{spec.key}")
        self.spec = spec
        self.app_state = app_state

    def compose(self) -> ComposeResult:
        yield Label(f"[bold]{self.spec.arabic}[/bold] — {self.spec.english}",
                    classes="phase-title")
        yield Static(self.spec.description, classes="phase-desc")
        with Horizontal(classes="controls"):
            if self.spec.has_input:
                yield Input(placeholder=self.spec.input_placeholder, id=f"input-{self.spec.key}")
            yield Button(f"Run Phase {self.spec.number}", id=f"btn-{self.spec.key}", variant="success")
        yield Static("", id=f"status-{self.spec.key}", classes="status")
        yield RichLog(id=f"log-{self.spec.key}", highlight=True, markup=True, wrap=True)

    def get_input_value(self) -> str:
        if not self.spec.has_input:
            return ""
        try:
            return self.query_one(f"#input-{self.spec.key}", Input).value.strip()
        except Exception:
            return ""

    def set_status(self, msg: str, kind: str = "info"):
        color = {"info": "cyan", "ok": "green", "err": "red"}.get(kind, "white")
        try:
            self.query_one(f"#status-{self.spec.key}", Static).update(
                f"[{color}]{msg}[/{color}]"
            )
        except Exception:
            pass

    def log(self, text: str):
        try:
            self.query_one(f"#log-{self.spec.key}", RichLog).write(text)
        except Exception:
            pass


class ReconTUI(App):
    """Recon Orchestrator - Main TUI Application"""

    CSS = """
    Screen {
        background: #0d1117;
        color: #c9d1d9;
    }
    Header {
        background: #161b22;
        color: #58a6ff;
    }
    Footer {
        background: #161b22;
        color: #8b949e;
    }
    TabbedContent {
        background: #0d1117;
        border: solid #30363d;
    }
    TabPane {
        padding: 1 2;
        background: #0d1117;
    }
    .phase-title {
        color: #58a6ff;
        text-style: bold;
        margin-bottom: 1;
    }
    .phase-desc {
        color: #8b949e;
        margin-bottom: 1;
    }
    .controls {
        height: auto;
        margin: 1 0;
    }
    Button {
        background: #238636;
        color: white;
        margin-right: 1;
    }
    Button:hover {
        background: #2ea043;
    }
    Button:disabled {
        background: #30363d;
        color: #6e7681;
    }
    Input {
        background: #0d1117;
        border: solid #30363d;
        color: #c9d1d9;
        margin-right: 1;
    }
    Input:focus {
        border: solid #58a6ff;
    }
    .status {
        height: 1;
        margin: 1 0;
        color: #8b949e;
    }
    RichLog {
        background: #000000;
        border: solid #30363d;
        height: 1fr;
        min-height: 8;
    }
    DataTable {
        background: #161b22;
        border: solid #30363d;
    }
    LoadingIndicator {
        color: #58a6ff;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+r", "reset_state", "Reset"),
        ("ctrl+h", "help", "Help"),
    ]

    def __init__(self):
        super().__init__()
        self.app_state = {
            "platform": os.environ.get("RECON_ENV", "kali"),
            "target": None,
            "devices": [],
            "scan_result": None,
            "vulns": None,
            "network_type": None,
            "session": None,
        }

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        phases = get_phases()
        with TabbedContent(initial="tab-network"):
            for spec in phases:
                with TabPane(f"{spec.number}. {spec.arabic}", id=f"tab-{spec.key}"):
                    yield PhaseTab(spec, self.app_state)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Recon Orchestrator — Kali Edition"
        self.sub_title = f"Platform: {self.app_state['platform']} | Session ready"

    # ---------- Event Handlers ----------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if not btn_id.startswith("btn-"):
            return
        phase_key = btn_id[4:]  # strip "btn-"
        tab = self._find_tab(phase_key)
        if not tab:
            return

        # Run phase in worker
        self._run_phase(phase_key, tab)

    async def action_reset_state(self) -> None:
        self.app_state["target"] = None
        self.app_state["devices"] = []
        self.app_state["scan_result"] = None
        self.app_state["vulns"] = None
        self.notify("State reset", severity="information")

    def action_help(self) -> None:
        self.notify(
            "Shortcuts: Ctrl+R=Reset | Q=Quit | Click 'Run' to execute",
            title="Help", severity="information", timeout=8
        )

    # ---------- Worker: Run Phase ----------

    @work(exclusive=True)
    async def _run_phase(self, phase_key: str, tab: PhaseTab) -> None:
        spec = tab.spec
        btn = tab.query_one(f"#btn-{spec.key}", Button)
        btn.disabled = True
        tab.set_status(f"⏳ Running {spec.english}...", "info")
        tab.log(f"[cyan]▶ Starting {spec.english}[/cyan]")

        try:
            input_val = tab.get_input_value()
            kwargs = {"target": input_val} if input_val else {}

            # Run in thread to avoid blocking event loop
            result = await asyncio.to_thread(spec.runner, self.app_state, **kwargs)

            ok = result.get("ok", False)
            output = result.get("output", "")

            if output:
                tab.log(output)

            if ok:
                tab.set_status(f"✓ {spec.english} completed", "ok")
                tab.log(f"[green]✓ Success[/green]")
                self._render_result(tab, spec, result.get("result"))
            else:
                tab.set_status(f"✗ {spec.english} failed", "err")
                tab.log(f"[red]✗ Failed[/red]")

        except Exception as e:
            tab.set_status(f"✗ Error: {e}", "err")
            tab.log(f"[red]✗ Exception: {type(e).__name__}: {e}[/red]")
        finally:
            btn.disabled = False

    def _render_result(self, tab: PhaseTab, spec, result) -> None:
        """Render structured result based on phase type."""
        try:
            if spec.key == "discovery" and result:
                table = DataTable()
                table.add_columns("IP", "MAC", "Vendor", "Type")
                for d in result:
                    table.add_row(
                        str(getattr(d, "ip", "?")),
                        str(getattr(d, "mac", "-")),
                        str(getattr(d, "vendor", "-"))[:20],
                        str(getattr(d, "device_type", "-")),
                    )
                tab.log("[bold cyan]📋 Discovered Devices:[/bold cyan]")
                tab.mount(table)
            elif spec.key == "ports" and result:
                ports = getattr(result, "ports", [])
                if ports:
                    table = DataTable()
                    table.add_columns("Port", "Proto", "Service", "Version", "Risk")
                    for p in ports:
                        table.add_row(
                            str(getattr(p, "port", "?")),
                            str(getattr(p, "protocol", "?")),
                            str(getattr(p, "service", "?")),
                            str(getattr(p, "product", "")) + " " + str(getattr(p, "version", "")),
                            str(getattr(p, "risk", "?")),
                        )
                    tab.log("[bold cyan]📋 Open Ports:[/bold cyan]")
                    tab.mount(table)
            elif spec.key == "vulns" and result:
                table = DataTable()
                table.add_columns("CVE", "Severity", "CVSS", "Port")
                for v in result:
                    table.add_row(
                        str(getattr(v, "cve", "?")),
                        str(getattr(v, "severity", "?")),
                        str(getattr(v, "cvss", "?")),
                        str(getattr(v, "port", "?")),
                    )
                tab.log("[bold cyan]📋 Vulnerabilities:[/bold cyan]")
                tab.mount(table)
        except Exception as e:
            tab.log(f"[yellow]Render note: {e}[/yellow]")

    def _find_tab(self, phase_key: str):
        try:
            tabs = self.query_all(PhaseTab)
            for t in tabs:
                if t.spec.key == phase_key:
                    return t
        except Exception:
            pass
        return None


def main():
    # Ensure env
    os.environ.setdefault("RECON_ENV", "kali")
    os.environ.setdefault("RECON_CONFIG_DIR", "kali/config")
    os.environ.setdefault("RECON_PLUGINS_DIR", "kali/plugins")

    # Load hooks for extended info
    try:
        from kali.hooks import install_network_hook
        install_network_hook()
    except Exception:
        pass

    app = ReconTUI()
    app.run()


if __name__ == "__main__":
    main()
