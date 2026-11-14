"""Recon Orchestrator - Modern TUI v2"""
import asyncio
import os
from textual import work
from textual.app import App, ComposeResult
from textual.widgets import (
    Header, Footer, TabbedContent, TabPane, DataTable, Button,
    Static, RichLog, Input, Label, ProgressBar,
)
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer

from ui.tui.registry import get_phases
from ui.tui.subprocess_runner import run_phase_isolated


class PhaseTab(Container):
    """Self-contained phase: handles its own button clicks."""

    def __init__(self, spec, app_state):
        super().__init__(id=f"tab-{spec.key}")
        self.spec = spec
        self.app_state = app_state
        self._running = False

    def compose(self) -> ComposeResult:
        with Vertical(classes="card"):
            yield Label(f"{self.spec.icon}  {self.spec.arabic}", classes="card-title")
            yield Label(self.spec.english, classes="card-subtitle")
            yield Static(self.spec.description_ar, classes="card-desc")
        with Horizontal(classes="controls"):
            if self.spec.has_input:
                yield Input(
                    placeholder=self.spec.input_placeholder,
                    id=f"input-{self.spec.key}",
                    classes="target-input",
                )
            yield Button(
                f"▶  تشغيل المرحلة {self.spec.number}",
                id=f"btn-{self.spec.key}",
                classes="run-btn",
            )
            yield Button(
                "✕  مسح",
                id=f"clear-{self.spec.key}",
                classes="clear-btn",
            )
        yield Static("● جاهز", id=f"status-{self.spec.key}", classes="status ready")
        yield ProgressBar(id=f"progress-{self.spec.key}", show_eta=False)
        with ScrollableContainer(classes="log-box"):
            yield RichLog(id=f"log-{self.spec.key}", highlight=True, markup=True, wrap=True,
                          classes="phase-log")
        yield Container(id=f"results-{self.spec.key}", classes="results")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == f"btn-{self.spec.key}":
            self._start()
        elif bid == f"clear-{self.spec.key}":
            self._clear()

    def _start(self):
        if self._running:
            self._log("[yellow]⚠ المرحلة قيد التشغيل[/yellow]")
            return
        self._running = True
        self._work()

    @work(exclusive=True)
    async def _work(self):
        try:
            self._status(f"⏳ جاري التشغيل...", "running")
            self._progress(True)
            self._log(f"[bold cyan]{'━'*55}[/bold cyan]")
            self._log(f"[bold cyan]▶  {self.spec.arabic} / {self.spec.english}[/bold cyan]")

            target = self._get_input()
            result = await asyncio.to_thread(
                run_phase_isolated, self.spec.key, target
            )

            output = result.get("output", "")
            if output:
                for line in output.splitlines():
                    if "__JSON_" in line:
                        continue
                    self._log(line)

            if result.get("ok"):
                self._status(f"✓  اكتملت بنجاح", "ok")
                self._log("[bold green]✓  المرحلة اكتملت[/bold green]")
                self._render(result.get("result"))
            else:
                self._status(f"✗  فشلت", "err")
                self._log("[bold red]✗  المرحلة فشلت[/bold red]")
        except Exception as e:
            self._status(f"✗ خطأ: {e}", "err")
            self._log(f"[red]Exception: {type(e).__name__}: {e}[/red]")
        finally:
            self._running = False
            self._progress(False)

    def _render(self, data):
        if not data:
            return
        try:
            container = self.query_one(f"#results-{self.spec.key}", Container)
            for w in list(container.children):
                w.remove()

            if self.spec.key == "network" and isinstance(data, dict):
                ntype = data.get("network_type") or data.get("classification") or "unknown"
                conf = data.get("confidence", 0)
                try:
                    conf_pct = float(conf) * 100
                except (ValueError, TypeError):
                    conf_pct = 0
                panel = Static(
                    f"[bold cyan]النوع:[/bold cyan]  {ntype}\n"
                    f"[bold cyan]الثقة:[/bold cyan]  {conf_pct:.0f}%",
                    classes="result-panel",
                )
                container.mount(panel)
            elif self.spec.key == "discovery" and isinstance(data, list):
                table = DataTable()
                table.add_columns("IP", "MAC", "المصنّع", "النوع")
                for d in data:
                    table.add_row(
                        str(d.get("ip", "?")),
                        str(d.get("mac", "-"))[:17],
                        str(d.get("vendor", "-"))[:28],
                        str(d.get("device_type", "unknown")),
                    )
                container.mount(table)
            elif self.spec.key == "ports" and isinstance(data, dict):
                ports = data.get("ports", [])
                if ports:
                    table = DataTable()
                    table.add_columns("المنفذ", "البروتوكول", "الخدمة", "الإصدار", "الخطورة")
                    for p in ports:
                        ver = f"{p.get('product', '')} {p.get('version', '')}".strip()
                        table.add_row(
                            str(p.get("port", "?")),
                            str(p.get("protocol", p.get("proto", "?"))),
                            str(p.get("service", "?")),
                            ver[:30] or "-",
                            str(p.get("risk", "?")),
                        )
                    container.mount(table)
                else:
                    container.mount(Static("[yellow]لا توجد منافذ مفتوحة[/yellow]"))
            elif self.spec.key == "vulns" and isinstance(data, list):
                table = DataTable()
                table.add_columns("CVE", "الخطورة", "CVSS", "المنفذ")
                for v in data:
                    table.add_row(
                        str(v.get("cve", "?")),
                        str(v.get("severity", "?")),
                        str(v.get("cvss", "?")),
                        str(v.get("port", "?")),
                    )
                container.mount(table)
            elif self.spec.key == "exploit" and isinstance(data, list):
                table = DataTable()
                table.add_columns("CVE", "CVSS", "المنفذ")
                for p in data:
                    table.add_row(
                        str(p.get("cve", "?")),
                        str(p.get("cvss", "?")),
                        str(p.get("port", "?")),
                    )
                container.mount(table)
        except Exception as e:
            self._log(f"[yellow]ملاحظة عرض: {e}[/yellow]")

    def _get_input(self):
        if not self.spec.has_input:
            return ""
        try:
            return self.query_one(f"#input-{self.spec.key}", Input).value.strip()
        except Exception:
            return ""

    def _status(self, msg, kind):
        try:
            s = self.query_one(f"#status-{self.spec.key}", Static)
            s.update(msg)
            s.remove_class("ready", "running", "ok", "err")
            s.add_class(kind)
        except Exception:
            pass

    def _log(self, text):
        try:
            self.query_one(f"#log-{self.spec.key}", RichLog).write(text)
        except Exception:
            pass

    def _progress(self, on):
        try:
            pb = self.query_one(f"#progress-{self.spec.key}", ProgressBar)
            pb.display = on
            if on:
                pb.advance(40)
            else:
                pb.update(progress=0)
        except Exception:
            pass

    def _clear(self):
        try:
            self.query_one(f"#log-{self.spec.key}", RichLog).clear()
            c = self.query_one(f"#results-{self.spec.key}", Container)
            for w in list(c.children):
                w.remove()
            self._status("● جاهز", "ready")
        except Exception:
            pass


class ReconTUI(App):
    CSS = """
    Screen { background: #0d1117; color: #c9d1d9; }
    Header { background: #161b22; color: #58a6ff; text-style: bold; }
    Footer { background: #161b22; color: #8b949e; }
    TabbedContent { background: #0d1117; border: round #30363d; height: 1fr; }
    Tab { background: #161b22; color: #8b949e; text-style: bold; }
    Tab.-active { background: #0d1117; color: #58a6ff; text-style: bold underline; }
    Tab:hover { background: #21262d; }
    TabPane { background: #0d1117; padding: 1 2; height: 1fr; overflow-y: auto; }
    .card { background: #161b22; border: round #58a6ff; padding: 1 2; margin: 0 0 1 0; height: auto; }
    .card-title { color: #58a6ff; text-style: bold; height: 1; }
    .card-subtitle { color: #79c0ff; text-style: italic; height: 1; }
    .card-desc { color: #c9d1d9; margin-top: 1; }
    .controls { height: 3; margin: 1 0; align: left middle; }
    .run-btn { background: #238636; color: #ffffff; text-style: bold; min-width: 22; margin-right: 1; }
    .run-btn:hover { background: #2ea043; }
    .run-btn:focus { background: #2ea043; }
    .clear-btn { background: #21262d; color: #c9d1d9; min-width: 10; }
    .clear-btn:hover { background: #30363d; }
    .target-input { background: #0d1117; color: #c9d1d9; border: tall #30363d; margin-right: 1; width: 32; }
    .target-input:focus { border: tall #58a6ff; }
    .status { height: 1; padding: 0 1; text-style: bold; margin: 0 0 1 0; }
    .status.ready { color: #8b949e; background: #161b22; }
    .status.running { color: #d29922; background: #2d2000; }
    .status.ok { color: #3fb950; background: #0d2818; }
    .status.err { color: #f85149; background: #2d0f0f; }
    ProgressBar { height: 1; margin: 0 0 1 0; display: none; }
    ProgressBar > .bar--bar { color: #58a6ff; background: #161b22; }
    .log-box { background: #000000; border: round #21262d; height: 14; margin: 1 0; }
    .phase-log { background: #000000; color: #7ee787; padding: 1; }
    .results { height: auto; min-height: 5; margin: 1 0; }
    DataTable { background: #161b22; border: round #30363d; height: auto; max-height: 22; }
    DataTable > .datatable--header { background: #0d1117; color: #79c0ff; text-style: bold; }
    .result-panel { background: #161b22; border: round #3fb950; padding: 1 2; height: auto; }
    """

    BINDINGS = [
        ("q", "quit", "خروج"),
        ("ctrl+r", "reset", "إعادة"),
        ("ctrl+h", "help", "مساعدة"),
    ]

    def __init__(self):
        super().__init__()
        self.app_state = {"platform": os.environ.get("RECON_ENV", "kali"), "target": None}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        phases = get_phases()
        with TabbedContent(id="main-tabs"):
            for spec in phases:
                with TabPane(f"{spec.icon}  {spec.number}. {spec.arabic}", id=f"tab-{spec.key}"):
                    yield PhaseTab(spec, self.app_state)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Recon Orchestrator — Kali Edition"
        self.sub_title = f"المنصة: {self.app_state['platform']}  |  جاهز"

    def action_reset(self) -> None:
        self.app_state["target"] = None
        self.notify("تمت إعادة التعيين", severity="information")

    def action_help(self) -> None:
        self.notify(
            "Q=خروج  |  Ctrl+R=إعادة  |  Ctrl+H=مساعدة  |  انقر تشغيل المرحلة",
            title="مساعدة", timeout=8,
        )


def main():
    os.environ.setdefault("RECON_ENV", "kali")
    os.environ.setdefault("RECON_CONFIG_DIR", "kali/config")
    os.environ.setdefault("RECON_PLUGINS_DIR", "kali/plugins")
    try:
        from kali.hooks import install_network_hook
        install_network_hook()
    except Exception:
        pass
    ReconTUI().run()


if __name__ == "__main__":
    main()
