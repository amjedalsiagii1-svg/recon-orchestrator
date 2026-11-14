"""TUI v6 - Bulletproof app with error capture and size check"""
import asyncio
import os
import sys
import shutil
import traceback
from datetime import datetime
from textual import work
from textual.app import App, ComposeResult
from textual.widgets import (
    Header, Footer, TabbedContent, TabPane, DataTable, Button,
    Static, RichLog, Input, Label, ProgressBar,
)
from textual.containers import Container, Horizontal, Vertical

from ui.tui.registry import get_phases
from ui.tui.runners import (
    run_p1, run_p2, run_p3, run_p4, run_p5, run_p6, run_p7, run_p8,
)

RUNNERS = {
    "network": run_p1, "discovery": run_p2, "target": run_p3,
    "ports": run_p4, "vulns": run_p5, "exploit": run_p6,
    "report": run_p7, "webscan": run_p8,
}

_DEBUG = "/tmp/tui_debug.log"


def _dlog(msg):
    try:
        with open(_DEBUG, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
    except Exception:
        pass


class PhaseTab(Container):
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
                yield Input(placeholder=self.spec.input_placeholder,
                            id=f"input-{self.spec.key}", classes="target-input")
            yield Button(f"▶  تشغيل المرحلة {self.spec.number}",
                         id=f"btn-{self.spec.key}", classes="run-btn")
            yield Button("✕  مسح", id=f"clear-{self.spec.key}", classes="clear-btn")
        yield Static("● جاهز", id=f"status-{self.spec.key}", classes="status ready")
        yield ProgressBar(id=f"progress-{self.spec.key}", show_eta=False)
        yield RichLog(id=f"log-{self.spec.key}", highlight=True, markup=True, wrap=True,
                      classes="phase-log")
        yield Container(id=f"results-{self.spec.key}", classes="results")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        _dlog(f"Button pressed: {bid}")
        if bid == f"btn-{self.spec.key}":
            self._start()
        elif bid == f"clear-{self.spec.key}":
            self._clear()

    def _start(self):
        if self._running:
            return
        self._running = True
        self._run_phase_async()

    @work(exclusive=True)
    async def _run_phase_async(self):
        _dlog(f"START phase {self.spec.key}")
        try:
            self._status("⏳ جاري التشغيل...", "running")
            self._log("[bold cyan]━━━ بدء التشغيل ━━━[/bold cyan]")

            target = self._get_input()
            runner = RUNNERS.get(self.spec.key)
            if not runner:
                self._log(f"[red]No runner for {self.spec.key}[/red]")
                self._status("✗ runner مفقود", "err")
                return

            self._log("[yellow]⏳ جاري التنفيذ...[/yellow]")
            
            # Direct call via thread
            result = await asyncio.to_thread(runner, self.app_state, target=target)
            _dlog(f"Runner returned ok={result.get('ok')}")

            output = result.get("output", "") or ""
            for line in output.splitlines():
                if line.strip():
                    self._log(line)

            if result.get("ok"):
                self._status("✓ اكتملت", "ok")
                self._log("[bold green]✓ اكتملت[/bold green]")
                self._render_result(result.get("result"))
            else:
                self._status("✗ فشلت", "err")
                self._log("[bold red]✗ فشلت[/bold red]")
        except Exception as e:
            _dlog(f"EXCEPTION: {traceback.format_exc()}")
            self._status("✗ خطأ", "err")
            self._log(f"[red]{traceback.format_exc()}[/red]")
        finally:
            self._running = False

    def _render_result(self, data):
        if not data: return
        try:
            container = self.app.query_one(f"#results-{self.spec.key}", Container)
            for w in list(container.children): w.remove()
            
            if self.spec.key == "network" and isinstance(data, dict):
                ntype = data.get("network_type", "unknown")
                try: conf = float(data.get("confidence", 0)) * 100
                except: conf = 0
                container.mount(Static(
                    f"[bold cyan]النوع:[/bold cyan] {ntype}\n[bold cyan]الثقة:[/bold cyan] {conf:.0f}%",
                    classes="result-panel"))
            elif self.spec.key == "discovery" and isinstance(data, list):
                t = DataTable(); t.add_columns("IP", "MAC", "المصنّع", "النوع")
                for d in data:
                    t.add_row(str(d.get("ip","?")), str(d.get("mac","-"))[:17],
                              str(d.get("vendor","-"))[:28], str(d.get("device_type","?")))
                container.mount(t)
            elif self.spec.key == "ports" and isinstance(data, dict):
                ports = data.get("ports", [])
                if ports:
                    t = DataTable(); t.add_columns("المنفذ","البروتوكول","الخدمة","الإصدار","الخطورة")
                    for p in ports:
                        ver = f"{p.get('product','')} {p.get('version','')}".strip()
                        t.add_row(str(p.get("port","?")), str(p.get("protocol",p.get("proto","?"))),
                                  str(p.get("service","?")), ver[:30] or "-", str(p.get("risk","?")))
                    container.mount(t)
            elif self.spec.key == "vulns" and isinstance(data, list):
                t = DataTable(); t.add_columns("CVE","الخطورة","CVSS","المنفذ")
                for v in data:
                    t.add_row(str(v.get("cve","?")), str(v.get("severity","?")),
                              str(v.get("cvss","?")), str(v.get("port","?")))
                container.mount(t)
        except Exception as e:
            _dlog(f"render_result: {e}")

    def _get_input(self):
        if not self.spec.has_input: return ""
        try: return self.app.query_one(f"#input-{self.spec.key}", Input).value.strip()
        except: return ""

    def _status(self, msg, kind):
        try:
            s = self.app.query_one(f"#status-{self.spec.key}", Static)
            s.update(msg)
            s.remove_class("ready", "running", "ok", "err")
            s.add_class(kind)
        except: pass

    def _log(self, text):
        try: self.app.query_one(f"#log-{self.spec.key}", RichLog).write(text)
        except: pass

    def _progress(self, on):
        try:
            pb = self.app.query_one(f"#progress-{self.spec.key}", ProgressBar)
            pb.display = on
        except: pass

    def _clear(self):
        try:
            self.app.query_one(f"#log-{self.spec.key}", RichLog).clear()
            c = self.app.query_one(f"#results-{self.spec.key}", Container)
            for w in list(c.children): w.remove()
            self._status("● جاهز", "ready")
        except: pass


class ReconTUI(App):
    CSS = """
    Screen { background: #0d1117; color: #c9d1d9; }
    Header { background: #161b22; color: #58a6ff; text-style: bold; }
    Footer { background: #161b22; color: #8b949e; }
    TabbedContent { background: #0d1117; border: round #30363d; height: 1fr; }
    Tab { background: #161b22; color: #8b949e; text-style: bold; }
    Tab.-active { background: #0d1117; color: #58a6ff; text-style: bold underline; }
    TabPane { background: #0d1117; padding: 1 2; height: 1fr; overflow-y: auto; }
    .card { background: #161b22; border: round #58a6ff; padding: 1 2; margin: 0 0 1 0; height: auto; }
    .card-title { color: #58a6ff; text-style: bold; height: 1; }
    .card-subtitle { color: #79c0ff; text-style: italic; height: 1; }
    .card-desc { color: #c9d1d9; margin-top: 1; }
    .controls { height: 3; margin: 1 0; align: left middle; }
    .run-btn { background: #238636; color: #ffffff; text-style: bold; min-width: 22; margin-right: 1; }
    .run-btn:hover { background: #2ea043; }
    .clear-btn { background: #21262d; color: #c9d1d9; min-width: 10; }
    .target-input { background: #0d1117; color: #c9d1d9; border: tall #30363d; margin-right: 1; width: 32; }
    .target-input:focus { border: tall #58a6ff; }
    .status { height: 1; padding: 0 1; text-style: bold; margin: 0 0 1 0; }
    .status.ready { color: #8b949e; background: #161b22; }
    .status.running { color: #d29922; background: #2d2000; }
    .status.ok { color: #3fb950; background: #0d2818; }
    .status.err { color: #f85149; background: #2d0f0f; }
    ProgressBar { height: 1; margin: 0 0 1 0; display: none; }
    .phase-log { background: #000000; color: #7ee787; border: round #21262d; height: 16; margin: 1 0; padding: 1; }
    .results { height: auto; min-height: 3; margin: 1 0; }
    DataTable { background: #161b22; border: round #30363d; height: auto; max-height: 22; }
    DataTable > .datatable--header { background: #0d1117; color: #79c0ff; text-style: bold; }
    .result-panel { background: #161b22; border: round #3fb950; padding: 1 2; height: auto; }
    """
    BINDINGS = [("q", "quit", "خروج"), ("ctrl+r", "reset", "إعادة"), ("ctrl+h", "help", "مساعدة")]

    def __init__(self):
        super().__init__()
        self.app_state = {"platform": os.environ.get("RECON_ENV", "kali"), "target": None}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(id="main-tabs"):
            for spec in get_phases():
                with TabPane(f"{spec.icon}  {spec.number}. {spec.arabic}", id=f"tab-{spec.key}"):
                    yield PhaseTab(spec, self.app_state)
        yield Footer()

    def on_mount(self):
        self.title = "Recon Orchestrator — Kali Edition"
        _dlog("TUI mounted successfully")

    def action_reset(self):
        self.app_state["target"] = None
        self.notify("تمت إعادة التعيين", severity="information")

    def action_help(self):
        self.notify("Q=خروج | Ctrl+R=إعادة", title="مساعدة", timeout=8)


def main():
    # 1. Terminal Size Check (Textual crashes if too small)
    size = shutil.get_terminal_size()
    _dlog(f"Terminal size: {size.columns}x{size.lines}")
    
    if size.lines < 20 or size.columns < 60:
        print("=" * 60)
        print("❌ خطأ: نافذة الطرفية صغيرة جداً")
        print(f"   الحجم الحالي: {size.columns} عرض × {size.lines} طول")
        print("   المطلوب: 60+ عرض × 20+ طول")
        print("\nالحل: قم بتكبير نافذة الطرفية (Maximize) ثم أعد المحاولة.")
        print("=" * 60)
        sys.exit(1)

    os.environ.setdefault("RECON_ENV", "kali")
    os.environ.setdefault("RECON_CONFIG_DIR", "kali/config")
    os.environ.setdefault("RECON_PLUGINS_DIR", "kali/plugins")

    _dlog("=" * 50)
    _dlog("TUI Main starting...")
    _dlog(f"Python: {sys.executable}")
    _dlog(f"TTY: {sys.stdout.isatty()}")
    _dlog(f"TERM: {os.environ.get('TERM')}")

    try:
        from kali.hooks import install_network_hook
        install_network_hook()
    except Exception as e:
        _dlog(f"Hooks failed: {e}")

    try:
        app = ReconTUI()
        app.run()
    except Exception as e:
        tb = traceback.format_exc()
        _dlog(f"FATAL CRASH: {tb}")
        print("\n" + "=" * 60)
        print("❌ انهارت الواجهة:")
        print(f"{e}")
        print("=" * 60)
        print("التفاصيل في: /tmp/tui_debug.log")
        sys.exit(1)

if __name__ == "__main__":
    main()
