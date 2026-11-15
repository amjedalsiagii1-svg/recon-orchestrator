"""Recon Orchestrator - Enterprise TUI v10"""
import os
import sys
import traceback
from textual import work
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Input, RichLog, Static, LoadingIndicator
from textual.containers import Horizontal, Vertical, ScrollableContainer

from ui.tui.runners import (
    run_p1, run_p2, run_p3, run_p4, run_p5, run_p6, run_p7, run_p8,
)

PHASES = {
    "1": ("🌐 كشف الشبكة", run_p1),
    "2": ("📡 اكتشاف الأجهزة", run_p2),
    "3": ("🎯 اختيار الهدف", run_p3),
    "4": ("🔍 فحص المنافذ", run_p4),
    "5": ("⚠️ فحص الثغرات", run_p5),
    "6": ("💥 الاستغلال", run_p6),
    "7": ("📄 التقرير", run_p7),
    "8": ("🌍 فحص الويب", run_p8),
}

class ReconTUI(App):
    CSS = """
    Screen { background: #0d1117; color: #c9d1d9; }
    
    /* Header & Footer */
    Header { background: #161b22; color: #58a6ff; text-style: bold; }
    Footer { background: #161b22; color: #8b949e; }
    
    /* Sidebar */
    #sidebar { width: 30; background: #161b22; border-right: vkey #30363d; padding: 1; }
    #sidebar-title { text-align: center; color: #58a6ff; text-style: bold; margin-bottom: 1; }
    Button { width: 100%; margin-bottom: 1; background: #21262d; color: #c9d1d9; border: none; }
    Button:hover { background: #30363d; }
    Button:focus { background: #58a6ff; color: #000; text-style: bold; }
    
    /* Main Area */
    #main { padding: 1 2; }
    #target-bar { height: 3; margin-bottom: 1; align: left middle; }
    #target-label { width: 15; content-align: left middle; }
    #target-input { width: 1fr; margin-right: 1; background: #0d1117; color: #3fb950; border: tall #30363d; }
    #target-input:focus { border: tall #58a6ff; }
    
    /* Status & Loading */
    #status-bar { height: 3; margin-bottom: 1; }
    #spinner { width: 5; display: none; color: #d29922; }
    #status-text { width: 1fr; content-align: left middle; color: #d29922; text-style: bold; }
    
    /* Log */
    #log { height: 1fr; background: #000000; border: round #30363d; color: #7ee787; padding: 1; }
    """

    BINDINGS = [("q", "quit", "خروج"), ("c", "clear_log", "مسح السجل")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("الأدوات المتاحة", id="sidebar-title")
                for key, (label, _) in PHASES.items():
                    yield Button(f"{label}", id=f"btn-{key}")
            
            with Vertical(id="main"):
                with Horizontal(id="target-bar"):
                    yield Static("الهدف (IP):", id="target-label")
                    yield Input(placeholder="192.168.8.1", value="192.168.8.1", id="target-input")
                
                with Horizontal(id="status-bar"):
                    yield LoadingIndicator(id="spinner")
                    yield Static("● جاهز للبدء", id="status-text")
                
                yield RichLog(id="log", highlight=True, markup=True, wrap=True)
        yield Footer()

    def on_mount(self):
        self.title = "Recon Orchestrator"
        self.sub_title = "Enterprise Edition"
        self.status_text = self.query_one("#status-text", Static)
        self.spinner = self.query_one("#spinner", LoadingIndicator)
        self.log_widget = self.query_one("#log", RichLog)
        self.target_input = self.query_one("#target-input", Input)
        self.state = {}

    def get_target(self):
        val = self.target_input.value.strip()
        return val if val else "192.168.8.1"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id.startswith("btn-"):
            phase = btn_id.replace("btn-", "")
            self._run_phase(phase)

    def action_clear_log(self):
        self.log_widget.clear()

    def _set_loading(self, is_loading, text=""):
        self.spinner.display = is_loading
        if is_loading:
            self.status_text.update(f"[#d29922]{text}[/#d29922]")
        else:
            self.status_text.update(f"[#3fb950]{text}[/#3fb950]")

    @work(thread=True, exclusive=True)
    def _run_phase(self, phase_key: str):
        label, runner = PHASES[phase_key]
        target = self.get_target()
        
        self.call_from_thread(self._set_loading, True, f"جاري تنفيذ: {label}...")
        self.call_from_thread(self.log_widget.write, f"\n[bold cyan]▶ {label}[/bold cyan]")
        
        try:
            # Update state with current target
            self.state["target"] = target
            res = runner(self.state, target=target)
            
            out = res.get("output", "")
            if out:
                for line in out.splitlines():
                    if line.strip():
                        self.call_from_thread(self.log_widget.write, line)
            
            if res.get("ok"):
                self.call_from_thread(self._set_loading, False, f"✓ {label} اكتملت")
                self.call_from_thread(self.log_widget.write, f"[bold green]✓ تم بنجاح[/bold green]")
            else:
                self.call_from_thread(self._set_loading, False, f"✗ {label} فشلت")
                self.call_from_thread(self.log_widget.write, f"[bold red]✗ فشل التنفيذ[/bold red]")
                
        except Exception as e:
            tb = traceback.format_exc()
            self.call_from_thread(self.log_widget.write, f"[red]{tb}[/red]")
            self.call_from_thread(self._set_loading, False, "✗ خطأ داخلي")

# تشغيل
os.environ.setdefault("RECON_ENV", "kali")
os.environ.setdefault("RECON_CONFIG_DIR", "kali/config")
os.environ.setdefault("RECON_PLUGINS_DIR", "kali/plugins")

try:
    app = ReconTUI()
    app.run()
except Exception as e:
    print(f"FATAL: {e}", file=sys.stderr)
    traceback.print_exc()
