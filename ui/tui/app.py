"""Recon Orchestrator - Stable TUI (No stdout hijack)"""
import asyncio
import os
from datetime import datetime
from textual import work
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Static
from textual.containers import Container, Vertical

from ui.tui.runners import (
    run_p1, run_p2, run_p3, run_p4, run_p5, run_p6, run_p7, run_p8,
)

PHASES = {
    "1": ("🌐 1. كشف الشبكة", run_p1),
    "2": ("📡 2. اكتشاف الأجهزة", run_p2),
    "3": ("🎯 3. اختيار الهدف", run_p3),
    "4": ("🔍 4. فحص المنافذ", run_p4),
    "5": ("⚠️ 5. فحص الثغرات", run_p5),
    "6": ("💥 6. خطة الاستغلال", run_p6),
    "7": ("📄 7. توليد التقرير", run_p7),
    "8": ("🌍 8. فحص الويب", run_p8),
}

class ReconTUI(App):
    CSS = """
    Screen { background: #0d1117; color: #c9d1d9; }
    Header { background: #161b22; color: #58a6ff; }
    Footer { background: #161b22; color: #8b949e; }
    Button { margin: 0 1; background: #21262d; color: #c9d1d9; width: 22; }
    Button:hover { background: #30363d; }
    Button:focus { background: #58a6ff; color: #000; }
    #status { height: 3; border: round #30363d; padding: 1; margin: 1 0; color: #d29922; text-style: bold; }
    #output { height: 1fr; border: round #30363d; padding: 1; background: #000000; color: #7ee787; }
    """

    BINDINGS = [("q", "quit", "خروج")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Container():
            with Container():
                for key, (label, _) in PHASES.items():
                    yield Button(label, id=f"btn-{key}")
            yield Static("● جاهز للبدء...", id="status")
            yield Static("", id="output")
        yield Footer()

    def on_mount(self):
        self.title = "Recon Orchestrator"
        self.status = self.query_one("#status", Static)
        self.output = self.query_one("#output", Static)
        self.output_text = ""

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id.startswith("btn-"):
            self._run_phase(btn_id.replace("btn-", ""))

    def _append_output(self, text):
        self.output_text += str(text) + "\n"
        lines = self.output_text.splitlines()[-40:]  # Keep last 40 lines
        self.output_text = "\n".join(lines)
        self.output.update(self.output_text)

    @work(exclusive=True)
    async def _run_phase(self, phase_key):
        label, runner = PHASES[phase_key]
        self.status.update(f"⏳ جاري تشغيل: {label}...")
        self._append_output(f"\n--- {label} ---")
        
        target = "192.168.8.1" if phase_key in ["3", "4", "5", "6", "8"] else ""
        
        try:
            # NO contextlib.redirect_stdout here! It breaks Textual.
            result = await asyncio.to_thread(runner, {"target": target}, target=target)
            
            out = result.get("output", "")
            if out:
                for line in out.splitlines():
                    if line.strip(): self._append_output(line)
            
            if result.get("ok"):
                self.status.update(f"✓ {label} اكتملت")
            else:
                self.status.update(f"✗ {label} فشلت")

        except Exception as e:
            self._append_output(f"خطأ: {e}")
            self.status.update("✗ خطأ داخلي")

app = ReconTUI()
app.run()
