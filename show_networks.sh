#!/bin/bash
cd "$(dirname "$0")"
if [ -d "venv" ]; then source venv/bin/activate; fi

python3 << 'PY_EOF'
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
console.print(Panel.fit(
    "[bold cyan]🌐 قاعدة معرفة أنواع الشبكات - Kali Edition[/bold cyan]\n"
    "[white]25 نوع مصنف بمعايير Enterprise[/white]",
    border_style="cyan"
))

try:
    with open("kali/config/network_types.yaml", "r", encoding="utf-8") as f:
        data = yaml.safe_load(f).get("network_types", {})
except Exception as e:
    console.print(f"[red]خطأ في تحميل الملف: {e}[/red]")
    exit(1)

risk_colors = {
    "low": "green", "medium": "yellow", "high": "red",
    "very_high": "bright_red", "critical": "bright_red"
}

for idx, (key, info) in enumerate(data.items(), 1):
    icon = info.get("icon", "🔍")
    ar = info.get("ar", key)
    risk = info.get("risk", "unknown")
    desc = info.get("description", "")
    recs = info.get("recommendations", [])
    det = info.get("detection", [])
    
    color = risk_colors.get(risk, "white")
    
    console.print(f"\n[bold cyan]{idx}. {icon} {ar}[/bold cyan]  [{color}][{risk.upper()}][/{color}]")
    console.print(f"   [dim]{desc}[/dim]")
    if recs:
        console.print("   [yellow]التوصيات:[/yellow]")
        for r in recs[:2]:
            console.print(f"     • {r}")
    if det:
        console.print(f"   [cyan]مؤشرات الكشف:[/cyan] {det[0]}")

console.print("\n" + "="*60)
console.print(f"[bold green]✅ إجمالي: {len(data)} نوع شبكة[/bold green]")
console.print("="*60)
PY_EOF
