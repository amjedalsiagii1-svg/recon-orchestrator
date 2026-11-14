import sys
import os
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


def show_service_commands(service, target="<target>"):
    yaml_path = os.path.join("kali", "plugins", "commands", f"{service}.yaml")
    if not os.path.exists(yaml_path):
        console.print(f"[red]No command file for: {service}[/red]")
        return False

    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    svc_name = data.get("service", service)
    port = data.get("port", "?")
    arabic = data.get("arabic_name", svc_name)
    svc_desc = data.get("description", "")

    console.print(Panel.fit(
        f"[bold cyan]{arabic}[/bold cyan]\n[white]{svc_desc}[/white]\n[yellow]المنفذ: {port}[/yellow]",
        title=f"خدمة {svc_name.upper()}",
        border_style="cyan"
    ))

    commands = data.get("commands", {})
    total = 0

    for category, cat_data in commands.items():
        cat_arabic = cat_data.get("arabic", category)
        cat_desc = cat_data.get("desc", "")
        items = cat_data.get("items", [])

        console.print()
        console.print(f"[bold magenta]━━━ {cat_arabic} ━━━[/bold magenta]")
        if cat_desc:
            console.print(f"[dim]{cat_desc}[/dim]")

        for item in items:
            cmd = item.get("cmd", "").replace("{target}", target)
            desc = item.get("desc", "")
            output = item.get("output", "")
            when = item.get("when", "")
            warning = item.get("warning", "")

            console.print()
            console.print(f"  [bold green]▶ {cmd}[/bold green]")
            if desc:
                console.print(f"    [cyan]📝 الشرح:[/cyan] {desc}")
            if output:
                console.print(f"    [yellow]📤 المخرجات:[/yellow] {output}")
            if when:
                console.print(f"    [blue]⏰ متى:[/blue] {when}")
            if warning:
                console.print(f"    [red]⚠️  تحذير:[/red] {warning}")
            total += 1

    console.print()
    console.print(f"[bold green]✅ إجمالي الأوامر: {total}[/bold green]")
    return True


def list_services():
    cmd_dir = "kali/plugins/commands"
    if not os.path.exists(cmd_dir):
        console.print("[red]No commands directory[/red]")
        return
    files = sorted([f[:-5] for f in os.listdir(cmd_dir) if f.endswith(".yaml")])
    console.print("[bold cyan]الخدمات المتاحة:[/bold cyan]")
    for f in files:
        try:
            with open(os.path.join(cmd_dir, f + ".yaml"), "r", encoding="utf-8") as fh:
                d = yaml.safe_load(fh)
                ar = d.get("arabic_name", f)
                port = d.get("port", "?")
                console.print(f"  [green]{f}[/green] ({ar}) - port {port}")
        except Exception:
            console.print(f"  [green]{f}[/green]")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "list":
        list_services()
    else:
        service = sys.argv[1]
        target = sys.argv[2] if len(sys.argv) > 2 else "<target>"
        show_service_commands(service, target)
