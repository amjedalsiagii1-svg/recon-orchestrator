import sys
import os
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()

def show_service_commands(service, target="<target>"):
    config_dir = os.environ.get("RECON_CONFIG_DIR", "kali/plugins/commands")
    yaml_path = os.path.join("kali", "plugins", "commands", f"{service}.yaml")
    
    if not os.path.exists(yaml_path):
        console.print(f"[red]No command file for: {service}[/red]")
        return False
    
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    svc_name = data.get("service", service)
    port = data.get("port", "?")
    commands = data.get("commands", {})
    
    console.print(Panel.fit(
        f"[bold cyan]{svc_name.upper()}[/bold cyan] — Port [yellow]{port}[/yellow]",
        border_style="cyan"
    ))
    
    for category, cmds in commands.items():
        console.print(f"\n[bold yellow]{category.replace('_', ' ').title()}:[/bold yellow]")
        for cmd in cmds:
            formatted = cmd.replace("{target}", target)
            console.print(f"  [green]{formatted}[/green]")
    return True

def list_services():
    cmd_dir = "kali/plugins/commands"
    if not os.path.exists(cmd_dir):
        console.print("[red]No commands directory[/red]")
        return
    files = sorted([f[:-5] for f in os.listdir(cmd_dir) if f.endswith(".yaml")])
    console.print("[bold cyan]Available Services:[/bold cyan]")
    for f in files:
        console.print(f"  - {f}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        list_services()
    elif sys.argv[1] == "list":
        list_services()
    else:
        service = sys.argv[1]
        target = sys.argv[2] if len(sys.argv) > 2 else "<target>"
        show_service_commands(service, target)
