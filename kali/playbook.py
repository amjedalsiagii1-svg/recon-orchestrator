"""Kali Edition Playbook Engine"""
import os
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Port to Service mapping
PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 88: "kerberos", 110: "pop3",
    135: "msrpc", 139: "smb", 143: "imap", 161: "snmp",
    389: "ldap", 443: "http", 445: "smb", 636: "ldap",
    993: "imap", 995: "pop3", 1433: "mssql", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http", 8443: "http",
    9200: "elasticsearch", 27017: "mongodb", 11211: "memcached"
}


def get_commands_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "plugins", "commands")


def load_service(service):
    """Load commands for a service"""
    path = os.path.join(get_commands_dir(), f"{service}.yaml")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def get_service_for_port(port):
    """Return service name for a port"""
    try:
        port = int(port)
    except (ValueError, TypeError):
        return None
    return PORT_SERVICE.get(port)


def build_playbook(detected_ports, target):
    """Build a complete playbook for detected ports.
    Returns dict: service -> {'arabic': ..., 'commands': [...]}
    """
    services_seen = set()
    playbook = {}

    for port in detected_ports:
        svc = get_service_for_port(port)
        if not svc or svc in services_seen:
            continue
        services_seen.add(svc)
        data = load_service(svc)
        if not data:
            continue
        playbook[svc] = {
            "arabic": data.get("arabic_name", svc),
            "port": data.get("port", port),
            "commands": data.get("commands", {})
        }

    return playbook


def display_playbook(playbook, target):
    """Display playbook in Arabic with full details"""
    if not playbook:
        console.print("[yellow]⚠️  لا توجد أوامر مطابقة للخدمات المكتشفة[/yellow]")
        return

    console.print()
    console.print(Panel.fit(
        f"[bold green]📋 خطة الاختراق لـ {target}[/bold green]\n"
        f"[white]الخدمات المكتشفة: {len(playbook)}[/white]",
        border_style="green"
    ))

    total = 0
    for svc, data in playbook.items():
        console.print()
        console.print(f"[bold cyan]▶ {data['arabic']}[/bold cyan] [dim](port {data['port']})[/dim]")

        for cat_key, cat_data in data["commands"].items():
            cat_name = cat_data.get("arabic", cat_key)
            console.print(f"\n  [bold magenta]━━ {cat_name} ━━[/bold magenta]")

            for item in cat_data.get("items", []):
                cmd = item.get("cmd", "").replace("{target}", target)
                desc = item.get("desc", "")
                console.print(f"    [bold green]▶ {cmd}[/bold green]")
                if desc:
                    console.print(f"      [dim]{desc}[/dim]")
                total += 1

    console.print()
    console.print(f"[bold green]✅ إجمالي الأوامر الجاهزة: {total}[/bold green]")


def save_playbook(playbook, target, output_path):
    """Save playbook to text file"""
    lines = [f"# Playbook for {target}", ""]
    for svc, data in playbook.items():
        lines.append(f"## {data['arabic']} (port {data['port']})")
        for cat_key, cat_data in data["commands"].items():
            cat_name = cat_data.get("arabic", cat_key)
            lines.append(f"\n### {cat_name}")
            for item in cat_data.get("items", []):
                cmd = item.get("cmd", "").replace("{target}", target)
                desc = item.get("desc", "")
                lines.append(f"\n# {desc}")
                lines.append(cmd)
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        console.print("[red]Usage: python3 kali/playbook.py <target> <port1,port2,...>[/red]")
        console.print("[dim]Example: python3 kali/playbook.py 192.168.8.1 22,80,443[/dim]")
        sys.exit(1)

    target = sys.argv[1]
    ports = [p.strip() for p in sys.argv[2].split(",")]
    pb = build_playbook(ports, target)
    display_playbook(pb, target)

    out_path = f"reports/playbook_{target.replace('.', '_')}.txt"
    os.makedirs("reports", exist_ok=True)
    save_playbook(pb, target, out_path)
    console.print(f"\n[green]💾 تم الحفظ في: {out_path}[/green]")
