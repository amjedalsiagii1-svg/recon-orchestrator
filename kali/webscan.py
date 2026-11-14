"""Kali Edition Web Scanner - Comprehensive standalone"""
import subprocess
import sys
import os
import re
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()


def has_tool(name):
    return subprocess.run(['which', name], capture_output=True).returncode == 0


def run(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return False, "", "TIMEOUT"
    except Exception as e:
        return False, "", str(e)


def section(num, title):
    console.print()
    console.print(Panel.fit(f"[bold cyan]{num}. {title}[/bold cyan]", border_style="cyan"))


def whatweb(url):
    section(1, "WhatWeb - Technology Fingerprinting")
    if not has_tool('whatweb'):
        console.print("[yellow]whatweb not installed[/yellow]")
        return
    ok, out, err = run(['whatweb', '-q', '--color=never', url], timeout=60)
    if out.strip():
        for part in out.strip().split(','):
            console.print(f"  [white]{part.strip()}[/white]")
    else:
        console.print("[yellow]No fingerprint[/yellow]")


def headers(url):
    section(2, "HTTP Headers Analysis")
    ok, out, err = run(['curl', '-sI', '--max-time', '15', url], timeout=20)
    if not out.strip():
        console.print("[red]No response[/red]")
        return
    interesting = []
    for line in out.strip().split('\n'):
        if ':' in line:
            k, v = line.split(':', 1)
            k = k.strip()
            v = v.strip()
            color = "white"
            if k.lower() in ['server', 'x-powered-by', 'x-generator']:
                color = "yellow"
            if k.lower() in ['x-frame-options', 'strict-transport-security', 'content-security-policy']:
                color = "green"
            console.print(f"  [cyan]{k}:[/cyan] [{color}]{v}[/{color}]")
            if k.lower() in ['server', 'x-powered-by', 'x-generator']:
                interesting.append(f"{k}: {v}")
    if interesting:
        console.print(f"\n  [yellow]⚡ Detected stack: {', '.join(interesting)}[/yellow]")


def sensitive_paths(url):
    section(3, "Sensitive Paths Check")
    base = url.rstrip('/')
    paths = [
        '/robots.txt', '/sitemap.xml', '/.git/HEAD', '/.env',
        '/.htaccess', '/admin', '/phpinfo.php', '/server-status',
        '/backup.sql', '/wp-config.php.bak'
    ]
    found = []
    for path in paths:
        full = base + path
        ok, out, err = run(['curl', '-s', '--max-time', '8', '-o', '/dev/null',
                            '-w', '%{http_code}|%{size_download}', full], timeout=10)
        if '|' in out:
            parts = out.strip().split('|')
            if len(parts) == 2:
                code = parts[0]
                size = int(parts[1]) if parts[1].isdigit() else 0
                if code == '200' and size > 10:
                    console.print(f"  [red]⚠  200[/red] {path} ({size} bytes)")
                    found.append(path)
                elif code in ('301', '302'):
                    console.print(f"  [cyan]→  {code}[/cyan] {path}")
    if not found:
        console.print("[green]No sensitive paths found[/green]")


def cms_detect(url):
    section(4, "CMS Detection")
    ok, out, err = run(['curl', '-s', '--max-time', '15', url], timeout=20)
    if not out:
        return
    html = out.lower()
    detected = []
    if 'wp-content' in html or 'wp-includes' in html or '/wp-json/' in html:
        detected.append('WordPress')
    if 'joomla' in html or '/components/com_' in html:
        detected.append('Joomla')
    if 'drupal' in html or 'sites/default/files' in html:
        detected.append('Drupal')
    if 'magento' in html:
        detected.append('Magento')
    if 'shopify' in html:
        detected.append('Shopify')
    if not detected:
        console.print("[yellow]No CMS detected (custom app?)[/yellow]")
        return
    for c in detected:
        console.print(f"  [green]✓ {c}[/green]")
        if c == 'WordPress':
            console.print(f"  [cyan]  → wpscan --url {url} --enumerate vp,vt,u[/cyan]")
        elif c == 'Joomla':
            console.print(f"  [cyan]  → joomscan -u {url}[/cyan]")
        elif c == 'Drupal':
            console.print(f"  [cyan]  → droopescan scan drupal -u {url}[/cyan]")


def nikto(url):
    section(5, "Nikto - Vulnerability Scan")
    if not has_tool('nikto'):
        console.print("[yellow]nikto not installed[/yellow]")
        return
    console.print("[yellow]Running (max 2 min)...[/yellow]")
    ok, out, err = run(['nikto', '-h', url, '-nointeractive', '-maxtime', '2m', '-ask', 'no'], timeout=180)
    if not out:
        console.print("[red]No output[/red]")
        return
    findings = []
    for line in out.split('\n'):
        if line.startswith('+ ') and 'Target' not in line and 'Start' not in line and 'End' not in line:
            findings.append(line[2:].strip())
    for f in findings[:20]:
        console.print(f"  [red]⚠[/red] {f}")
    if len(findings) > 20:
        console.print(f"  [yellow]... +{len(findings)-20} more[/yellow]")
    if not findings:
        console.print("[green]Clean[/green]")


def gobuster(url):
    section(6, "Gobuster - Directory Bruteforce")
    if not has_tool('gobuster'):
        console.print("[yellow]gobuster not installed[/yellow]")
        return
    wordlists = [
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/dirb/wordlists/common.txt',
    ]
    wordlist = next((w for w in wordlists if os.path.exists(w)), None)
    if not wordlist:
        console.print("[yellow]No wordlist[/yellow]")
        return
    console.print(f"[dim]Wordlist: {wordlist}[/dim]")
    console.print("[yellow]Running (max 2 min)...[/yellow]")
    ok, out, err = run(['gobuster', 'dir', '-u', url, '-w', wordlist,
                        '-t', '20', '-q', '--timeout', '10s'], timeout=180)
    if not out:
        console.print("[yellow]No results[/yellow]")
        return
    paths = [l.strip() for l in out.split('\n') if l.strip()]
    for p in paths[:25]:
        if 'Status: 200' in p or 'Status: 301' in p or 'Status: 403' in p:
            color = "red" if 'Status: 200' in p else "cyan"
            console.print(f"  [{color}]▶ {p}[/{color}]")
    if len(paths) > 25:
        console.print(f"  [yellow]... +{len(paths)-25} more[/yellow]")


def ssl_check(host):
    section(7, "SSL/TLS Analysis")
    if not has_tool('sslscan'):
        console.print("[yellow]sslscan not installed[/yellow]")
        return
    ok, out, err = run(['sslscan', '--no-colour', host], timeout=60)
    if not out:
        return
    for line in out.split('\n'):
        line = line.strip()
        if 'SSLv2' in line and 'enabled' in line:
            console.print(f"  [red]⚠ DANGER: {line}[/red]")
        elif 'SSLv3' in line and 'enabled' in line:
            console.print(f"  [red]⚠ VULN: {line}[/red]")
        elif 'TLSv1.0' in line and 'enabled' in line:
            console.print(f"  [yellow]⚠ WEAK: {line}[/yellow]")
        elif 'TLSv1.2' in line and 'enabled' in line:
            console.print(f"  [green]✓ {line}[/green]")
        elif 'TLSv1.3' in line and 'enabled' in line:
            console.print(f"  [green]✓ {line}[/green]")


def nuclei_web(url):
    section(8, "Nuclei - Web Templates")
    if not has_tool('nuclei'):
        console.print("[yellow]nuclei not installed[/yellow]")
        return
    console.print("[yellow]Running (max 2 min)...[/yellow]")
    ok, out, err = run(['nuclei', '-u', url, '-severity', 'critical,high',
                        '-silent', '-timeout', '10', '-no-color'], timeout=180)
    if not out.strip():
        console.print("[green]No nuclei findings[/green]")
        return
    lines = [l for l in out.split('\n') if l.strip()]
    for l in lines[:15]:
        console.print(f"  [red]⚠[/red] {l}")
    if len(lines) > 15:
        console.print(f"  [yellow]... +{len(lines)-15} more[/yellow]")


def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage: python3 webscan.py <url_or_ip> [--fast][/red]")
        console.print("[dim]Example: python3 webscan.py http://192.168.8.1[/dim]")
        console.print("[dim]Example: python3 webscan.py 192.168.8.1 --fast[/dim]")
        sys.exit(1)
    
    url = sys.argv[1]
    if not url.startswith('http'):
        url = f"http://{url}"
    
    fast_mode = '--fast' in sys.argv
    host = url.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    
    console.print()
    console.print(Panel.fit(
        f"[bold green]🔍 Kali Edition Web Scanner[/bold green]\n"
        f"[white]Target: {url}[/white]\n"
        f"[dim]Mode: {'FAST' if fast_mode else 'FULL'} | Time: {datetime.now().strftime('%H:%M:%S')}[/dim]",
        border_style="green"
    ))
    
    whatweb(url)
    headers(url)
    sensitive_paths(url)
    cms_detect(url)
    
    if not fast_mode:
        nikto(url)
        gobuster(url)
        if url.startswith('https') or ':443' in sys.argv[1]:
            ssl_check(host)
        nuclei_web(url)
    else:
        console.print("\n[yellow]--fast mode: skipped nikto, gobuster, nuclei, ssl[/yellow]")
        console.print("[dim]Run without --fast for full scan[/dim]")
    
    console.print()
    console.print(Panel.fit(
        "[bold green]✅ Web Scan Complete[/bold green]",
        border_style="green"
    ))


if __name__ == "__main__":
    main()
