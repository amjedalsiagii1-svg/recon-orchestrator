"""Enrich HTML report with service commands + explanations"""
import os
import yaml

PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 88: "kerberos", 110: "pop3",
    135: "msrpc", 139: "smb", 143: "imap", 161: "snmp",
    389: "ldap", 443: "http", 445: "smb", 636: "ldap",
    1433: "mssql", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http", 8443: "http", 9200: "elasticsearch",
    27017: "mongodb", 11211: "memcached"
}


def _build_commands_section(ports, target):
    services_seen = set()
    html = '<section>\n<h2>📋 أوامر التعداد والاستغلال الجاهزة</h2>\n'
    html += '<p style="color:#8b949e;font-size:0.9em;margin-bottom:12px">'
    html += 'أوامر جاهزة للنسخ واللصق لكل خدمة مكتشفة، مع الشرح والمخرجات المتوقعة.'
    html += '</p>\n'
    total_cmds = 0
    for port in ports:
        try:
            svc = PORT_SERVICE.get(int(port))
        except (ValueError, TypeError):
            continue
        if not svc or svc in services_seen:
            continue
        services_seen.add(svc)
        yaml_path = os.path.join("kali", "plugins", "commands", f"{svc}.yaml")
        if not os.path.exists(yaml_path):
            continue
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        arabic = data.get("arabic_name", svc)
        port_num = data.get("port", port)
        svc_desc = data.get("description", "")
        html += '<h3 style="color:#58a6ff;margin-top:22px;font-size:1.1em">'
        html += f'▶ {arabic} <span style="color:#8b949e;font-size:0.85em">(port {port_num})</span>'
        html += '</h3>\n'
        if svc_desc:
            html += f'<p style="color:#8b949e;font-size:0.9em;margin:4px 0 12px 0">{svc_desc}</p>\n'
        for cat_key, cat_data in data.get("commands", {}).items():
            cat_ar = cat_data.get("arabic", cat_key)
            cat_desc = cat_data.get("desc", "")
            html += f'<h4 style="color:#79c0ff;margin:14px 0 6px 0;font-size:1em">{cat_ar}</h4>\n'
            if cat_desc:
                html += f'<p style="color:#8b949e;font-size:0.88em;margin:4px 0">{cat_desc}</p>\n'
            for item in cat_data.get("items", []):
                cmd = item.get("cmd", "").replace("{target}", target)
                desc = item.get("desc", "")
                output = item.get("output", "")
                when = item.get("when", "")
                warning = item.get("warning", "")
                total_cmds += 1
                html += '<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;margin:10px 0">\n'
                html += f'<code style="display:block;color:#7ee787;background:#000;padding:10px;border-radius:4px;font-size:0.85em;direction:ltr;text-align:left;margin-bottom:8px;white-space:pre-wrap;word-break:break-all;border:1px solid #21262d">{cmd}</code>\n'
                if desc:
                    html += f'<p style="margin:6px 0;color:#c9d1d9;font-size:0.9em"><strong style="color:#79c0ff">📝 الشرح:</strong> {desc}</p>\n'
                if output:
                    html += f'<p style="margin:6px 0;color:#c9d1d9;font-size:0.9em"><strong style="color:#79c0ff">📤 المخرجات المتوقعة:</strong> {output}</p>\n'
                if when:
                    html += f'<p style="margin:6px 0;color:#c9d1d9;font-size:0.9em"><strong style="color:#79c0ff">⏰ متى:</strong> {when}</p>\n'
                if warning:
                    html += f'<p style="margin:6px 0;color:#f85149;font-size:0.9em"><strong>⚠️ تحذير:</strong> {warning}</p>\n'
                html += '</div>\n'
    html += f'<p style="color:#3fb950;font-weight:bold;margin-top:16px;font-size:1em">✅ إجمالي الأوامر الجاهزة: {total_cmds}</p>\n'
    html += '</section>\n'
    return html


def enrich_report_file(report_path, ports, target):
    if not os.path.exists(report_path):
        return False
    with open(report_path, "r", encoding="utf-8") as f:
        html = f.read()
    if "أوامر التعداد والاستغلال الجاهزة" in html:
        return True
    commands_html = _build_commands_section(ports, target)
    if "<footer>" in html:
        html = html.replace("<footer>", commands_html + "\n<footer>", 1)
    elif "</body>" in html:
        html = html.replace("</body>", commands_html + "\n</body>", 1)
    else:
        return False
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("\033[92m[OK] Report enriched with commands: " + report_path + "\033[0m")
    return True
