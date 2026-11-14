"""Add web scan section to HTML report"""
import os
import re


def add_web_section(report_path, target, web_findings=None):
    """web_findings: dict with keys whatweb, headers, cms, nikto, gobuster, sensitive"""
    if not os.path.exists(report_path):
        return False
    with open(report_path, "r", encoding="utf-8") as f:
        html = f.read()
    if "Web Reconnaissance" in html:
        return True
    
    findings = web_findings or {}
    url = f"http://{target}" if not target.startswith("http") else target
    
    html_section = '<section>\n<h2>🌐 Web Reconnaissance - فحص الويب</h2>\n'
    html_section += f'<p style="color:#8b949e;font-size:0.9em">Target: <code>{url}</code></p>\n'
    
    # Stack
    if findings.get("stack"):
        html_section += '<h3 style="color:#58a6ff;margin-top:14px">⚡ Technology Stack</h3>\n'
        html_section += '<ul style="padding-right:20px">\n'
        for item in findings["stack"]:
            html_section += f'<li>{item}</li>\n'
        html_section += '</ul>\n'
    
    # CMS
    if findings.get("cms"):
        html_section += '<h3 style="color:#58a6ff;margin-top:14px">📦 Detected CMS</h3>\n'
        html_section += '<ul style="padding-right:20px">\n'
        for cms in findings["cms"]:
            html_section += f'<li><strong style="color:#f0b400">{cms}</strong></li>\n'
        html_section += '</ul>\n'
    
    # Nikto
    if findings.get("nikto"):
        html_section += '<h3 style="color:#58a6ff;margin-top:14px">⚠️ Nikto Findings</h3>\n'
        html_section += '<ul style="padding-right:20px">\n'
        for finding in findings["nikto"]:
            html_section += f'<li style="color:#f85149;margin-bottom:6px">{finding}</li>\n'
        html_section += '</ul>\n'
    
    # Sensitive paths
    if findings.get("sensitive"):
        html_section += '<h3 style="color:#58a6ff;margin-top:14px">🚨 Sensitive Paths</h3>\n'
        html_section += '<ul style="padding-right:20px">\n'
        for path in findings["sensitive"]:
            html_section += f'<li><code>{path}</code></li>\n'
        html_section += '</ul>\n'
    
    html_section += '</section>\n'
    
    if "<footer>" in html:
        html = html.replace("<footer>", html_section + "\n<footer>", 1)
    elif "</body>" in html:
        html = html.replace("</body>", html_section + "\n</body>", 1)
    else:
        return False
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("[OK] Web section added to: " + report_path)
    return True
