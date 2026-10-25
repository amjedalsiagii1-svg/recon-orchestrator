"""Port knowledge base — service name, description, initial risk, notes.

Risk levels: low | medium | high | critical
Notes are practical exploitation hints for the interpreter + reporter.
"""
from __future__ import annotations

from typing import Any


PORT_DB: dict[int, dict[str, Any]] = {
    20: {"service": "ftp-data", "desc": "FTP data channel", "risk": "high",
         "notes": ["Legacy protocol — plaintext transfer"]},
    21: {"service": "ftp", "desc": "FTP control", "risk": "high",
         "notes": ["Anonymous login (anonymous:anonymous) often enabled",
                   "Cleartext credentials on the wire"]},
    22: {"service": "ssh", "desc": "SSH remote shell", "risk": "medium",
         "notes": ["Check for weak/default keys",
                   "Older versions may allow user enumeration"]},
    23: {"service": "telnet", "desc": "Telnet — cleartext shell", "risk": "critical",
         "notes": ["All traffic in cleartext",
                   "Default creds common on routers/IoT",
                   "Often no rate limiting"]},
    25: {"service": "smtp", "desc": "SMTP mail transfer", "risk": "medium",
         "notes": ["Open relay check", "VRFY/EXPN user enumeration"]},
    53: {"service": "dns", "desc": "DNS resolver", "risk": "medium",
         "notes": ["AXFR zone transfer test", "Cache poisoning possibilities"]},
    80: {"service": "http", "desc": "HTTP web server", "risk": "low",
         "notes": ["Run P5 nuclei http templates",
                   "Check directory listing, robots.txt, admin panels"]},
    110: {"service": "pop3", "desc": "POP3 mail", "risk": "medium",
          "notes": ["Cleartext (except 995)"]},
    111: {"service": "rpcbind", "desc": "RPC portmapper", "risk": "high",
          "notes": ["Enumerate with rpcinfo -p", "Exposes NFS/other RPC"]},
    135: {"service": "msrpc", "desc": "Microsoft RPC", "risk": "high",
          "notes": ["Endpoint mapper — enumerate with rpcdump.py"]},
    139: {"service": "netbios-ssn", "desc": "NetBIOS session", "risk": "high",
          "notes": ["Pair with 445 for full SMB attack surface"]},
    143: {"service": "imap", "desc": "IMAP", "risk": "medium",
          "notes": ["Cleartext (except 993)"]},
    161: {"service": "snmp", "desc": "SNMP — device management", "risk": "high",
          "notes": ["Community string 'public' commonly works",
                    "Full config leak possible (snmpwalk)"]},
    389: {"service": "ldap", "desc": "LDAP directory", "risk": "medium",
          "notes": ["Anonymous bind may work", "Enumerate users/groups"]},
    443: {"service": "https", "desc": "HTTPS web server", "risk": "low",
          "notes": ["TLS config, cert SNI, cipher suites",
                    "Run P5 nuclei ssl templates"]},
    445: {"service": "microsoft-ds", "desc": "SMB / CIFS", "risk": "critical",
          "notes": ["EternalBlue (CVE-2017-0144) if unpatched",
                    "Signing often disabled on legacy hosts",
                    "Null sessions to enumerate shares"]},
    512: {"service": "exec", "desc": "rexec", "risk": "critical",
          "notes": ["Legacy remote exec — rarely secured"]},
    513: {"service": "login", "desc": "rlogin", "risk": "critical",
          "notes": ["Trust-based auth — .rhosts bypass"]},
    514: {"service": "shell", "desc": "rsh", "risk": "critical",
          "notes": ["Same as rlogin — trust bypass"]},
    515: {"service": "printer", "desc": "LPD printing", "risk": "medium",
          "notes": ["May allow arbitrary file printing", "Check queue names"]},
    548: {"service": "afp", "desc": "Apple Filing Protocol", "risk": "medium",
          "notes": ["Guest access often enabled"]},
    554: {"service": "rtsp", "desc": "RTSP — IP cameras", "risk": "high",
          "notes": ["Anonymous stream: rtsp://ip:554/",
                    "Common Hikvision/Dahua path: /Streaming/Channels/101"]},
    587: {"service": "submission", "desc": "SMTP submission", "risk": "medium",
          "notes": ["TLS submission — check auth requirements"]},
    631: {"service": "ipp", "desc": "IPP printing", "risk": "medium",
          "notes": ["Unauthenticated print job often allowed",
                    "Mopria/Android printing uses this"]},
    993: {"service": "imaps", "desc": "IMAP over TLS", "risk": "low",
          "notes": ["TLS — check cert validity"]},
    995: {"service": "pop3s", "desc": "POP3 over TLS", "risk": "low",
          "notes": ["TLS — check cert validity"]},
    1080: {"service": "socks", "desc": "SOCKS proxy", "risk": "high",
           "notes": ["Open proxy can be abused for traffic relay"]},
    1433: {"service": "ms-sql-s", "desc": "Microsoft SQL Server", "risk": "critical",
           "notes": ["SA account default on legacy install",
                     "xp_cmdshell often enabled by default"]},
    1521: {"service": "oracle", "desc": "Oracle DB listener", "risk": "critical",
           "notes": ["SID enumeration via tnscmd", "Default creds on XE"]},
    1723: {"service": "pptp", "desc": "PPTP VPN", "risk": "high",
           "notes": ["MS-CHAPv2 broken — offline crack"]},
    1900: {"service": "upnp", "desc": "UPnP / SSDP", "risk": "high",
           "notes": ["Port-forward hijack",
                     "Many routers expose SOAP API with no auth"]},
    2049: {"service": "nfs", "desc": "NFS share", "risk": "critical",
           "notes": ["Showmount: showmount -e <ip>",
                     "No_root_squash = root over NFS"]},
    2375: {"service": "docker", "desc": "Docker API (plain HTTP)", "risk": "critical",
           "notes": ["UNAUTHENTICATED = full host RCE",
                     "docker -H tcp://<ip>:2375 ps"]},
    2376: {"service": "docker-tls", "desc": "Docker API (TLS)", "risk": "high",
           "notes": ["Check client-cert requirement"]},
    3000: {"service": "grafana", "desc": "Grafana / dev web", "risk": "medium",
           "notes": ["Default admin:admin", "Often deployed unpatched"]},
    3306: {"service": "mysql", "desc": "MySQL / MariaDB", "risk": "critical",
           "notes": ["root with empty password common on old installs",
                     "Check bind-address"]},
    3389: {"service": "ms-wbt-server", "desc": "RDP", "risk": "critical",
           "notes": ["BlueKeep (CVE-2019-0708) if unpatched",
                     "NLA often disabled", "Brute-force friendly"]},
    5000: {"service": "upnp-flask", "desc": "Dev web / Docker registry", "risk": "medium",
           "notes": ["Flask dev server often exposed"]},
    5060: {"service": "sip", "desc": "SIP VoIP", "risk": "medium",
           "notes": ["User enumeration via OPTIONS", "Toll fraud on open PBX"]},
    5432: {"service": "postgresql", "desc": "PostgreSQL", "risk": "critical",
           "notes": ["Trust auth in pg_hba.conf common", "Default postgres/postgres"]},
    5555: {"service": "freeciv", "desc": "Android ADB / misc", "risk": "critical",
           "notes": ["If ADB: adb connect <ip>:5555 → full shell",
                     "Often enabled for TV boxes, industrial devices"]},
    5900: {"service": "vnc", "desc": "VNC remote desktop", "risk": "critical",
           "notes": ["Password often empty", "Old auth scheme bypass"]},
    6379: {"service": "redis", "desc": "Redis", "risk": "critical",
           "notes": ["Default: no password",
                     "Config rewrite → RCE via SSH key or cron"]},
    7547: {"service": "cwmp", "desc": "TR-069 ISP backdoor", "risk": "high",
           "notes": ["Many ISP routers expose CWMP without auth",
                     "Known RCE: CVE-2016-10372"]},
    8080: {"service": "http-alt", "desc": "HTTP alt (proxy/dev)", "risk": "low",
           "notes": ["Tomcat, Jenkins, or dev server", "Check default creds"]},
    8291: {"service": "mikrotik-api", "desc": "MikroTik Winbox", "risk": "critical",
           "notes": ["CVE-2018-14847 — unauthenticated file read",
                     "Default admin blank password"]},
    8443: {"service": "https-alt", "desc": "HTTPS alt", "risk": "low",
           "notes": ["Admin panels, UniFi, cPanel"]},
    8888: {"service": "sun-answerbook", "desc": "HTTP alt / Jupyter", "risk": "medium",
           "notes": ["Jupyter often no auth, then code exec"]},
    9000: {"service": "cslistener", "desc": "Portainer / PHP-FPM", "risk": "medium",
           "notes": ["Portainer admin often default"]},
    9100: {"service": "jetdirect", "desc": "Printer raw TCP", "risk": "medium",
           "notes": ["Raw PCL/PS — may allow NVRAM write",
                     "Often unauthenticated"]},
    9200: {"service": "elasticsearch", "desc": "Elasticsearch HTTP", "risk": "critical",
           "notes": ["No auth by default", "Full data exfil via /_search"]},
    10000: {"service": "webmin", "desc": "Webmin", "risk": "critical",
            "notes": ["CVE-2019-15107 backdoor RCE"]},
    27017: {"service": "mongodb", "desc": "MongoDB", "risk": "critical",
            "notes": ["No auth by default", "Full data exfil, sometimes RCE"]},
}


def get_port_info(port: int) -> dict[str, Any]:
    """Return merged info for a port (db entry or generic unknown)."""
    entry = PORT_DB.get(port, {})
    return {
        "port": port,
        "service": entry.get("service", "unknown"),
        "description": entry.get("desc", ""),
        "risk": entry.get("risk", "low"),
        "notes": list(entry.get("notes", [])),
    }


def enrich(
    port: int,
    protocol: str = "tcp",
    nmap_service: str | None = None,
    nmap_product: str | None = None,
    nmap_version: str | None = None,
) -> dict[str, Any]:
    """Enrich a port with DB metadata + nmap-detected details.

    Risk escalation rules:
      - nmap sees telnet/ftp/rexec → high minimum
      - suspicious product name (anonymous, default) → critical
      - unknown port with nmap product=... → medium (banner-info leak)
    """
    base = get_port_info(port)
    enriched: dict[str, Any] = {
        **base,
        "protocol": protocol,
        "nmap_service": nmap_service,
        "product": nmap_product,
        "version": nmap_version,
    }

    svc = (nmap_service or "").lower()
    prod = (nmap_product or "").lower()

    RISK_ORDER = ["low", "medium", "high", "critical"]
    def _escalate(level: str) -> None:
        cur = RISK_ORDER.index(enriched["risk"])
        new = RISK_ORDER.index(level)
        if new > cur:
            enriched["risk"] = level

    if svc in ("telnet", "ftp", "shell", "exec", "login"):
        _escalate("high")
    if any(kw in prod for kw in ("anonymous", "default", "open")):
        _escalate("critical")
    if enriched["service"] == "unknown" and nmap_product:
        _escalate("medium")
        enriched["notes"].append(
            f"Unknown port with banner: {nmap_product} {nmap_version or ''}".strip()
        )

    if nmap_version and enriched["service"] != "unknown":
        enriched["version_note"] = (
            f"Detected {nmap_product or ''} {nmap_version}; "
            "P5 should match this product/version against CVE databases"
        )
    return enriched
