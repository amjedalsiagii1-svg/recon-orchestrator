"""Optional nuclei integration — gracefully skips if unavailable."""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path


async def find_nuclei() -> str | None:
    """Return nuclei binary path or None."""
    # 1) PATH
    path = shutil.which("nuclei")
    if path:
        return path
    # 2) tools/bin (our local install)
    local = Path("tools/bin/nuclei")
    if local.exists() and local.is_file():
        return str(local.resolve())
    return None


async def run_web_scan(
    url: str,
    severity: str = "critical,high,medium",
    timeout: int = 300,
) -> tuple[list[dict], str | None]:
    """Run nuclei against a URL. Returns (findings, error)."""
    binary = await find_nuclei()
    if not binary:
        return [], "nuclei not installed"

    cmd = [
        binary, "-u", url,
        "-severity", severity,
        "-jsonl", "-silent",
        "-rate-limit", "100",
        "-no-color",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return [], "nuclei binary not executable"

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return [], "nuclei timeout"

    out = (stdout or b"").decode(errors="replace")
    err = (stderr or b"").decode(errors="replace")

    findings: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append({
            "template_id": j.get("template-id") or j.get("templateID") or "nuclei-unknown",
            "name": j.get("info", {}).get("name", ""),
            "severity": (j.get("info", {}).get("severity") or "info").lower(),
            "matched_at": j.get("matched-at") or j.get("matched") or url,
            "description": j.get("info", {}).get("description", ""),
            "reference": j.get("info", {}).get("reference", []),
        })

    if not findings and proc.returncode and proc.returncode != 0:
        return [], err.strip() or "nuclei failed"
    return findings, None
