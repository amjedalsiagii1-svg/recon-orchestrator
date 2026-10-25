"""Phase 7 — Report generation with filename support."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core.reporter import generate as generate_html
from core.session import Session


async def generate(
    session: Session,
    out_dir: str | Path = "reports/output",
    template_dir: str | Path = "reports/templates",
    filename: str | None = None,
) -> dict[str, Any]:
    try:
        path = await generate_html(session, out_dir, template_dir, filename=filename)
        return {
            "ok": True,
            "path": str(path),
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "format": "html",
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
