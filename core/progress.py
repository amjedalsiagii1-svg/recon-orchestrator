"""Progress indicators for CLI — spinner + elapsed time during async work."""
from __future__ import annotations

import io
from typing import Awaitable, TypeVar

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

T = TypeVar("T")


async def with_progress(
    console: Console,
    coro: Awaitable[T],
    msg_ar: str,
    msg_en: str = "",
    hint: str = "",
) -> T:
    """Show animated spinner while awaiting coro. Returns coro's result.

    Args:
        console: Rich Console to render on.
        coro: Awaitable to run.
        msg_ar: Primary message (Arabic).
        msg_en: Secondary message (English, dim).
        hint: Optional hint like "Ctrl+C to abort".

    Returns:
        Whatever `coro` returns.

    Behavior:
        - Spinner + elapsed time appear immediately.
        - On completion, spinner is cleared (transient).
        - If coro raises, spinner is cleared and exception propagates.
    """
    # Build a compact description line
    desc = msg_ar
    if msg_en:
        desc += f" [dim]({msg_en})[/dim]"
    if hint:
        desc += f" [dim]• {hint}[/dim]"

    progress = Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        refresh_per_second=10,
    )
    progress.start()
    task_id = progress.add_task(desc, total=None)
    try:
        result = await coro
        return result
    finally:
        try:
            progress.stop()
        except Exception:
            pass


def with_progress_safe(
    console: Console | None,
    coro: Awaitable[T],
    msg_ar: str,
    msg_en: str = "",
    hint: str = "",
) -> Awaitable[T]:
    """Fallback if console is None — just await coro."""
    if console is None:
        return coro
    return with_progress(console, coro, msg_ar, msg_en, hint)
