"""Tests for core.progress — B3."""
import asyncio
import io

import pytest
from rich.console import Console

from core.progress import with_progress


@pytest.mark.asyncio
async def test_returns_coro_result():
    """with_progress must return whatever coro returns."""
    async def work():
        await asyncio.sleep(0.01)
        return 42

    console = Console(file=io.StringIO())
    result = await with_progress(console, work(), "test")
    assert result == 42


@pytest.mark.asyncio
async def test_propagates_exceptions():
    """with_progress must re-raise exceptions."""
    async def failing():
        raise ValueError("boom")

    console = Console(file=io.StringIO())
    with pytest.raises(ValueError, match="boom"):
        await with_progress(console, failing(), "test")


@pytest.mark.asyncio
async def test_arabic_message_accepted():
    """Arabic messages must not break anything."""
    async def work():
        return "ok"

    console = Console(file=io.StringIO())
    result = await with_progress(console, work(), "جارٍ الفحص")
    assert result == "ok"


@pytest.mark.asyncio
async def test_bilingual_message():
    """Bilingual message + hint must not break."""
    async def work():
        return 1

    console = Console(file=io.StringIO())
    result = await with_progress(
        console, work(),
        "جارٍ الفحص",
        "Running scan",
        hint="Ctrl+C to abort",
    )
    assert result == 1


@pytest.mark.asyncio
async def test_fast_coro():
    """Fast coroutines should not crash."""
    async def work():
        return "fast"

    console = Console(file=io.StringIO())
    result = await with_progress(console, work(), "سريع")
    assert result == "fast"
