"""Tests for aiohttp_mcp.protocol.context — Context, contextvars, and find_context_kwarg."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from aiohttp_mcp.protocol.context import (
    Context,
    RequestContext,
    find_context_kwarg,
    get_current_context,
    set_current_context,
)

# ---------------------------------------------------------------------------
# Context properties
# ---------------------------------------------------------------------------


async def test_app_property_raises_without_request() -> None:
    ctx = Context(request_context=RequestContext())
    with pytest.raises(RuntimeError, match="No HTTP request context available"):
        _ = ctx.app


async def test_request_id_from_context() -> None:
    ctx = Context(request_context=RequestContext(request_id="req-123"))
    assert ctx.request_id == "req-123"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


async def test_log_no_sender() -> None:
    """log() is a no-op when send_notification is None."""
    ctx = Context(request_context=RequestContext())
    # Should not raise
    await ctx.log("info", "msg")


async def test_log_with_logger_name() -> None:
    sender = AsyncMock()
    ctx = Context(request_context=RequestContext(_send_notification=sender))
    await ctx.log("info", "test message", logger_name="my.logger")
    sender.assert_called_once_with(
        "notifications/message",
        {"level": "info", "data": "test message", "logger": "my.logger"},
    )


async def test_log_levels() -> None:
    sender = AsyncMock()
    ctx = Context(request_context=RequestContext(_send_notification=sender))
    await ctx.debug("d")
    await ctx.info("i")
    await ctx.warning("w")
    await ctx.error("e")
    assert sender.call_count == 4


# ---------------------------------------------------------------------------
# Progress reporting
# ---------------------------------------------------------------------------


async def test_report_progress_no_sender() -> None:
    ctx = Context(request_context=RequestContext())
    # Should not raise
    await ctx.report_progress(0.5)


async def test_report_progress_with_total_and_message() -> None:
    sender = AsyncMock()
    ctx = Context(request_context=RequestContext(request_id="req-1", _send_notification=sender))
    await ctx.report_progress(0.5, total=1.0, message="halfway")
    sender.assert_called_once()
    params = sender.call_args[0][1]
    assert params["progress"] == 0.5
    assert params["total"] == 1.0
    assert params["message"] == "halfway"
    assert params["progressToken"] == "req-1"


async def test_report_progress_without_request_id() -> None:
    sender = AsyncMock()
    ctx = Context(request_context=RequestContext(_send_notification=sender))
    await ctx.report_progress(0.3)
    params = sender.call_args[0][1]
    assert "progressToken" not in params


# ---------------------------------------------------------------------------
# Resource reading
# ---------------------------------------------------------------------------


async def test_read_resource_raises_without_reader() -> None:
    ctx = Context(request_context=RequestContext())
    with pytest.raises(RuntimeError, match="read_resource is not available"):
        await ctx.read_resource("res://x")


async def test_read_resource_calls_reader() -> None:
    reader = AsyncMock(return_value=["content"])
    ctx = Context(request_context=RequestContext(_read_resource=reader))
    result = await ctx.read_resource("res://x")
    reader.assert_called_once_with("res://x")
    assert result == ["content"]


# ---------------------------------------------------------------------------
# contextvars: set/get
# ---------------------------------------------------------------------------


async def test_set_and_get_current_context() -> None:
    ctx = Context(request_context=RequestContext())
    set_current_context(ctx)
    try:
        assert get_current_context() is ctx
    finally:
        set_current_context(None)


async def test_get_current_context_raises_when_unset() -> None:
    set_current_context(None)
    with pytest.raises(ValueError, match="No MCP context is currently set"):
        get_current_context()


# ---------------------------------------------------------------------------
# find_context_kwarg
# ---------------------------------------------------------------------------


def test_find_context_kwarg_found() -> None:
    def fn(x: int, ctx: Context) -> None: ...

    assert find_context_kwarg(fn) == "ctx"


def test_find_context_kwarg_not_found() -> None:
    def fn(x: int, y: str) -> None: ...

    assert find_context_kwarg(fn) is None


def test_find_context_kwarg_no_annotation() -> None:
    def fn(x) -> None: ...  # type: ignore[no-untyped-def]

    assert find_context_kwarg(fn) is None


def test_find_context_kwarg_union_type() -> None:
    def fn(ctx: Context | None) -> None: ...

    assert find_context_kwarg(fn) == "ctx"


def test_find_context_kwarg_builtin_no_signature() -> None:
    """Built-in functions that can't have their signature inspected return None."""
    result = find_context_kwarg(len)
    assert result is None
